//
// client.go --- Golang e3db client.
//
// Copyright (C) 2020, Tozny, LLC.
// All Rights Reserved.
//

/*
Package e3db provides programmatic access to the e3db API/Innovault service for the secure transmission and storage of arbitrary data encrypted locally using this SDK.

Official documentation for e3db can be found at https://tozny.com/documentation/e3db/

If not using go mod command for your project:
	  import "github.com/tozny/e3db-go"
Otherwise
	  import "github.com/tozny/e3db-go/v2"
*/
package e3db

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/identityClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"github.com/tozny/e3db-clients-go/storageClient"

	"github.com/google/uuid"
	"golang.org/x/oauth2/clientcredentials"
)

const defaultStorageURL = "https://api.e3db.com"

type akCacheKey struct {
	WriterID string
	UserID   string
	Type     string
}

// ClientOpts contains options for configuring an E3DB client.
type ClientOpts struct {
	ClientID    string
	ClientEmail string
	APIKeyID    string
	APISecret   string
	PublicKey   PublicKey
	PrivateKey  PrivateKey
	APIBaseURL  string
	Logging     bool
}

// Client is an authenticated connection to the E3DB service, providing
// access to end-to-end encrypted data stored in the database.
type Client struct {
	Options ClientOpts

	httpClient *http.Client
	akCache    map[akCacheKey]secretKey
}

// ClientKey contains a cryptographic key for use in client operations.
type ClientKey struct {
	Curve25519 string `json:"curve25519"`
}

// ClientInfo contains information sent by the E3DB service
// about a client.
type ClientInfo struct {
	ClientID  string    `json:"client_id"`
	PublicKey ClientKey `json:"public_key"`
	Validated bool      `json:"validated"`
}

// ClientDetails contains information about a newly-registered E3DB client
type ClientDetails struct {
	ClientID  string    `json:"client_id"`
	ApiKeyID  string    `json:"api_key_id"`
	ApiSecret string    `json:"api_secret"`
	PublicKey ClientKey `json:"public_key"`
	Name      string    `json:"name"`
}

type clientRegistrationInfo struct {
	Name      string    `json:"name"`
	PublicKey ClientKey `json:"public_key"`
}

type clientRegistrationRequest struct {
	Token  string                 `json:"token"`
	Client clientRegistrationInfo `json:"client"`
}

// Meta contains meta-information about an E3DB record, such as
// who wrote it, when it was written, and the type of the data stored.
type Meta struct {
	RecordID     string            `json:"record_id,omitempty"`
	WriterID     string            `json:"writer_id"`
	UserID       string            `json:"user_id"`
	Type         string            `json:"type"`
	Plain        map[string]string `json:"plain"`
	Created      time.Time         `json:"created"`
	LastModified time.Time         `json:"last_modified"`
	Version      string            `json:"version,omitempty"`
}

// Record contains a plaintext 'Meta' object containing record metadata,
// along with decrypted fields in 'Data'. All data will be encrypted
// before it is stored in the E3DB service.
type Record struct {
	Meta Meta              `json:"meta"`
	Data map[string]string `json:"data"`
}

// GetDefaultClient loads the default E3DB configuration profile and
// creates a client using those options.
func GetDefaultClient() (*Client, error) {
	opts, err := DefaultConfig()
	if err != nil {
		return nil, err
	}

	client, err := GetClient(*opts)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GetClient creates an E3DB client given a custom set of options. Use
// 'GetConfig' to load options from a configuration profile.
func GetClient(opts ClientOpts) (*Client, error) {
	return &Client{
		Options: opts,
	}, nil
}

// RegisterClient creates a new client for a given InnoVault account
func RegisterClient(registrationToken string, clientName string, publicKey string, privateKey string, backup bool, apiURL string) (*ClientDetails, string, error) {
	if apiURL == "" {
		apiURL = defaultStorageURL
	}

	request := &clientRegistrationRequest{
		Token: registrationToken,
		Client: clientRegistrationInfo{
			Name:      clientName,
			PublicKey: ClientKey{Curve25519: publicKey},
		},
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(request)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/account/e3db/clients/register", apiURL), buf)

	if err != nil {
		return nil, apiURL, err
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, apiURL, err
	}

	defer closeResp(resp)

	var details *ClientDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		closeResp(resp)
		return nil, apiURL, err
	}

	backupClient := resp.Header.Get("X-Backup-Client")

	if backup {
		if privateKey == "" {
			return nil, apiURL, errors.New("Cannot back up client credentials without a private key!")
		}

		pubBytes, _ := base64.RawURLEncoding.DecodeString(publicKey)
		privBytes, _ := base64.RawURLEncoding.DecodeString(privateKey)

		config := &ClientOpts{
			ClientID:    details.ClientID,
			ClientEmail: "",
			APIKeyID:    details.ApiKeyID,
			APISecret:   details.ApiSecret,
			PublicKey:   MakePublicKey(pubBytes),
			PrivateKey:  MakePrivateKey(privBytes),
			APIBaseURL:  "https://api.e3db.com",
			Logging:     false,
		}

		client, err := GetClient(*config)
		if err != nil {
			closeResp(resp)
			return nil, apiURL, err
		}

		client.Backup(context.Background(), backupClient, registrationToken)
	}

	return details, apiURL, nil
}

func (c *Client) apiURL() string {
	if c.Options.APIBaseURL == "" {
		return defaultStorageURL
	}

	return strings.TrimRight(c.Options.APIBaseURL, "/")
}

func logRequest(req *http.Request) {
	reqDump, _ := httputil.DumpRequestOut(req, true)
	scanner := bufio.NewScanner(bytes.NewReader(reqDump))
	for scanner.Scan() {
		fmt.Printf("> %s\n", scanner.Text())
	}
}

func logResponse(resp *http.Response) {
	respDump, _ := httputil.DumpResponse(resp, true)
	scanner := bufio.NewScanner(bytes.NewReader(respDump))
	for scanner.Scan() {
		fmt.Printf("< %s\n", scanner.Text())
	}
}

type httpError struct {
	message    string
	URL        string
	StatusCode int
}

func (err *httpError) Error() string {
	return err.message
}

func closeResp(resp *http.Response) {
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
}

func (c *Client) rawCall(ctx context.Context, req *http.Request, jsonResult interface{}) (*http.Response, error) {
	if c.httpClient == nil {
		config := clientcredentials.Config{
			ClientID:     c.Options.APIKeyID,
			ClientSecret: c.Options.APISecret,
			TokenURL:     c.apiURL() + "/v1/auth/token",
		}
		c.httpClient = config.Client(ctx)
	}

	if c.Options.Logging {
		logRequest(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if c.Options.Logging {
		logResponse(resp)
	}

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		closeResp(resp)
		u := req.URL.String()
		return nil, &httpError{
			StatusCode: resp.StatusCode,
			URL:        u,
			message:    fmt.Sprintf("e3db: %s: server http error %d", u, resp.StatusCode),
		}
	}

	if jsonResult != nil {
		if err := json.NewDecoder(resp.Body).Decode(jsonResult); err != nil {
			closeResp(resp)
			return nil, err
		}
	}

	return resp, nil
}

// GetClientInfo queries the E3DB server for a client's public
// information given its client UUID.
func (c *Client) GetClientInfo(ctx context.Context, clientID string) (*ClientInfo, error) {
	var u, method string

	if strings.Contains(clientID, "@") {
		return nil, errors.New("Email lookup is not supported.")
	} else {
		u = fmt.Sprintf("%s/v1/storage/clients/%s", c.apiURL(), url.QueryEscape(clientID))
		method = "GET"
	}

	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}

	var info ClientInfo
	resp, err := c.rawCall(ctx, req, &info)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)
	return &info, nil
}

// getClientKey queries the E3DB server for a client's public key
// given its client UUID. (This was exported in the Java SDK but
// I'm not sure why since it's rather low level.)
func (c *Client) getClientKey(ctx context.Context, clientID string) (PublicKey, error) {
	info, err := c.GetClientInfo(ctx, clientID)
	if err != nil {
		return nil, err
	}

	key, err := base64Decode(info.PublicKey.Curve25519)
	if err != nil {
		return nil, err
	}

	return MakePublicKey(key), nil
}

// readRaw reads a record given a record ID and returns the record without
// decrypting data fields.
func (c *Client) readRaw(ctx context.Context, recordID string, fields []string) (*Record, error) {
	path := fmt.Sprintf("%s/v1/storage/records/%s", c.apiURL(), recordID)

	if fields != nil && len(fields) > 0 {
		mappedFields := make([]string, len(fields))
		for i, v := range fields {
			mappedFields[i] = fmt.Sprintf("field=%s", url.QueryEscape(v))
		}
		fieldList := strings.Join(mappedFields, "&")
		path = fmt.Sprintf("%s?%s", path, fieldList)
	}

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var record Record
	resp, err := c.rawCall(ctx, req, &record)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)
	return &record, nil
}

// Read reads a record given a record ID, decrypts it, and returns the result.
func (c *Client) Read(ctx context.Context, recordID string) (*Record, error) {
	return c.ReadFields(ctx, recordID, nil)
}

// ReadFields reads a record given a record ID, selecting a subset of fields,
// and returns a decrypted result.
func (c *Client) ReadFields(ctx context.Context, recordID string, fields []string) (*Record, error) {
	record, err := c.readRaw(ctx, recordID, fields)
	if err != nil {
		return nil, err
	}

	if err := c.decryptRecord(ctx, record); err != nil {
		return nil, err
	}

	return record, nil
}

// Write writes a new encrypted record to the database. Returns the new record (with
// the original, unencrypted data)
func (c *Client) Write(ctx context.Context, recordType string, data map[string]string, plain map[string]string) (*Record, error) {
	record := &Record{
		Meta: Meta{
			Type:     recordType,
			WriterID: c.Options.ClientID,
			UserID:   c.Options.ClientID, // for now
			Plain:    plain,
		},
		Data: data,
	}

	encryptedRecord, err := c.encryptRecord(ctx, record)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(encryptedRecord)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/storage/records", c.apiURL()), buf)
	if err != nil {
		return nil, err
	}

	resp, err := c.rawCall(ctx, req, encryptedRecord)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)

	record.Meta.Created = encryptedRecord.Meta.Created
	record.Meta.LastModified = encryptedRecord.Meta.LastModified
	record.Meta.Version = encryptedRecord.Meta.Version
	record.Meta.RecordID = encryptedRecord.Meta.RecordID
	return record, nil
}

// Update a record, if the version field matches the
// version stored by E3DB.
//
// Returns HTTP 409 (Conflict) in error if the record cannot be updated.
func (c *Client) Update(ctx context.Context, record *Record) error {
	encryptedRecord, err := c.encryptRecord(ctx, record)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(encryptedRecord)
	u := fmt.Sprintf("%s/v1/storage/records/safe/%s/%s", c.apiURL(), url.QueryEscape(record.Meta.RecordID), url.QueryEscape(record.Meta.Version))
	req, err := http.NewRequest("PUT", u, buf)
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, encryptedRecord)
	if err != nil {
		return err
	}

	defer closeResp(resp)

	record.Meta = encryptedRecord.Meta
	return nil
}

// Delete removes a record, with optional optimistic locking.
func (c *Client) Delete(ctx context.Context, recordID string, version string) error {
	u := fmt.Sprintf("%s/v1/storage/records/%s", c.apiURL(), url.QueryEscape(recordID))

	if version != "" {
		u = fmt.Sprintf("%s/v1/storage/records/safe/%s/%s", c.apiURL(), url.QueryEscape(recordID), url.QueryEscape(version))
	}

	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return err
	}

	defer closeResp(resp)
	return nil
}

// Backup backs up the client's credentials to an account with which it's registered.
func (c *Client) Backup(ctx context.Context, clientID string, registrationToken string) error {
	credentials := make(map[string]string)
	credentials["version"] = "1"
	credentials["client_id"] = "\"" + c.Options.ClientID + "\""
	credentials["api_key_id"] = "\"" + c.Options.APIKeyID + "\""
	credentials["api_secret"] = "\"" + c.Options.APISecret + "\""
	credentials["client_email"] = "\"" + c.Options.ClientEmail + "\""
	credentials["public_key"] = "\"" + encodePublicKey(c.Options.PublicKey) + "\""
	credentials["private_key"] = "\"" + encodePrivateKey(c.Options.PrivateKey) + "\""
	credentials["api_url"] = "\"" + c.Options.APIBaseURL + "\""

	plain := make(map[string]string)
	plain["client"] = c.Options.ClientID

	c.Write(ctx, "tozny.key_backup", credentials, plain)
	c.Share(ctx, "tozny.key_backup", clientID)

	u := fmt.Sprintf("%s/v1/account/backup/%s/%s", c.apiURL(), registrationToken, c.Options.ClientID)
	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return err
	}

	defer closeResp(resp)
	return nil
}

const allowReadPolicy = `{"allow": [{"read": {}}]}`
const denyReadPolicy = `{"deny": [{"read": {}}]}`

// Share grants another e3db client permission to read records of the
// specified record type.
func (c *Client) Share(ctx context.Context, recordType string, readerID string) error {
	id := c.Options.ClientID
	ak, err := c.getAccessKey(ctx, id, id, id, recordType)
	if err != nil {
		return err
	}

	if ak == nil {
		return errors.New("no applicable records exist to share")
	}

	err = c.putAccessKey(ctx, id, id, readerID, recordType, ak)
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/v1/storage/policy/%s/%s/%s/%s", c.apiURL(), id, id, readerID, recordType)
	req, err := http.NewRequest("PUT", u, strings.NewReader(allowReadPolicy))
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return err
	}

	defer closeResp(resp)
	return nil
}

// Unshare revokes another e3db client's permission to read records of the
// given record type.
func (c *Client) Unshare(ctx context.Context, recordType string, readerID string) error {
	id := c.Options.ClientID
	u := fmt.Sprintf("%s/v1/storage/policy/%s/%s/%s/%s", c.apiURL(), id, id, readerID, recordType)
	req, err := http.NewRequest("PUT", u, strings.NewReader(denyReadPolicy))
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return err
	}

	err = c.deleteAccessKey(ctx, id, id, readerID, recordType)
	if err != nil {
		return err
	}

	defer closeResp(resp)
	return nil
}

// OutgoingSharingPolicy contains information about who and what types of
// records I have shared with.
type OutgoingSharingPolicy struct {
	ReaderID   string `json:"reader_id"`
	Type       string `json:"record_type"`
	ReaderName string `json:"reader_name"`
}

// GetOutgoingSharing returns a list of readers and types of records that
// I am currently sharing.
func (c *Client) GetOutgoingSharing(ctx context.Context) ([]OutgoingSharingPolicy, error) {
	u := fmt.Sprintf("%s/v1/storage/policy/outgoing", c.apiURL())
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var osp []OutgoingSharingPolicy

	resp, err := c.rawCall(ctx, req, &osp)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)
	return osp, nil
}

// IncomingSharingPolicy contains information about who has shared what type
// of records with me.
type IncomingSharingPolicy struct {
	WriterID   string `json:"writer_id"`
	Type       string `json:"record_type"`
	WriterName string `json:"writer_name"`
}

// GetIncomingSharing returns a list of writers and types of records that are
// currently shared with me.
func (c *Client) GetIncomingSharing(ctx context.Context) ([]IncomingSharingPolicy, error) {
	u := fmt.Sprintf("%s/v1/storage/policy/incoming", c.apiURL())
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var isp []IncomingSharingPolicy

	resp, err := c.rawCall(ctx, req, &isp)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)
	return isp, nil
}

/**
SDK V3 prototyping below.
Not for external production use.
Interface is rapidly evolving.
*/

// ToznySDKV3 wraps config and higher level methods for service agnostic &
// user centric operations for accomplishing both low level and complex tasks.
type ToznySDKV3 struct {
	// Embedded low level client to use for account authenticated operations
	// By embedded individual clients it allows for collecting and centralizing
	// all interactions with Tozny services behind a single interface (ToznySDK)
	// e.g. toznySDK.CreateAccount(ctx context.Context, params accountClient.CreateAccountRequest)
	*accountClient.E3dbAccountClient
	*identityClient.E3dbIdentityClient
	*storageClient.StorageClient
	*pdsClient.E3dbPDSClient
	// Account public authentication material for creating and deriving account credentials
	AccountUsername string
	// Account private authentication material for creating and deriving account credentials
	AccountPassword string
	// Network location of the Tozny services to communicate with.
	APIEndpoint string
	// Tozny server defined globally unique id for this Client.
	ClientID string
}

// ToznySDKConfig wraps parameters needed to configure a ToznySDK
type ToznySDKConfig struct {
	e3dbClients.ClientConfig
	AccountUsername string `json:"account_username"`
	AccountPassword string `json:"account_password"`
	APIEndpoint     string `json:"api_url"`
}

// NewToznySDK returns a new instance of the ToznySDK initialized with the provided
// config or error (if any).
func NewToznySDKV3(config ToznySDKConfig) (*ToznySDKV3, error) {
	accountServiceClient := accountClient.New(config.ClientConfig)
	identityClient := identityClient.New(config.ClientConfig)
	storageClient := storageClient.New(config.ClientConfig)
	pdsClient := pdsClient.New(config.ClientConfig)

	return &ToznySDKV3{
		E3dbAccountClient:  &accountServiceClient,
		E3dbIdentityClient: &identityClient,
		StorageClient:      &storageClient,
		E3dbPDSClient:      &pdsClient,
		AccountUsername:    config.AccountUsername,
		AccountPassword:    config.AccountPassword,
		APIEndpoint:        config.APIEndpoint,
		ClientID:           config.ClientID,
	}, nil
}

// GetSDKV3 creates a V3 Tozny SDK based off the JSON contents
// of the file at the specified path, returning config and error (if any).
func GetSDKV3(configJSONFilePath string) (*ToznySDKV3, error) {
	config, err := LoadConfigFile(configJSONFilePath)
	if err != nil {
		return nil, err
	}
	return sdkV3FromConfig(config)
}

func sdkV3FromConfig(config ToznySDKJSONConfig) (*ToznySDKV3, error) {
	return NewToznySDKV3(ToznySDKConfig{
		ClientConfig: e3dbClients.ClientConfig{
			ClientID:  config.ClientID,
			APIKey:    config.APIKeyID,
			APISecret: config.APISecret,
			Host:      config.APIBaseURL,
			AuthNHost: config.APIBaseURL,
			SigningKeys: e3dbClients.SigningKeys{
				Public: e3dbClients.Key{
					Type:     e3dbClients.DefaultSigningKeyType,
					Material: config.PublicSigningKey,
				},
				Private: e3dbClients.Key{
					Type:     e3dbClients.DefaultSigningKeyType,
					Material: config.PrivateSigningKey,
				},
			},
			EncryptionKeys: e3dbClients.EncryptionKeys{
				Private: e3dbClients.Key{
					Material: config.PrivateKey,
					Type:     e3dbClients.DefaultEncryptionKeyType,
				},
				Public: e3dbClients.Key{
					Material: config.PublicKey,
					Type:     e3dbClients.DefaultEncryptionKeyType,
				},
			},
		},
		AccountUsername: config.AccountUsername,
		AccountPassword: config.AccountPassword,
		APIEndpoint:     config.APIBaseURL,
	})
}

type LoginActionData = map[string]string

type TozIDLoginRequest struct {
	Username  string
	Password  string
	RealmName string

	APIBaseURL string
	LoginHandler func(response *identityClient.IdentitySessionRequestResponse) (LoginActionData, error)
}

//GetSDKV3ForTozIDUser logs in a TozID user and returns the storage client of that user as a ToznySDKV3
func GetSDKV3ForTozIDUser(login TozIDLoginRequest) (*ToznySDKV3, error) {
	if login.APIBaseURL == "" {
		login.APIBaseURL = "https://api.e3db.com"
	}
	username := strings.ToLower(login.Username)
	anonConfig := e3dbClients.ClientConfig{
		Host:      login.APIBaseURL,
		AuthNHost: login.APIBaseURL,
	}
	ctx := context.Background()
	anonymousClient := identityClient.New(anonConfig)
	realmInfo, err := anonymousClient.RealmInfo(ctx, login.RealmName)
	if err != nil {
		// TODO: better error message for failure to get realmInfo
		return nil, err
	}
	noteName, encryptionKeys, signingKeys, err := e3dbClients.DeriveIdentityCredentials(username, login.Password, realmInfo.Name, "")
	if err != nil {
		return nil, err
	}
	clientConfig := e3dbClients.ClientConfig{
		Host:           login.APIBaseURL,
		AuthNHost:      login.APIBaseURL,
		SigningKeys:    signingKeys,
		EncryptionKeys: encryptionKeys,
	}
	idClient := identityClient.New(clientConfig)
	loginResponse, err := idClient.InitiateIdentityLogin(ctx, identityClient.IdentityLoginRequest{
		Username:   username,
		RealmName:  login.RealmName,
		AppName:    "account",
		LoginStyle: "api",
	})
	if err != nil {
		return nil, err
	}
	sessionResponse, err := idClient.IdentitySessionRequest(ctx, realmInfo.Name, *loginResponse)
	if err != nil {
		return nil, err
	}
	// TODO: rework this to support brokered logins. See JS SDK for examples
	for {
		if sessionResponse.LoginActionType == "fetch" {
			break
		}
		switch sessionResponse.LoginActionType {
		case "continue":
			data := url.Values{}
			request, err := http.NewRequest("POST", sessionResponse.ActionURL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, err
			}
			err = e3dbClients.MakeSignedServiceCall(ctx, &http.Client{}, request, signingKeys, "", &sessionResponse)
			if err != nil {
				return nil, err
			}
		default:
			if login.LoginHandler == nil {
				return nil, fmt.Errorf("A Login handler must be provided for action type %s", sessionResponse.LoginActionType)
			}
			data, err := login.LoginHandler(sessionResponse)
			if err != nil {
				return nil, err
			}
			var reader io.Reader
			if sessionResponse.ContentType == "application/x-www-form-urlencoded" {
				values := url.Values{}
				for key, value := range data {
					values.Set(key, value)
				}
				reader = strings.NewReader(values.Encode())
			} else {
				var buf bytes.Buffer
				err := json.NewEncoder(&buf).Encode(&data)
				if err != nil {
					return nil, err
				}
				reader = &buf
			}
			request, err := http.NewRequest("POST", sessionResponse.ActionURL, reader)
			request.Header.Set("Content-Type", sessionResponse.ContentType)
			if err != nil {
				return nil, err
			}
			err = e3dbClients.MakeSignedServiceCall(ctx, &http.Client{}, request, signingKeys, "", &sessionResponse)
			if err != nil {
				return nil, err
			} else if sessionResponse.Message.IsError {
				return nil, fmt.Errorf(sessionResponse.Message.Summary)
			}
		}
	}
	redirectRequest := identityClient.IdentityLoginRedirectRequest{
		RealmName: realmInfo.Domain,
		// The following map values if not present will be set to the empty string and identity service will handle appropriately
		SessionCode:   sessionResponse.Context["session_code"],
		Execution:     sessionResponse.Context["execution"],
		TabID:         sessionResponse.Context["tab_id"],
		ClientID:      sessionResponse.Context["client_id"],
		AuthSessionId: sessionResponse.Context["auth_session_id"],
	}
	redirect, err := idClient.IdentityLoginRedirect(ctx, redirectRequest)
	if err != nil {
		return nil, err
	}
	storage := storageClient.New(clientConfig)
	note, err := storage.ReadNoteByName(ctx, noteName, map[string]string{storageClient.TozIDLoginTokenHeader: redirect.AccessToken})
	if err != nil {
		return nil, err
	}
	err = storage.DecryptNote(note)
	if err != nil {
		return nil, err
	}
	var config ToznySDKJSONConfig
	err = json.Unmarshal([]byte(note.Data["storage"]), &config)
	if err != nil {
		return nil, err
	}
	return sdkV3FromConfig(config)

}

// CreateResponse wraps the value return from the account creation method
type RegisterAccountResponse struct {
	PaperKey string
	Account  Account
}

// Account wraps the data needed to make TozStore account calls
type Account struct {
	AccountID string
	// JWT that can be used for later requests against the account service.
	Token  string
	Config ClientConfig
	Client *accountClient.E3dbAccountClient
}

// Challenge wraps the parameters needed to initiate and account login
type Challenge struct {
	Challenge     string `json:"challenge"`
	AuthSalt      string `json:"auth_salt"`
	PaperAuthSalt string `json:"paper_auth_salt"`
}

// AuthResponse wraps data returned from a completed login challenge
type AuthResponse struct {
	Token   string
	Profile *accountClient.Profile
	Account *accountClient.Account
}

// ProfileMeta wraps the JSON struct for account meta
type ProfileMeta struct {
	Enabled      string `json:"backupEnabled"`
	BackupClient string `json:"backupClient"`
	PaperBackup  string `json:"paperBackup"`
}

// ClientConfig provides a simpler way to serialize/deserialized client
// credentials stored in account meta
type ClientConfig struct {
	Version           int    `json:"version"`
	APIURL            string `json:"api_url"`
	ClientEmail       string `json:"client_email"`
	ClientID          string `json:"client_id"`
	APIKeyID          string `json:"api_key_id"`
	APISecret         string `json:"api_secret"`
	PublicKey         string `json:"public_key"`
	PrivateKey        string `json:"private_key"`
	PublicSigningKey  string `json:"public_signing_key"`
	PrivateSigningKey string `json:"private_signing_key"`
}

// Register attempts to create a valid TozStore account returning the root client config for the created account and error (if any).
func (c *ToznySDKV3) Register(ctx context.Context, name string, email string, password string, apiURL string) (RegisterAccountResponse, error) {
	if apiURL == "" {
		apiURL = defaultStorageURL
	}
	const (
		pwEncSalt  = "pwEncSalt"
		pwAuthSalt = "pwAuthSalt"
		pkEncSalt  = "pkEncSalt"
		pkAuthSalt = "pkAuthSalt"
	)
	// Boot client
	bootClientConfig := e3dbClients.ClientConfig{
		Host:      apiURL,
		AuthNHost: apiURL,
	}
	bootClient := accountClient.New(bootClientConfig)
	var createResponse RegisterAccountResponse
	var accountClientConfig = e3dbClients.ClientConfig{
		Host:      apiURL,
		AuthNHost: apiURL,
	}
	var accountResponse *accountClient.CreateAccountResponse

	paperKeyRaw := make([]byte, 64)
	_, err := rand.Read(paperKeyRaw)
	if err != nil {
		return createResponse, fmt.Errorf("reading bytes for paper key: %v", err)
	}
	paperKey := base64.RawURLEncoding.EncodeToString(paperKeyRaw)

	salts := make(map[string][]byte, 4)
	for _, name := range []string{pwEncSalt, pwAuthSalt, pkEncSalt, pkAuthSalt} {
		salt := make([]byte, e3dbClients.SaltSize)
		_, err = rand.Read(salt)
		if err != nil {
			return createResponse, fmt.Errorf("reading bytes for salt %s: %v", name, err)
		}
		salts[name] = salt
	}

	// Derive keys
	pwSigningKey, _ := e3dbClients.DeriveSigningKey([]byte(password), salts[pwAuthSalt], e3dbClients.AccountDerivationRounds)
	pwEncKey := e3dbClients.DeriveSymmetricKey([]byte(password), salts[pwEncSalt], e3dbClients.AccountDerivationRounds)
	pkSigningKey, _ := e3dbClients.DeriveSigningKey([]byte(paperKey), salts[pwAuthSalt], e3dbClients.AccountDerivationRounds)
	pkEncKey := e3dbClients.DeriveSymmetricKey([]byte(paperKey), salts[pkEncSalt], e3dbClients.AccountDerivationRounds)
	// Generate client keys
	encryptionKeypair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		return createResponse, fmt.Errorf("Failed generating encryption key pair %s", err)
	}
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		return createResponse, fmt.Errorf("Failed generating signing key pair %s", err)
	}
	createAccountParams := accountClient.CreateAccountRequest{
		Profile: accountClient.Profile{
			Name:               email,
			Email:              email,
			AuthenticationSalt: base64.RawURLEncoding.EncodeToString(salts[pwAuthSalt]),
			EncodingSalt:       base64.RawURLEncoding.EncodeToString(salts[pwEncSalt]),
			SigningKey: accountClient.EncryptionKey{
				Ed25519: base64.RawURLEncoding.EncodeToString(pwSigningKey[:]),
			},
			PaperAuthenticationSalt: base64.RawURLEncoding.EncodeToString(salts[pkAuthSalt]),
			PaperEncodingSalt:       base64.RawURLEncoding.EncodeToString(salts[pkEncSalt]),
			PaperSigningKey: accountClient.EncryptionKey{
				Ed25519: base64.RawURLEncoding.EncodeToString(pkSigningKey[:]),
			},
		},
		Account: accountClient.Account{
			Company: name,
			Plan:    "free0",
			PublicKey: accountClient.ClientKey{
				Curve25519: encryptionKeypair.Public.Material,
			},
			SigningKey: accountClient.EncryptionKey{
				Ed25519: signingKeys.Public.Material,
			},
		},
	}
	// Create an account and client for that account using the specified params
	accountResponse, err = bootClient.CreateAccount(ctx, createAccountParams)
	if err != nil {
		return createResponse, fmt.Errorf("creating account with params: %v - %+v", err, createAccountParams)
	}
	clientConfig := ClientConfig{
		Version:           2,
		APIURL:            apiURL,
		ClientID:          accountResponse.Account.Client.ClientID,
		APIKeyID:          accountResponse.Account.Client.APIKeyID,
		APISecret:         accountResponse.Account.Client.APISecretKey,
		PublicKey:         encryptionKeypair.Public.Material,
		PrivateKey:        encryptionKeypair.Private.Material,
		PublicSigningKey:  signingKeys.Public.Material,
		PrivateSigningKey: signingKeys.Private.Material,
	}
	serializedConfig, err := json.Marshal(clientConfig)
	if err != nil {
		return createResponse, fmt.Errorf("serializing config: %v", err)
	}
	pwConfig := e3dbClients.Encrypt(serializedConfig, e3dbClients.MakeSymmetricKey(pwEncKey[:]))
	pkConfig := e3dbClients.Encrypt(serializedConfig, e3dbClients.MakeSymmetricKey(pkEncKey[:]))
	meta := ProfileMeta{
		Enabled:      "enabled",
		BackupClient: pwConfig,
		PaperBackup:  pkConfig,
	}

	accountClientConfig.ClientID = accountResponse.Account.Client.ClientID
	accountClientConfig.APIKey = accountResponse.Account.Client.APIKeyID
	accountClientConfig.APISecret = accountResponse.Account.Client.APISecretKey
	accountClientConfig.SigningKeys = signingKeys
	accountClientConfig.EncryptionKeys = e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Material: encryptionKeypair.Private.Material,
			Type:     e3dbClients.DefaultEncryptionKeyType},
		Public: e3dbClients.Key{
			Material: encryptionKeypair.Public.Material,
			Type:     e3dbClients.DefaultEncryptionKeyType},
	}
	accountToken := accountResponse.AccountServiceToken
	account := accountClient.New(accountClientConfig)
	path := account.Host + "/v1/account/profile/meta"
	request, err := e3dbClients.CreateRequest("PUT", path, meta)
	if err != nil {
		return createResponse, e3dbClients.NewError(err.Error(), path, 0)
	}
	requester := http.Client{}
	err = e3dbClients.MakeProxiedUserCall(context.Background(), &requester, accountToken, request, nil)
	if err != nil {
		return createResponse, fmt.Errorf("updating profile meta: %v", err)
	}
	createResponse.PaperKey = paperKey
	createResponse.Account = Account{
		AccountID: accountResponse.Profile.AccountID,
		Token:     accountToken,
		Config:    clientConfig,
		Client:    &account,
	}
	return createResponse, nil
}

// Login derives the needed keys and fetches an active account session
func (c *ToznySDKV3) Login(ctx context.Context, email string, password string, salt string, apiEndpoint string) (Account, error) {
	var account Account
	var err error
	var challenge Challenge
	apiHost := c.APIEndpoint
	if apiEndpoint != "" {
		apiHost = apiEndpoint
	}
	body := map[string]string{}
	body["email"] = strings.ToLower(email)
	path := apiHost + "/v1/account/challenge"
	request, err := e3dbClients.CreateRequest("POST", path, body)
	if err != nil {
		return account, e3dbClients.NewError(err.Error(), path, 0)
	}
	requester := &http.Client{}
	err = e3dbClients.MakePublicCall(ctx, requester, request, &challenge)
	if err != nil {
		return account, fmt.Errorf("initiating login challenge: %v", err)
	}
	var authSalt []byte
	if salt != "paper" {
		authSalt, err = base64.RawURLEncoding.DecodeString(challenge.AuthSalt)
	} else {
		authSalt, err = base64.RawURLEncoding.DecodeString(challenge.PaperAuthSalt)
	}
	if err != nil {
		return account, fmt.Errorf("decoding salt: %v", err)
	}
	_, privateKey := e3dbClients.DeriveSigningKey([]byte(password), authSalt, e3dbClients.AccountDerivationRounds)
	challengeBytes, err := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return account, fmt.Errorf("decoding signature: %v", err)
	}
	// challenge.challenge, sigKeys.privateKey
	signatureBytes := e3dbClients.Sign(challengeBytes, privateKey)
	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)
	body["challenge"] = challenge.Challenge
	body["response"] = signature
	if salt != "paper" {
		body["keyid"] = "password"
	} else {
		body["keyid"] = "paper"
	}
	path = apiHost + "/v1/account/auth"
	request, err = e3dbClients.CreateRequest("POST", path, body)
	if err != nil {
		return account, e3dbClients.NewError(err.Error(), path, 0)
	}
	var authResponse AuthResponse
	err = e3dbClients.MakePublicCall(ctx, requester, request, &authResponse)
	if err != nil {
		return account, fmt.Errorf("error %v initiating login challenge %+v", err, request)
	}
	var meta ProfileMeta
	accountToken := authResponse.Token
	path = apiHost + "/v1/account/profile/meta"
	request, err = e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return account, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeProxiedUserCall(ctx, requester, accountToken, request, &meta)
	if err != nil {
		return account, fmt.Errorf("updating profile meta: %v", err)
	}
	var encSalt []byte
	if salt != "paper" {
		encSalt, err = base64.RawURLEncoding.DecodeString(authResponse.Profile.EncodingSalt)
	} else {
		encSalt, err = base64.RawURLEncoding.DecodeString(authResponse.Profile.PaperEncodingSalt)
	}
	if err != nil {
		return account, fmt.Errorf("decoding salt: %v", err)
	}
	encKey := e3dbClients.DeriveSymmetricKey([]byte(password), encSalt, e3dbClients.AccountDerivationRounds)
	var encCipher string
	if salt != "paper" {
		encCipher = meta.BackupClient
	} else {
		encCipher = meta.PaperBackup
	}
	var clientConfig ClientConfig
	clientJSON, err := e3dbClients.Decrypt(encCipher, e3dbClients.MakeSymmetricKey(encKey[:]))
	if err != nil {
		return account, fmt.Errorf("decrypting client credentials: %v", err)
	}
	err = json.Unmarshal(clientJSON, &clientConfig)
	if err != nil {
		return account, fmt.Errorf("decoding client credentials: %v", err)
	}

	var accountClientConfig = e3dbClients.ClientConfig{
		Host:      apiHost,
		AuthNHost: apiHost,
		ClientID:  clientConfig.ClientID,
		APIKey:    clientConfig.APIKeyID,
		APISecret: clientConfig.APISecret,
		SigningKeys: e3dbClients.SigningKeys{
			Private: e3dbClients.Key{
				Material: clientConfig.PrivateSigningKey,
				Type:     e3dbClients.DefaultSigningKeyType},
			Public: e3dbClients.Key{
				Material: clientConfig.PublicSigningKey,
				Type:     e3dbClients.DefaultSigningKeyType},
		},
		EncryptionKeys: e3dbClients.EncryptionKeys{
			Private: e3dbClients.Key{
				Material: clientConfig.PrivateKey,
				Type:     e3dbClients.DefaultEncryptionKeyType},
			Public: e3dbClients.Key{
				Material: clientConfig.PublicKey,
				Type:     e3dbClients.DefaultEncryptionKeyType},
		},
	}
	mainClient := accountClient.New(accountClientConfig)
	account.Client = &mainClient
	account.Token = accountToken
	account.Config = clientConfig
	return account, nil
}

// ConvertBrokerIdentityToClientConfig converts a broker identity to raw Tozny client credentials.
func ConvertBrokerIdentityToClientConfig(broker identityClient.Identity, clientURL string) ClientConfig {
	return ClientConfig{
		APIKeyID:          broker.APIKeyID,
		APISecret:         broker.APIKeySecret,
		APIURL:            clientURL,
		ClientEmail:       "",
		ClientID:          broker.ToznyID.String(),
		PrivateKey:        broker.PrivateEncryptionKeys[e3dbClients.DefaultEncryptionKeyType],
		PrivateSigningKey: broker.PrivateSigningKeys[e3dbClients.DefaultSigningKeyType],
		PublicKey:         broker.PublicKeys[e3dbClients.DefaultEncryptionKeyType],
		PublicSigningKey:  broker.SigningKeys[e3dbClients.DefaultSigningKeyType],
		Version:           2,
	}
}

type NoteBody map[string]string

// GenerateRealmBrokerNoteToken writes a note whose contents are the broker identity credentials
// and returns a token that can be used to fetch and decrypt that note or error (if any).
func (c *ToznySDKV3) GenerateRealmBrokerNoteToken(ctx context.Context, broker identityClient.Identity) (string, error) {
	serializedBrokerCredentialsBytes, err := json.Marshal(ConvertBrokerIdentityToClientConfig(broker, c.APIEndpoint))
	if err != nil {
		return "", err
	}
	// Generate a random value for deriving the keys needed to
	// read and decrypt the broker note by a third party
	base64NotePassword := e3dbClients.Base64Encode(e3dbClients.RandomSymmetricKey()[:])
	base64NotePasswordBytes := []byte(base64NotePassword)
	// Generate nonces to use in broker note key derivation
	encodingNonce := e3dbClients.RandomNonce()
	signingNone := e3dbClients.RandomNonce()
	// Start accumulating the values that will be needed for a third party to
	// derive keys for reading and decrypting the broker note
	tokenSeed := base64NotePassword + e3dbClients.Base64Encode(encodingNonce[:]) + e3dbClients.Base64Encode(signingNone[:])
	// Derive keys for encrypting and signing the broker note
	publicEncryptionKey, _ := e3dbClients.DeriveCryptoKey(base64NotePasswordBytes, encodingNonce[:], e3dbClients.IdentityDerivationRounds)
	publicSigningKey, _ := e3dbClients.DeriveSigningKey(base64NotePasswordBytes, signingNone[:], e3dbClients.IdentityDerivationRounds)
	// Content for the broker note is all the information needed to instantiate
	// the broker identity for the realm it can broker actions for
	rawNoteBody := NoteBody{
		"realmId":   fmt.Sprintf("%d", broker.RealmID),
		"realmName": broker.RealmName,
		"client":    string(serializedBrokerCredentialsBytes),
		"publicKey": e3dbClients.Base64Encode(publicSigningKey[:]),
	}

	rawBrokerNote := storageClient.Note{
		Mode:                e3dbClients.DefaultCryptographicMode,
		RecipientSigningKey: e3dbClients.Base64Encode(publicSigningKey[:]),
		WriterSigningKey:    c.StorageClient.SigningKeys.Public.Material,
		WriterEncryptionKey: c.StorageClient.EncryptionKeys.Public.Material,
		Data:                rawNoteBody,
		Type:                "Realm Broker Note",
		MaxViews:            -1,
		Expires:             false,
	}
	// Sign over all the broker note data and the signature material itself
	privateSigningKeyBytes, err := e3dbClients.Base64Decode(c.StorageClient.SigningKeys.Private.Material)
	if err != nil {
		return "", err
	}
	notePrivateSigningKey := [e3dbClients.SigningKeySize]byte{}
	copy(notePrivateSigningKey[:], privateSigningKeyBytes)
	signingSalt := uuid.New().String()
	signedNote, err := c.SignNote(rawBrokerNote, &notePrivateSigningKey, signingSalt)
	if err != nil {
		return "", err
	}
	// Create and asymmetrically encrypt an access key using the writing clients private key
	// and the brokers public key, whoever gains access to the broker's private key
	// (such as being able to derive it by possessing the broker note token)
	// and the public keys for the writing client which are embedded in the note itself
	// will be able to decrypt this access key and thus the note contents itself
	// using the mathematical magic of public key cryptography
	accessKey := e3dbClients.RandomSymmetricKey()
	encryptedAccessKey, err := e3dbClients.EncryptAccessKey(accessKey, e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: c.StorageClient.EncryptionKeys.Private.Material,
		},
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: e3dbClients.Base64Encode(publicEncryptionKey[:]),
		},
	})
	if err != nil {
		return "", err
	}
	// Encrypt the signed note and add the encrypted version of the access
	// key to the note for the reader to be able to decrypt the note
	encryptedNoteBody := e3dbClients.EncryptData(signedNote.Data, accessKey)
	signedNote.Data = *encryptedNoteBody
	signedNote.EncryptedAccessKey = encryptedAccessKey
	// Write the broker note
	brokerNote, err := c.WriteNote(ctx, signedNote)
	if err != nil {
		return "", err
	}
	// Construct the token whose value can be used to fetch and decrypt the broker note
	brokerNoteToken := tokenSeed + brokerNote.NoteID

	return brokerNoteToken, nil
}

// AddAuthorizedSharer adds the specified client as an authorized sharer
// for records of the specified type written by the authorizing client,
// returning error (if any).
func (c *ToznySDKV3) AddAuthorizedSharer(ctx context.Context, authorizedSharerClientID string, recordType string) error {
	_, err := c.GetOrCreateAccessKey(ctx, pdsClient.GetOrCreateAccessKeyRequest{
		WriterID:   c.ClientID,
		UserID:     c.ClientID,
		ReaderID:   c.ClientID,
		RecordType: recordType,
	})
	if err != nil {
		return err
	}
	return c.E3dbPDSClient.AddAuthorizedSharer(ctx, pdsClient.AddAuthorizedWriterRequest{
		UserID:       c.ClientID,
		WriterID:     c.ClientID,
		AuthorizerID: authorizedSharerClientID,
		RecordType:   recordType,
	})
}

// RemoveAuthorizedSharer removes the specified client as an authorized sharer
// for records of the specified type written by the authorizing client,
// returning error (if any).
func (c *ToznySDKV3) RemoveAuthorizedSharer(ctx context.Context, authorizedSharerClientID string, recordType string) error {
	return c.E3dbPDSClient.RemoveAuthorizedSharer(ctx, pdsClient.AddAuthorizedWriterRequest{
		UserID:       c.ClientID,
		WriterID:     c.ClientID,
		AuthorizerID: authorizedSharerClientID,
		RecordType:   recordType,
	})
}

// AddAuthorizedSharer adds the specified client as an authorized sharer
// for records of the specified type written by the authorizing client,
// returning error (if any).
func (c *ToznySDKV3) BrokerShare(ctx context.Context, authorizerClientID string, readerClientID string, recordType string) error {
	return c.AuthorizerShareRecords(ctx, pdsClient.AuthorizerShareRecordsRequest{
		UserID:       authorizerClientID,
		WriterID:     authorizerClientID,
		AuthorizerID: c.ClientID,
		ReaderID:     readerClientID,
		RecordType:   recordType,
	})
}

// RemoveAuthorizedSharer removes the specified client as an authorized sharer
// for records of the specified type written by the authorizing client,
// returning error (if any).
func (c *ToznySDKV3) UnbrokerShare(ctx context.Context, authorizerClientID string, readerClientID string, recordType string) error {
	return c.AuthorizerUnshareRecords(ctx, pdsClient.AuthorizerUnshareRecordsRequest{
		UserID:       authorizerClientID,
		WriterID:     authorizerClientID,
		AuthorizerID: c.ClientID,
		ReaderID:     readerClientID,
		RecordType:   recordType,
	})
}
