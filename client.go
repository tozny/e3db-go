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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/file"
	"github.com/tozny/e3db-clients-go/identityClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"github.com/tozny/e3db-clients-go/searchExecutorClient"
	"github.com/tozny/e3db-clients-go/secureComputeClient"
	"github.com/tozny/e3db-clients-go/storageClient"

	"github.com/google/uuid"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	DefaultStorageURL               = "https://api.e3db.com"
	DefaultEncryptedFileName        = "encrypted"
	DefaultDownloadedFileName       = "downloaded"
	SecretUUID                      = "38bb737a-4ce0-5ead-8585-e13ea23b09a6"
	SecretWriterUsernameMetadataKey = "username"
	SecretSharedMetadataKey         = "shared"
	SecretFileSizeMetadataKey       = "size"
	SecretFilenameMetadataKey       = "fileName"
	SecretTypeMetadataKey           = "secretType"
	SecretDescriptionMetadataKey    = "description"
	SecretNameMetadataKey           = "secretName"
	SecretVersionMetadataKey        = "version"
	SecretValueDataKey              = "secretValue"
	AccountApplicationName          = "account"
)

const (
	FileSecretType       = "File"
	CredentialSecretType = "Credential"
	ClientSecretType     = "Client"
)

var (
	SecretTypes = []string{ClientSecretType, CredentialSecretType, FileSecretType}
)

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

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
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
		apiURL = DefaultStorageURL
	}

	request := &clientRegistrationRequest{
		Token: registrationToken,
		Client: clientRegistrationInfo{
			Name:      clientName,
			PublicKey: ClientKey{Curve25519: publicKey},
		},
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(request); err != nil {
		return nil, apiURL, fmt.Errorf("failed to encode request: %v", err)
	}

	url := fmt.Sprintf("%s/v1/account/e3db/clients/register", apiURL)

	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		return nil, apiURL, fmt.Errorf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, apiURL, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read the entire response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apiURL, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status code indicates an error
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, apiURL, fmt.Errorf("API returned non-200 status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var details *ClientDetails
	if err := json.Unmarshal(body, &details); err != nil {
		return nil, apiURL, fmt.Errorf("failed to decode response JSON: %v, raw response: %s", err, string(body))
	}

	backupClient := resp.Header.Get("X-Backup-Client")
	if backup {
		if privateKey == "" {
			return nil, apiURL, errors.New("cannot back up client credentials without a private key")
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
			return nil, apiURL, fmt.Errorf("failed to get client for backup: %v", err)
		}
		if err := client.Backup(context.Background(), backupClient, registrationToken); err != nil {
			return nil, apiURL, fmt.Errorf("failed to backup client: %v", err)
		}
	}

	return details, apiURL, nil
}

func (c *Client) apiURL() string {
	if c.Options.APIBaseURL == "" {
		return DefaultStorageURL
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
	io.Copy(io.Discard, resp.Body)
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
	*accountClient.E3dbAccountClientV2
	*secureComputeClient.E3dbSecureComputeClient
	// Account public authentication material for creating and deriving account credentials
	AccountUsername string
	// Account private authentication material for creating and deriving account credentials
	AccountPassword string
	// Network location of the Tozny services to communicate with.
	APIEndpoint string
	// Tozny server defined globally unique id for this Client.
	ClientID        string
	CurrentIdentity TozIDSessionIdentityData
	// TozIDRealmIDPAccessToken is the tozid-realm-idp jwt given by final redirect of login flow.
	// because it expires, it is not saved to the config file, and so can be empty.
	TozIDRealmIDPAccessToken  *string
	TozIDRealmIDPRefreshToken *string
	TozIDRealmIDPIDToken      *string
	config                    e3dbClients.ClientConfig
	akCache                   map[akCacheKey]e3dbClients.SymmetricKey
}

// LoggedInIdentityData represents data about the identity session of a given user. Currently that is just realm and
// username but in the future may include tokens
type TozIDSessionIdentityData struct {
	Username string `json:"username"`
	Realm    string `json:"realm"`
}

// ToznySDKConfig wraps parameters needed to configure a ToznySDK
type ToznySDKConfig struct {
	e3dbClients.ClientConfig
	TozIDSessionIdentityData `json:"toz_id_session_identity_data"`
	AccountUsername          string `json:"account_username"`
	AccountPassword          string `json:"account_password"`
	APIEndpoint              string `json:"api_url"`
	// TozIDRealmIDPAccessToken is populated during the login process.
	// The token can expire so is purposefully not preserved in the saved JSON, and so can be empty.
	TozIDRealmIDPAccessToken *string
}

// NewToznySDK returns a new instance of the ToznySDK initialized with the provided
// config or error (if any).
func NewToznySDKV3(config ToznySDKConfig) (*ToznySDKV3, error) {
	accountServiceV2Client := accountClient.NewV2(config.ClientConfig)
	accountServiceClient := accountClient.New(config.ClientConfig)
	identityClient := identityClient.New(config.ClientConfig)
	storageClient := storageClient.New(config.ClientConfig)
	pdsClient := pdsClient.New(config.ClientConfig)
	secureComputeClient := secureComputeClient.New(config.ClientConfig)

	return &ToznySDKV3{
		E3dbAccountClient:        &accountServiceClient,
		E3dbAccountClientV2:      &accountServiceV2Client,
		E3dbIdentityClient:       &identityClient,
		StorageClient:            &storageClient,
		E3dbPDSClient:            &pdsClient,
		E3dbSecureComputeClient:  &secureComputeClient,
		AccountUsername:          config.AccountUsername,
		AccountPassword:          config.AccountPassword,
		APIEndpoint:              config.APIEndpoint,
		ClientID:                 config.ClientID,
		CurrentIdentity:          config.TozIDSessionIdentityData,
		TozIDRealmIDPAccessToken: config.TozIDRealmIDPAccessToken,
		config:                   config.ClientConfig,
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
		AccountUsername:          config.AccountUsername,
		AccountPassword:          config.AccountPassword,
		APIEndpoint:              config.APIBaseURL,
		TozIDRealmIDPAccessToken: config.TozIDRealmIDPAccessToken,
		TozIDSessionIdentityData: TozIDSessionIdentityData{
			Username: config.Username,
			Realm:    config.Realm,
		},
	})
}

type LoginActionData = map[string]string

type IdentitySessionIntermediateResponse = identityClient.IdentitySessionRequestResponse

// TozIDLoginRequest is used to login to a TozID account to get a ToznySDKV3 or active TozID session (future plan)
type TozIDLoginRequest struct {
	Username     string
	Password     string
	RealmName    string
	APIBaseURL   string
	LoginHandler func(response *IdentitySessionIntermediateResponse) (LoginActionData, error)
}

// GetSDKV3ForTozIDUser logs in a TozID user and returns the storage client of that user as a ToznySDKV3
func GetSDKV3ForTozIDUser(login TozIDLoginRequest) (*ToznySDKV3, error) {
	if login.APIBaseURL == "" {
		login.APIBaseURL = "https://api.e3db.com"
	} else {
		login.APIBaseURL = strings.TrimSuffix(strings.TrimSpace(login.APIBaseURL), "/")
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
		return nil, fmt.Errorf("GetSDKV3ForTozIDUser: failed to get realm infor with error %w", err)
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
	federated := false
	var brokerStorageClient storageClient.StorageClient
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
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			err = e3dbClients.MakeSignedServiceCall(ctx, &http.Client{}, request, signingKeys, "", &sessionResponse)
			if err != nil {
				return nil, err
			}
		case "password-challenge":
			federated = true
			data := url.Values{}
			data.Add("password", login.Password)
			request, err := http.NewRequest("POST", sessionResponse.ActionURL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, err
			}
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			err = e3dbClients.MakeSignedServiceCall(ctx, &http.Client{}, request, signingKeys, "", &sessionResponse)
			if err != nil {
				return nil, err
			}
		case "register-brokered-user":
			data := url.Values{}
			brokerStorageClient = storageClient.New(clientConfig)
			data["public_key"] = []string{brokerStorageClient.EncryptionKeys.Public.Material}
			data["public_signing_key"] = []string{brokerStorageClient.SigningKeys.Public.Material}
			request, err := http.NewRequest("POST", sessionResponse.ActionURL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, err
			}
			request.Header.Set("Content-Type", sessionResponse.ContentType)
			err = e3dbClients.MakeSignedServiceCall(ctx, &http.Client{}, request, signingKeys, "", &sessionResponse)
			if err != nil {
				return nil, err
			}
		case "complete-broker-registration":
			// Get the api_key_id
			apiKey := ""
			res := sessionResponse.Context["result"]
			if res == nil {
				return nil, fmt.Errorf("Failed result lookup")
			}
			identityIface, ok := res.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("Failed identity lookup")
			}
			id := identityIface["identity"]
			if id == nil {
				return nil, fmt.Errorf("Failed identity lookup")
			}
			idMap, ok := id.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("Failed apikey lookup")
			}
			api_key_id := idMap["api_key_id"]
			if api_key_id != nil {
				apiKey = api_key_id.(string)
			}
			if apiKey == "" {
				return nil, fmt.Errorf("Failed apikey lookup")
			}
			apiSecret := idMap["api_secret_key"].(string)
			clientConfig.APIKey = apiKey
			clientConfig.APISecret = apiSecret
			// Setup identity to write broker notes
			idObj := &Identity{
				ID:        int64(idMap["id"].(float64)),
				Username:  idMap["name"].(string),
				FirstName: idMap["first_name"].(string),
				LastName:  idMap["last_name"].(string),
				Realm: &Realm{
					Name:            login.RealmName,
					App:             "account",
					APIEndpoint:     login.APIBaseURL,
					BrokerTargetURL: login.APIBaseURL + "/" + login.RealmName + "/" + "recover",
					realmInfo: &identityClient.RealmInfo{
						Name:   login.RealmName,
						Domain: login.RealmName,
					},
				},
			}
			idObj.Realm.realmInfo.BrokerIdentityToznyID.UnmarshalText([]byte(identityIface["realm_broker_identity_tozny_id"].(string)))
			pdsClient := pdsClient.New(clientConfig)
			idObj.ToznySDKV3 = &ToznySDKV3{
				APIEndpoint:   login.APIBaseURL,
				E3dbPDSClient: &pdsClient,
				StorageClient: &brokerStorageClient,
			}
			idObj.ToznySDKV3.ClientID = idMap["tozny_id"].(string)
			brokerStorageClient.ClientID = idMap["tozny_id"].(string)
			brokerStorageClient.APIKey = apiKey
			brokerStorageClient.APISecret = apiSecret
			email := idMap["email"].(string)
			_, err := idObj.writeBrokeredLoginNotes(email)
			if err != nil {
				return nil, err
			}
			data := url.Values{}
			request, err := http.NewRequest("POST", sessionResponse.ActionURL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, err
			}
			request.Header.Set("Content-Type", sessionResponse.ContentType)
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
			if err != nil {
				return nil, err
			}
			request.Header.Set("Content-Type", sessionResponse.ContentType)
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
		SessionCode:   sessionResponse.Context["session_code"].(string),
		Execution:     sessionResponse.Context["execution"].(string),
		TabID:         sessionResponse.Context["tab_id"].(string),
		ClientID:      sessionResponse.Context["client_id"].(string),
		AuthSessionId: sessionResponse.Context["auth_session_id"].(string),
	}
	redirect, err := idClient.IdentityLoginRedirect(ctx, redirectRequest)
	if err != nil {
		return nil, err
	}
	storage := storageClient.New(clientConfig)
	if federated {
		noteNameRealm, _ := e3dbClients.HashString("federated:" + login.Username + "@realm:" + login.RealmName)
		brokerLoginRequest := identityClient.BrokerLoginRequest{
			Action:     "login",
			NoteName:   noteNameRealm,
			PublicKey:  encryptionKeys.Public.Material,
			SigningKey: signingKeys.Public.Material,
			AuthHeaders: identityClient.AuthHeaders{
				TozIDToken: redirect.AccessToken,
			},
		}
		brokerResp, err := idClient.BrokerIdentityLogin(ctx, brokerLoginRequest, login.RealmName)
		if err != nil {
			return nil, err
		}
		note, err := storage.ReadNote(ctx, brokerResp.RecoveryNoteID.String(), map[string]string{storageClient.TozIDLoginTokenHeader: redirect.AccessToken})
		if err != nil {
			return nil, err
		}
		err = storage.DecryptNote(note)
		if err != nil {
			return nil, err
		}
		noteName, encryptionKeys, signingKeys, err = e3dbClients.DeriveIdentityCredentials(note.Data["username"], note.Data["broker_key"], realmInfo.Name, "")
		clientConfig.EncryptionKeys = encryptionKeys
		clientConfig.SigningKeys = signingKeys
		storage = storageClient.New(clientConfig)
	}
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
	config.TozIDRealmIDPAccessToken = &redirect.AccessToken
	config.Realm = realmInfo.Name
	config.Username = username
	sdk, err := sdkV3FromConfig(config)
	if err == nil {
		sdk.TozIDRealmIDPAccessToken = &redirect.AccessToken
	}
	return sdk, err

}

func (i *Identity) writeBrokeredLoginNotes(email string) ([]*storageClient.Note, error) {
	realmInfo, err := i.Realm.Info()
	if err != nil {
		return []*storageClient.Note{}, err
	}
	// Skip credential notes if there is no broker
	if realmInfo.BrokerIdentityToznyID == uuid.Nil {
		return []*storageClient.Note{}, nil
	}
	// Fetch the public broker info
	brokerInfo, err := i.ClientInfo(context.Background(), realmInfo.BrokerIdentityToznyID.String())
	if brokerInfo == nil {
		err = fmt.Errorf("Broker info not found for realm %q", realmInfo.Name)
	}
	if err != nil {
		return []*storageClient.Note{}, err
	}
	// If there is no broker, do not try to write broker notes
	// otherwise, get the broker's info
	// Email EACP
	emailEACP := storageClient.EmailEACP{
		EmailAddress:             email,
		Template:                 "claim_account",
		ProviderLink:             i.Realm.BrokerTargetURL,
		DefaultExpirationMinutes: i.Realm.EmailExpiryMinutes,
	}
	// format the name based on if first and last are provided
	name := ""
	if i.FirstName != "" {
		name = i.FirstName
	}
	if i.LastName != "" {
		if name != "" {
			name = name + " "
		}
		name = name + i.LastName
	}
	if name != "" {
		emailEACP.TemplateFields = map[string]string{"name": name}
	}
	eacps := &storageClient.EACP{
		TozIDEACP: &storageClient.TozIDEACP{
			RealmName: i.Realm.Name,
			Basic:     true,
		},
	}
	writtenNotes := []*storageClient.Note{}
	noteKey, keyNote, err := i.writeKeyNote("federated", brokerInfo.PublicKey.Curve25519, brokerInfo.SigningKey.Ed25519, eacps)
	if err != nil {
		return []*storageClient.Note{}, err
	}
	noteName, cryptoKeyPair, signingKeyPair, err := i.DeriveCredentails(noteKey, "")
	if err != nil {
		return []*storageClient.Note{}, err
	}
	keyNoteID, err := uuid.Parse(keyNote.NoteID)
	if err != nil {
		return []*storageClient.Note{}, err
	}
	brokeredEACP := &storageClient.EACP{
		LastAccessEACP: &storageClient.LastAccessEACP{
			LastReadNoteID: keyNoteID,
		},
	}
	credentialNote, err := i.writeCredentialNote(noteName, &cryptoKeyPair, &signingKeyPair, brokeredEACP)
	if err != nil {
		return []*storageClient.Note{}, err
	}
	writtenNotes = append(writtenNotes, keyNote, credentialNote)
	return writtenNotes, nil
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

// StoreConfigFile stores a ToznySDKV3 config file at the specified path, returning an error if any
func (c *ToznySDKV3) StoreConfigFile(path string) error {
	config := ToznySDKJSONConfig{
		ConfigFile: ConfigFile{
			Version:     2,
			APIBaseURL:  c.APIEndpoint,
			APIKeyID:    c.config.APIKey,
			APISecret:   c.config.APISecret,
			ClientID:    c.config.ClientID,
			ClientEmail: "",
			PublicKey:   c.config.EncryptionKeys.Public.Material,
			PrivateKey:  c.config.EncryptionKeys.Private.Material,
		},
		PublicSigningKey:  c.config.SigningKeys.Public.Material,
		PrivateSigningKey: c.config.SigningKeys.Private.Material,
		AccountUsername:   c.AccountUsername,
		AccountPassword:   c.AccountPassword,
		TozIDSessionIdentityData: TozIDSessionIdentityData{
			Username: c.CurrentIdentity.Username,
			Realm:    c.CurrentIdentity.Realm,
		},
	}
	return saveJson(path, config)
}

// Register attempts to create a valid TozStore account returning the root client config for the created account and error (if any).
func (c *ToznySDKV3) Register(ctx context.Context, name string, email string, password string, apiURL string) (RegisterAccountResponse, error) {
	if apiURL == "" {
		apiURL = DefaultStorageURL
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

func (c *ToznySDKV3) DeriveAccountCredentials(ctx context.Context, name string, email string, password string, apiURL string) (accountClient.CreateAccountRequest, error) {
	if apiURL == "" {
		apiURL = DefaultStorageURL
	}
	const (
		pwEncSalt  = "pwEncSalt"
		pwAuthSalt = "pwAuthSalt"
		pkEncSalt  = "pkEncSalt"
		pkAuthSalt = "pkAuthSalt"
	)
	var createRequest accountClient.CreateAccountRequest
	paperKeyRaw := make([]byte, 64)
	_, err := rand.Read(paperKeyRaw)
	if err != nil {
		return createRequest, fmt.Errorf("reading bytes for paper key: %v", err)
	}
	paperKey := base64.RawURLEncoding.EncodeToString(paperKeyRaw)

	salts := make(map[string][]byte, 4)
	for _, name := range []string{pwEncSalt, pwAuthSalt, pkEncSalt, pkAuthSalt} {
		salt := make([]byte, e3dbClients.SaltSize)
		_, err = rand.Read(salt)
		if err != nil {
			return createRequest, fmt.Errorf("reading bytes for salt %s: %v", name, err)
		}
		salts[name] = salt
	}

	// Derive keys
	pwSigningKey, _ := e3dbClients.DeriveSigningKey([]byte(password), salts[pwAuthSalt], e3dbClients.AccountDerivationRounds)
	pkSigningKey, _ := e3dbClients.DeriveSigningKey([]byte(paperKey), salts[pwAuthSalt], e3dbClients.AccountDerivationRounds)
	// Generate client keys
	encryptionKeypair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		return createRequest, fmt.Errorf("Failed generating encryption key pair %s", err)
	}
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		return createRequest, fmt.Errorf("Failed generating signing key pair %s", err)
	}
	createRequest = accountClient.CreateAccountRequest{
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

	return createRequest, nil
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

// GetRealmInfo Grabs the public realm information
func (c *ToznySDKV3) GetRealmInfo(ctx context.Context, realmName string, apiBaseURL string) (*identityClient.RealmInfo, error) {
	clientConfig := e3dbClients.ClientConfig{
		Host:      apiBaseURL,
		AuthNHost: apiBaseURL,
	}
	identityClientConfig := identityClient.New(clientConfig)
	c.APIEndpoint = apiBaseURL
	c.E3dbIdentityClient = &identityClientConfig
	realmInfo, err := c.RealmInfo(ctx, realmName)
	if err != nil {
		return nil, err
	}
	return realmInfo, nil
}

// ListAvailableIdPs lists all the Identity Providers configured for a given realm
func (c *ToznySDKV3) ListAvailableIdPs(ctx context.Context, realmName string, apiBaseURL string, appName string, scopes string) (string, error) {
	idPsAvailable := ""
	// Get Realm Info
	realmInfo, err := c.GetRealmInfo(ctx, realmName, apiBaseURL)
	if err != nil {
		return idPsAvailable, err
	}
	// If we have IdPs Configured, get a List
	if realmInfo.DoIdPsExist {
		dataBytes, err := e3dbClients.GenerateRandomBytes(32)
		pkceVerifier := e3dbClients.Base64Encode(dataBytes)
		request := identityClient.InitiateIdentityProviderLoginRequest{
			RealmName:     realmName,
			AppName:       appName,
			CodeChallenge: pkceVerifier,
			LoginStyle:    "api",
			RedirectURL:   "",
			Scope:         scopes,
		}
		idPInfo, err := c.InitiateIdentityProviderLogin(ctx, request)
		if err != nil {
			return idPsAvailable, err
		}
		providers := idPInfo.Context.(map[string]interface{})["idp_providers"].(map[string]interface{})["providers"].([]interface{})
		for _, provider := range providers {
			idPsAvailable += fmt.Sprintf("%+v \n", provider.(map[string]interface{})["displayName"])
		}
	}

	return idPsAvailable, nil

}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length+2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[2 : length+2]
}

// IdPLogin Login as an Identity Provider for a configured realm
func (c *ToznySDKV3) IdPLoginToClient(ctx context.Context, realmName string, apiBaseURL string, clientApplicationName string) error {
	// Get Realm Info
	realmInfo, err := c.GetRealmInfo(ctx, realmName, apiBaseURL)
	if err != nil {
		return err
	}
	// If we have IdPs Configured, get a List
	if realmInfo.DoIdPsExist {
		var tokenReturnedResponse TokenResponse
		// Set up OIDC state variable
		state := randomString(16)

		// Find next available port
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			panic(err)
		}
		availablePort := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
		_ = listener.Close()
		// Close listener

		// Set available port addresses
		fullPathAddress := fmt.Sprintf("http://localhost:%s", availablePort)
		hostURL := fmt.Sprintf("localhost:%s", availablePort)

		// Set up OIDC Base URL
		oidcBaseURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect", apiBaseURL, realmInfo.Domain)
		mux := http.NewServeMux()
		server := http.Server{Addr: hostURL, Handler: mux}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			exchangeCodeForToken(w, r, &tokenReturnedResponse, &server, oidcBaseURL, state, clientApplicationName)
		})

		// Create Auth URL
		authURL := fmt.Sprintf("%s/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid&state=%s", oidcBaseURL, clientApplicationName, fullPathAddress, state)

		// Open browser
		err = open.Start(authURL)
		if err != nil {
			log.Println(err)
			return err
		}
		// Begin Server
		err = server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Println(err)
			return err
		}
		c.TozIDRealmIDPAccessToken = &tokenReturnedResponse.AccessToken
		c.TozIDRealmIDPRefreshToken = &tokenReturnedResponse.RefreshToken
		c.TozIDRealmIDPIDToken = &tokenReturnedResponse.IDToken

	} else {
		fmt.Printf("No Providers Found for Realm %+v \n", realmName)
	}
	return nil
}

func exchangeCodeForToken(w http.ResponseWriter, r *http.Request, tokenReturn *TokenResponse, server *http.Server, oidcBaseURL string, requestedState string, clientApplicationName string) {
	defer func() {
		go server.Shutdown(r.Context())
	}()
	// Grab URL Query
	urlValues := r.URL.Query()
	requestState := urlValues.Get("state")
	if requestedState != requestState {
		errMessage := "Server State does not match requested state"
		http.Error(w, errMessage, http.StatusBadRequest)
		fmt.Println(errMessage)
		return
	}
	code := urlValues.Get("code")
	if len(code) == 0 {
		errMessage := "Code not found"
		http.Error(w, errMessage, http.StatusBadRequest)
		fmt.Println(errMessage)
		return
	}
	// Set URL Query parameter
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientApplicationName)
	data.Set("redirect_uri", "http://"+r.Host)

	// Set up token URL
	tokenEndpointURL := oidcBaseURL + "/token"
	resp, err := http.Post(tokenEndpointURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		fmt.Printf("Unable to successfully get token. Err: %+v\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		fmt.Printf("Unable to read body. Err: %+v\n", err)
	}
	// Unmarshal response into return object
	err = json.Unmarshal(body, &tokenReturn)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		fmt.Printf("Unable to populate token return object. Err: %+v\n", err)
	}
	w.WriteHeader(200)
	w.Write([]byte("<h1>You can now close this tab!</h1>"))

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

type Secret struct {
	SecretType    string
	SecretName    string
	SecretValue   string
	Description   string
	FileName      string
	SecretID      uuid.UUID
	RealmName     string
	OwnerUsername string
	NamespaceId   string
	Version       string
	Record        *pdsClient.Record
}

type CreateSecretOptions struct {
	SecretType       string
	SecretName       string
	SecretValue      string
	Description      string
	FileName         string
	RealmName        string
	OwnerPermissions []string // optional
}

// CreateSecret makes a secret of the specified type and share it with a group containing the writer
func (c *ToznySDKV3) CreateSecret(ctx context.Context, secretDetails CreateSecretOptions) (*Secret, error) {
	// once ToznySDKV3 is updated, this will be c.RealmName if secret.RealmName is empty
	var realmName string
	if secretDetails.RealmName != "" {
		realmName = secretDetails.RealmName
	} else if c.CurrentIdentity.Realm != "" {
		realmName = c.CurrentIdentity.Realm
	} else {
		return nil, fmt.Errorf("CreateSecret: No realm name was provided.")
	}
	err := ValidateSecret(secretDetails)
	if err != nil {
		return nil, err
	}
	ownerClientID, err := uuid.Parse(c.StorageClient.ClientID)
	if err != nil {
		return nil, fmt.Errorf("CreateSecret: Client ID must be a valid UUID, got %s", c.StorageClient.ClientID)
	}
	// Default permissions for the owner are share & read, but this will be replaced if the user specified permissions
	permissions := []string{storageClient.ShareContentGroupCapability, storageClient.ReadContentGroupCapability}
	if len(secretDetails.OwnerPermissions) > 0 {
		permissions = secretDetails.OwnerPermissions
	}
	namespaceOptions := NamespaceOptions{
		RealmName: realmName,
		Namespace: ownerClientID.String(),
		SharingMatrix: map[uuid.UUID][]string{
			ownerClientID: permissions,
		},
	}
	group, err := c.GetOrCreateNamespace(ctx, namespaceOptions)
	if err != nil {
		return nil, err
	}
	recordTypeOptions := GetRecordTypeOptions{
		SecretType: secretDetails.SecretType,
		SecretName: secretDetails.SecretName,
	}
	recordType := GetRecordType(recordTypeOptions)
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/int64(time.Millisecond))
	plain := map[string]string{
		"secretType":  secretDetails.SecretType,
		"secretName":  secretDetails.SecretName,
		"description": secretDetails.Description,
		"version":     timestamp,
	}
	var createdRecord *pdsClient.Record
	if secretDetails.SecretType == FileSecretType {
		writeFileRequest := WriteFileOptions{
			RecordType: recordType,
			Plain:      plain,
			FileName:   secretDetails.FileName,
		}
		createdRecord, err = c.WriteFile(ctx, writeFileRequest)
		if err != nil {
			return nil, err
		}
	} else {
		data := map[string]string{"secretValue": secretDetails.SecretValue}
		createdRecord, err = c.WriteRecord(ctx, data, recordType, plain)
		if err != nil {
			return nil, err
		}
	}
	createdSecret := c.MakeSecretResponse(createdRecord, group.GroupID.String(), "")
	err = c.ShareRecordWithGroup(ctx, recordType, group)
	if err != nil {
		return nil, err
	}
	return createdSecret, nil
}

type WriteFileOptions struct {
	RecordType string
	Plain      map[string]string
	FileName   string
}

// WriteFile encrypts the file with specified fileName and uploads it, creating a new record in E3DB
func (c *ToznySDKV3) WriteFile(ctx context.Context, options WriteFileOptions) (*pdsClient.Record, error) {
	keyRequest := pdsClient.GetOrCreateAccessKeyRequest{
		WriterID:   c.E3dbPDSClient.ClientID,
		UserID:     c.E3dbPDSClient.ClientID,
		ReaderID:   c.E3dbPDSClient.ClientID,
		RecordType: options.RecordType,
	}
	ak, err := c.E3dbPDSClient.GetOrCreateAccessKey(ctx, keyRequest)
	if err != nil {
		return nil, err
	}
	// Encrypt the file
	encryptionInfo, err := e3dbClients.EncryptFile(options.FileName, DefaultEncryptedFileName, ak)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := os.Remove(encryptionInfo.EncryptedFileName)
		if err != nil {
			fmt.Printf("WriteFile: Could not delete %s: %+v", encryptionInfo.EncryptedFileName, err)
		}
	}()
	options.Plain[SecretFilenameMetadataKey] = filepath.Base(options.FileName)
	sizeKB := encryptionInfo.Size / 1024
	if sizeKB >= 1 {
		options.Plain[SecretFileSizeMetadataKey] = fmt.Sprintf("%d", sizeKB)
	} else {
		options.Plain[SecretFileSizeMetadataKey] = "< 1"
	}
	// Write the whole file
	recordToWrite := storageClient.Record{
		Metadata: storageClient.Meta{
			Type:     options.RecordType,
			WriterID: uuid.MustParse(c.StorageClient.ClientID),
			UserID:   uuid.MustParse(c.StorageClient.ClientID),
			Plain:    options.Plain,
			FileMeta: &storageClient.FileMeta{
				Size:        int64(encryptionInfo.Size),
				Checksum:    encryptionInfo.Checksum,
				Compression: "raw",
			},
		},
	}
	pendingFileURL, err := c.StorageClient.WriteFile(ctx, recordToWrite)
	if err != nil {
		return nil, err
	}
	uploadRequest := file.UploadRequest{
		URL:               pendingFileURL.FileURL,
		EncryptedFileName: encryptionInfo.EncryptedFileName,
		Checksum:          encryptionInfo.Checksum,
		Size:              encryptionInfo.Size,
	}
	err = file.UploadFile(uploadRequest)
	if err != nil {
		return nil, err
	}
	// Register the file as being written
	response, err := c.StorageClient.FileCommit(ctx, pendingFileURL.PendingFileID)
	if err != nil {
		return nil, err
	}
	// get the file from the record
	fileRecord := &pdsClient.Record{
		Metadata: pdsClient.Meta{
			RecordID:     response.Metadata.RecordID.String(),
			WriterID:     response.Metadata.WriterID.String(),
			UserID:       response.Metadata.UserID.String(),
			Type:         response.Metadata.Type,
			Plain:        response.Metadata.Plain,
			Created:      response.Metadata.Created,
			LastModified: response.Metadata.LastModified,
			Version:      response.Metadata.Version.String(),
			FileMeta:     (*pdsClient.FileMeta)(response.Metadata.FileMeta),
		},
		Data:            response.Data,
		RecordSignature: response.RecordSignature,
	}
	return fileRecord, nil
}

type ReadFileOptions struct {
	RecordID         uuid.UUID
	DownloadFileName string
}

// ReadFile downloads and decrypts the file from the record
func (c *ToznySDKV3) ReadFile(ctx context.Context, options ReadFileOptions) error {
	fileResp, err := c.E3dbPDSClient.GetFileRecord(ctx, options.RecordID)
	if err != nil {
		return err
	}
	fileURL := fileResp.Metadata.FileMeta.FileURL
	downloadRequest := file.DownloadRequest{
		URL:               fileURL,
		EncryptedFileName: DefaultDownloadedFileName,
	}
	// download file from URL and store in EncryptedFileName
	downloadedPath, err := file.DownloadFile(downloadRequest)
	if err != nil {
		return fmt.Errorf("ReadFile: Err: %+v", err)
	}
	defer func() {
		err := os.Remove(downloadedPath)
		if err != nil {
			fmt.Printf("ReadFile: Could not delete %s: %+v", downloadedPath, err)
		}
	}()
	// get access key for the record type
	keyRequest := pdsClient.GetOrCreateAccessKeyRequest{
		WriterID:   fileResp.Metadata.WriterID,
		UserID:     fileResp.Metadata.UserID,
		ReaderID:   c.E3dbPDSClient.ClientID,
		RecordType: fileResp.Metadata.Type,
	}
	ak, err := c.E3dbPDSClient.GetOrCreateAccessKey(ctx, keyRequest)
	if err != nil {
		return err
	}
	// decrypt the file with the access key
	err = e3dbClients.DecryptFile(downloadedPath, options.DownloadFileName, ak)
	if err != nil {
		return err
	}
	return nil
}

// WriteRecord encrypts the data for the record and creates a new record in E3DB
func (c *ToznySDKV3) WriteRecord(ctx context.Context, data map[string]string, recordType string, plain map[string]string) (*pdsClient.Record, error) {
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: c.E3dbPDSClient.ClientID,
			UserID:   c.E3dbPDSClient.ClientID,
			Plain:    plain,
		},
	}
	encryptedRecord, err := c.E3dbPDSClient.EncryptRecord(ctx, recordToWrite)
	if err != nil {
		return nil, err
	}
	record, err := c.E3dbPDSClient.WriteRecord(ctx, encryptedRecord)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// UpdateRecord encrypts the data for the record and creates a new record in E3DB
func (c *ToznySDKV3) UpdateRecord(ctx context.Context, data map[string]string, recordType string, plain map[string]string, recordId string) (*pdsClient.Record, error) {
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: c.E3dbPDSClient.ClientID,
			UserID:   c.E3dbPDSClient.ClientID,
			Plain:    plain,
		},
	}
	encryptedRecord, err := c.E3dbPDSClient.EncryptRecord(ctx, recordToWrite)
	if err != nil {
		return nil, err
	}
	record, err := c.E3dbPDSClient.UpdateRecord(ctx, encryptedRecord, recordId)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (c *ToznySDKV3) ShareRecordWithGroup(ctx context.Context, recordType string, group *storageClient.Group) error {
	keyRequest := pdsClient.GetOrCreateAccessKeyRequest{
		WriterID:   c.E3dbPDSClient.ClientID,
		UserID:     c.E3dbPDSClient.ClientID,
		ReaderID:   c.E3dbPDSClient.ClientID,
		RecordType: recordType,
	}
	keyResp, err := c.E3dbPDSClient.GetOrCreateAccessKey(ctx, keyRequest)
	if err != nil {
		return err
	}
	encryptionKeys := e3dbClients.EncryptionKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: c.StorageClient.EncryptionKeys.Public.Material,
		},
		Private: c.StorageClient.EncryptionKeys.Private,
	}
	wrappedAK, err := e3dbClients.EncryptAccessKey(keyResp, encryptionKeys)
	if err != nil {
		return err
	}
	accessKeyRequest := storageClient.GroupAccessKeyRequest{
		GroupID:            group.GroupID,
		RecordType:         recordType,
		EncryptedAccessKey: wrappedAK,
		PublicKey:          group.PublicKey,
	}
	_, encryptedGroupAK, err := c.StorageClient.CreateGroupAccessKey(ctx, accessKeyRequest)
	if err != nil {
		return err
	}
	// share secret with group
	secretShareRequest := storageClient.ShareGroupRecordRequest{
		GroupID:            group.GroupID,
		RecordType:         recordType,
		EncryptedAccessKey: encryptedGroupAK,
		PublicKey:          group.PublicKey,
	}
	_, err = c.StorageClient.ShareRecordWithGroup(ctx, secretShareRequest)
	if err != nil {
		return err
	}
	return nil
}

type GetSecretGroupNameOptions struct {
	RealmName     string
	Namespace     string
	OwnerClientID uuid.UUID
	ShareeOwnerID uuid.UUID
	SecretName    string
	SecretType    string
}

// GetSecretGroupName makes and returns the groupName based on the input. It uses the Namespace if it's provided.
func GetSecretGroupName(options GetSecretGroupNameOptions) string {
	if options.Namespace != "" {
		return fmt.Sprintf("tozny.secret.%s.%s", options.RealmName, options.Namespace)
	} else {
		return fmt.Sprintf("tozny.secret.%s.%s.%s.%s.%s", options.RealmName, options.OwnerClientID, options.ShareeOwnerID, options.SecretName, options.SecretType)
	}
}

type GetRecordTypeOptions struct {
	SecretType string
	SecretName string
}

// GetRecordType returns the recordType which uses the provided secretType and secretName
func GetRecordType(options GetRecordTypeOptions) string {
	return fmt.Sprintf("tozny.secret.%s.%s.%s", SecretUUID, options.SecretType, options.SecretName)
}

type NamespaceOptions struct {
	Namespace string
	RealmName string
	// SharingMatrix must include all clients who need to be in the group
	// if the calling client is not included in the mapping, it will not have access to the group
	SharingMatrix map[uuid.UUID][]string
}

// GetOrCreateNamespace creates the group for the namespace if it doesn't exist and returns the Group
// SharingMatrix must include the calling client if they want to be able to interact with the group.
func (c *ToznySDKV3) GetOrCreateNamespace(ctx context.Context, options NamespaceOptions) (*storageClient.Group, error) {
	// If there is no one to share it with, don't create the group
	if len(options.SharingMatrix) < 1 {
		return nil, fmt.Errorf("Sharing matrix must include at least one mapping")
	}
	var group *storageClient.Group
	groupNamingOptions := GetSecretGroupNameOptions{
		RealmName: options.RealmName,
		Namespace: options.Namespace,
	}
	groupName := GetSecretGroupName(groupNamingOptions)
	listRequest := storageClient.ListGroupsRequest{
		ClientID:   uuid.MustParse(c.StorageClient.ClientID),
		GroupNames: []string{groupName},
	}
	responseList, err := c.StorageClient.ListGroups(ctx, listRequest)
	if err != nil {
		return nil, err
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, c.StorageClient.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	if len(responseList.Groups) < 1 {
		// create group
		groupRequest := storageClient.CreateGroupRequest{
			Name:              groupName,
			PublicKey:         encryptionKeyPair.Public.Material,
			EncryptedGroupKey: eak,
		}
		createGroupResponse, err := c.StorageClient.CreateGroup(ctx, groupRequest)
		if err != nil {
			return nil, err
		}
		group = createGroupResponse
		// make new members from the clientIDs
		memberRequest := []storageClient.GroupMember{}
		for clientID, permissions := range options.SharingMatrix {
			// get membership keys for the specific member
			membershipKeyRequest := storageClient.CreateMembershipKeyRequest{
				GroupAdminID:      c.ClientID,
				NewMemberID:       clientID.String(),
				EncryptedGroupKey: group.EncryptedGroupKey,
				ShareePublicKey:   c.StorageClient.EncryptionKeys.Public.Material,
			}
			membershipKeyResp, err := c.StorageClient.CreateGroupMembershipKey(ctx, membershipKeyRequest)
			if err != nil {
				return nil, err
			}
			memberRequest = append(memberRequest, storageClient.GroupMember{
				ClientID:        clientID,
				MembershipKey:   membershipKeyResp,
				CapabilityNames: permissions,
			})
		}
		// add group members
		addMemberRequest := storageClient.AddGroupMembersRequest{
			GroupID:      createGroupResponse.GroupID,
			GroupMembers: memberRequest,
		}
		_, err = c.StorageClient.AddGroupMembers(ctx, addMemberRequest)
		if err != nil {
			return nil, err
		}
	} else {
		// the group already exists
		group = &responseList.Groups[0]
	}
	return group, nil
}

// ValidateSecret checks that the secret contains valid input for each entry
func ValidateSecret(secret CreateSecretOptions) error {
	secret.SecretName = strings.TrimSpace(secret.SecretName)
	secret.SecretValue = strings.TrimSpace(secret.SecretValue)
	if secret.SecretType == "" {
		return errors.New("type cannot be empty")
	}
	if !SliceContainsString(SecretTypes, secret.SecretType) {
		return errors.New("invalid type")
	}
	if secret.SecretName == "" {
		return errors.New("name cannot be empty")
	}
	matched, err := regexp.MatchString(`^[a-zA-Z0-9-_]{1,50}$`, secret.SecretName)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("Secret name must contain 1-50 alphanumeric characters, -, or _")
	}
	if secret.SecretValue == "" && secret.SecretType == CredentialSecretType {
		return errors.New("Value cannot be empty")
	}
	if secret.SecretType == FileSecretType && strings.TrimSpace(secret.SecretName) == "" {
		return errors.New("File name cannot be empty")
	}
	if secret.SecretType == ClientSecretType {
		err := VerifyRawClientCredentials(secret.SecretValue)
		if err != nil {
			return err
		}
	}
	return nil
}

// SliceContainsString checks if str is present in an array of strings
func SliceContainsString(list []string, str string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

type ClientConfigRoot struct {
	APIBaseURL        string      `json:"api_url"`
	APIKeyID          string      `json:"api_key_id"`
	APISecret         string      `json:"api_secret"`
	ClientID          string      `json:"client_id"`
	ClientEmail       string      `json:"client_email"`
	PublicKey         string      `json:"public_key"`
	PrivateKey        string      `json:"private_key"`
	PublicSigningKey  string      `json:"public_signing_key"`
	PrivateSigningKey string      `json:"private_signing_key"`
	Version           interface{} `json:"version"`
}

// VerifyRawClientCredentials ensures that client credentials are in the proper form and contain all required keys
func VerifyRawClientCredentials(credential string) error {
	var clientConfig ClientConfigRoot
	err := json.Unmarshal([]byte(credential), &clientConfig)
	if err != nil {
		return err
	}
	// Check that all fields (except ClientEmail, optionally) are non-empty
	if clientConfig.Version == "" {
		return errors.New("Value for version must be non-empty")
	}
	if clientConfig.ClientID == "" {
		return errors.New("Value for client_id must be non-empty")
	}
	if clientConfig.PrivateSigningKey == "" {
		return errors.New("Value for private_signing_key must be non-empty")
	}
	if clientConfig.PublicSigningKey == "" {
		return errors.New("Value for public_signing_key must be non-empty")
	}
	if clientConfig.PrivateKey == "" {
		return errors.New("Value for private_key must be non-empty")
	}
	if clientConfig.PublicKey == "" {
		return errors.New("Value for public_key must be non-empty")
	}
	if clientConfig.APIBaseURL == "" {
		return errors.New("Value for api_url must be non-empty")
	}
	if clientConfig.APIKeyID == "" {
		return errors.New("Value for api_key_id must be non-empty")
	}
	if clientConfig.APISecret == "" {
		return errors.New("Value for api_secret must be non-empty")
	}
	_, versionInt := clientConfig.Version.(int)
	_, err = strconv.Atoi(fmt.Sprintf("%v", clientConfig.Version))
	if !versionInt && err != nil {
		return errors.New("Value for version must be a number")
	}
	// ClientID must be a UUID
	_, err = uuid.Parse(clientConfig.ClientID)
	if err != nil {
		return errors.New("Value for client_id should be in UUID format")
	}
	// Base64 encoded keys must have correct lengths
	if len(clientConfig.PrivateSigningKey) != e3dbClients.Base64EncodedPrivateSigningKeyLength {
		return fmt.Errorf("Invalid key length: private_signing_key Expected length: %d Received length: %d", e3dbClients.Base64EncodedPrivateSigningKeyLength, len(clientConfig.PrivateSigningKey))
	}
	if len(clientConfig.PublicSigningKey) != e3dbClients.Base64EncodedPublicSigningKeyLength {
		return fmt.Errorf("Invalid key length: public_signing_key Expected length: %d Received length: %d", e3dbClients.Base64EncodedPublicSigningKeyLength, len(clientConfig.PublicSigningKey))
	}
	if len(clientConfig.PrivateKey) != e3dbClients.Base64EncodedSymmetricKeyLength {
		return fmt.Errorf("Invalid key length: private_key Expected length: %d Received length: %d", e3dbClients.Base64EncodedSymmetricKeyLength, len(clientConfig.PrivateKey))
	}
	if len(clientConfig.PublicKey) != e3dbClients.Base64EncodedSymmetricKeyLength {
		return fmt.Errorf("Invalid key length: public_key Expected length: %d Received length: %d", e3dbClients.Base64EncodedSymmetricKeyLength, len(clientConfig.PublicKey))
	}
	return nil
}

type ListedSecrets struct {
	List      []Secret
	NextToken string
}

type ListSecretsOptions struct {
	RealmName string
	Limit     int
	NextToken int64
}

// ListSecrets returns a list of up to limit secrets that are shared with or owned by the identity
func (c *ToznySDKV3) ListSecrets(ctx context.Context, options ListSecretsOptions) (*ListedSecrets, []error, error) {
	sharedSecrets := &ListedSecrets{}
	listRequest := storageClient.ListGroupsRequest{
		ClientID:  uuid.MustParse(c.StorageClient.ClientID),
		NextToken: options.NextToken,
		Max:       options.Limit,
	}
	responseList, err := c.StorageClient.ListGroups(ctx, listRequest)
	if err != nil {
		return nil, nil, err
	}
	if len(responseList.Groups) < 1 {
		return sharedSecrets, nil, nil
	}
	var sharedSecretList []Secret
	// Collect errors that prevent listing specific secrets, but don't cause ListSecrets to terminate.
	var processingErrors []error
	sharedSecretIDs := make(map[string]bool)
	for _, group := range responseList.Groups {
		if !ValidToznySecretNamespace(group.Name) {
			continue
		}
		listRequest := storageClient.ListGroupRecordsRequest{
			GroupID: group.GroupID,
			Max:     options.Limit,
		}
		for {
			listGroupRecords, err := c.StorageClient.GetSharedWithGroup(ctx, listRequest)
			// if group can't be accessed, add a processing error, but don't fail
			if err != nil {
				processingErrors = append(processingErrors, fmt.Errorf("Could not access group: %s with error %+v", listRequest.GroupID, err))
				break
			}
			// Add records shared with this group to the list of secrets the user can view.
			for _, record := range listGroupRecords.ResultList {
				// If this record has already been found and added to the list, skip it
				_, exists := sharedSecretIDs[record.Metadata.RecordID]
				if exists {
					continue
				}
				var shared string
				if group.MemberCount > 1 {
					shared = "Yes"
				} else {
					shared = "No"
				}
				// find the username for secret writer if it's someone else
				writerID, err := uuid.Parse(record.Metadata.WriterID)
				if err != nil {
					processingErrors = append(processingErrors, fmt.Errorf("WriterID must be a UUID but is %s.", record.Metadata.WriterID))
					continue
				}
				searchParams := identityClient.SearchRealmIdentitiesRequest{
					RealmName:         options.RealmName,
					IdentityClientIDs: []uuid.UUID{writerID},
				}
				identities, err := c.E3dbIdentityClient.SearchRealmIdentities(ctx, searchParams)
				if err != nil {
					processingErrors = append(processingErrors, fmt.Errorf("Error finding identity with clientID %s. Error: %+v", writerID, err))
					continue
				}
				var username string
				if len(identities.SearchedIdentitiesInformation) > 0 {
					username = identities.SearchedIdentitiesInformation[0].RealmUsername
				}
				record.Metadata.Plain[SecretWriterUsernameMetadataKey] = username
				record.Metadata.Plain[SecretSharedMetadataKey] = shared
				// Decrypt the record & add to the list of secrets
				recordDecrypted, err := c.DecryptTextSecret(ctx, &record)
				// If secret can't be decrypted, add a processing error and skip it
				if err != nil {
					processingErrors = append(processingErrors, fmt.Errorf("Could not decrypt record with ID %s. Error: %+v", record.Metadata.RecordID, err))
					continue
				}
				secretDecrypted := c.MakeSecretResponse(recordDecrypted, group.GroupID.String(), username)
				sharedSecretList = append(sharedSecretList, *secretDecrypted)
				sharedSecretIDs[record.Metadata.RecordID] = true
			}

			if listGroupRecords.NextToken == "0" {
				break
			} else {
				listRequest.NextToken = listGroupRecords.NextToken
			}
		}
	}
	sharedSecrets.List = sharedSecretList
	sharedSecrets.NextToken = fmt.Sprintf("%d", responseList.NextToken)
	return sharedSecrets, processingErrors, nil
}

type ViewSecretOptions struct {
	SecretID   uuid.UUID
	MaxSecrets int
}

// ViewSecret returns the decrypted secret with secretID
func (c *ToznySDKV3) ViewSecret(ctx context.Context, options ViewSecretOptions) (*Secret, error) {
	listRequest := storageClient.ListGroupsRequest{
		ClientID: uuid.MustParse(c.StorageClient.ClientID),
	}
	groupList, err := c.StorageClient.ListGroups(ctx, listRequest)
	if err != nil {
		return nil, err
	}
	var secret *pdsClient.ListedRecord
	var groupID string
	var nextToken string
	for _, group := range groupList.Groups {
		listRequest := storageClient.ListGroupRecordsRequest{
			GroupID:   group.GroupID,
			NextToken: nextToken,
			Max:       options.MaxSecrets,
		}
		for {
			listGroupRecords, err := c.StorageClient.GetSharedWithGroup(ctx, listRequest)
			// if calling client doesn't actually have access to the group, skip it
			if err != nil {
				break
			}
			for _, record := range listGroupRecords.ResultList {
				if record.Metadata.RecordID == options.SecretID.String() {
					secret = &record
					groupID = group.GroupID.String()
					break
				}
			}
			if listGroupRecords.NextToken == "0" {
				break
			} else {
				listRequest.NextToken = listGroupRecords.NextToken
			}
		}
	}
	if secret == nil {
		return nil, fmt.Errorf("the requested secret could not be found: %s", options.SecretID)
	}
	recordDecrypted, err := c.DecryptTextSecret(ctx, secret)
	if err != nil {
		return nil, err
	}
	secretDecrypted := c.MakeSecretResponse(recordDecrypted, groupID, "")
	return secretDecrypted, nil
}

// ValidToznySecretNamespace returns true if the namespace is in the form of a tozny secret
func ValidToznySecretNamespace(groupName string) bool {
	groupNamesSplit := strings.Split(groupName, ".")
	if len(groupNamesSplit) < 2 || groupNamesSplit[0] != "tozny" || groupNamesSplit[1] != "secret" {
		return false
	}
	return true
}

// DecryptTextSecret decrypts a non-file secret using the group access key
func (c *ToznySDKV3) DecryptTextSecret(ctx context.Context, secret *pdsClient.ListedRecord) (*pdsClient.Record, error) {
	encryptedRecord := pdsClient.Record{
		Metadata:        secret.Metadata,
		Data:            secret.Data,
		RecordSignature: secret.RecordSignature,
	}
	if secret.AccessKey == nil {
		return nil, fmt.Errorf("requested Access Key is not found %+v", secret)
	}
	decryptedRecord, err := c.E3dbPDSClient.DecryptGroupRecordWithGroupEncryptedAccessKey(ctx, encryptedRecord, secret.AccessKey)
	if err != nil {
		return nil, err
	}
	return &decryptedRecord, nil
}

// MakeSecretResponse makes a secret containing from the record, group, and owner info
func (c *ToznySDKV3) MakeSecretResponse(secretRecord *pdsClient.Record, groupID string, ownerUsername string) *Secret {
	secret := &Secret{
		SecretName:    secretRecord.Metadata.Plain[SecretNameMetadataKey],
		SecretType:    secretRecord.Metadata.Plain[SecretTypeMetadataKey],
		SecretID:      uuid.MustParse(secretRecord.Metadata.RecordID),
		Description:   secretRecord.Metadata.Plain[SecretDescriptionMetadataKey],
		Version:       secretRecord.Metadata.Plain[SecretVersionMetadataKey],
		Record:        secretRecord,
		NamespaceId:   groupID,
		OwnerUsername: ownerUsername,
		RealmName:     c.CurrentIdentity.Realm,
	}
	if secret.SecretType == FileSecretType {
		secret.FileName = secretRecord.Metadata.Plain[SecretFilenameMetadataKey]
	} else {
		secret.SecretValue = secretRecord.Data[SecretValueDataKey]
	}
	return secret
}

type ShareSecretOptions struct {
	SecretName                   string
	SecretType                   string
	UsernameToAddWithPermissions map[string][]string
}

// ShareSecretWithUsername shares all versions of a specified secret with the user with UsernameToAdd
func (c *ToznySDKV3) ShareSecretWithUsername(ctx context.Context, options ShareSecretOptions) error {
	if len(options.UsernameToAddWithPermissions) != 1 {
		return fmt.Errorf("ShareSecretWithUsername: One username to add must be provided.")
	}
	var clientID uuid.UUID
	sharingMatrix := make(map[uuid.UUID][]string)
	ownerClientID, err := uuid.Parse(c.StorageClient.ClientID)
	if err != nil {
		return fmt.Errorf("ShareSecretWithUsername: Client ID must be a valid UUID, got %s", c.StorageClient.ClientID)
	}
	// Add default permissions for the calling client to the sharing matrix
	// If the calling client & permissions were included in UsernameToAddWithPermissions, these will be overwritten
	sharingMatrix[ownerClientID] = []string{storageClient.ShareContentGroupCapability, storageClient.ReadContentGroupCapability}
	for username, permissions := range options.UsernameToAddWithPermissions {
		// Find the clientID for the username to add
		searchParams := identityClient.SearchRealmIdentitiesRequest{
			RealmName:         c.CurrentIdentity.Realm,
			IdentityUsernames: []string{username},
		}
		identities, err := c.E3dbIdentityClient.SearchRealmIdentities(ctx, searchParams)
		if err != nil {
			return err
		}
		if len(identities.SearchedIdentitiesInformation) < 1 {
			return fmt.Errorf("ShareSecretWithUser: no identity found within realm %s with username %s", c.CurrentIdentity.Realm, username)
		}
		clientID = identities.SearchedIdentitiesInformation[0].ClientID
		// Add client to the sharing matrix
		sharingMatrix[clientID] = permissions
	}
	// If user tries to share secret with self, return without failure
	if clientID == ownerClientID {
		return nil
	}
	// Find or create the group for sharing with UsernameToAdd
	namespaceOptions := NamespaceOptions{
		RealmName:     c.CurrentIdentity.Realm,
		Namespace:     fmt.Sprintf("%s.%s.%s.%s", c.StorageClient.ClientID, clientID, options.SecretName, options.SecretType),
		SharingMatrix: sharingMatrix,
	}
	group, err := c.GetOrCreateNamespace(ctx, namespaceOptions)
	if err != nil {
		return err
	}
	// Share record type with group
	recordTypeOptions := GetRecordTypeOptions{
		SecretType: options.SecretType,
		SecretName: options.SecretName,
	}
	recordType := GetRecordType(recordTypeOptions)
	err = c.ShareRecordWithGroup(ctx, recordType, group)
	if err != nil {
		return err
	}
	return nil
}

type UnshareSecretOptions struct {
	SecretName       string
	SecretType       string
	UsernameToRevoke string
}

// UnshareSecretFromUsername revokes read access to secrets of provided name & type for this specific user
// Calling client must be the owner of the secret for this to succeed.
func (c *ToznySDKV3) UnshareSecretFromUsername(ctx context.Context, options UnshareSecretOptions) error {
	if options.UsernameToRevoke == "" {
		return fmt.Errorf("UnshareSecretFromUsername: Username to revoke must be provided")
	}
	// find the clientID for the username
	searchParams := identityClient.SearchRealmIdentitiesRequest{
		RealmName:         c.CurrentIdentity.Realm,
		IdentityUsernames: []string{options.UsernameToRevoke},
	}
	identities, err := c.E3dbIdentityClient.SearchRealmIdentities(ctx, searchParams)
	if err != nil {
		return err
	}
	// Username doesn't match an identity, so return an error
	if len(identities.SearchedIdentitiesInformation) < 1 {
		return fmt.Errorf("UnshareSecretFromUsername: no identity found within realm %s with username %s", c.CurrentIdentity.Realm, options.UsernameToRevoke)
	}
	// Find the sharing group
	revokeClientID := identities.SearchedIdentitiesInformation[0].ClientID
	ownerClientID, err := uuid.Parse(c.StorageClient.ClientID)
	if err != nil {
		return fmt.Errorf("UnshareSecretFromUsername: Client ID must be a valid UUID, got %s", c.StorageClient.ClientID)
	}
	// return an error if user tries to unshare secret from self
	if revokeClientID == ownerClientID {
		return fmt.Errorf("UnshareSecretFromUsername: Cannot unshare secret from self")
	}
	groupNamingOptions := GetSecretGroupNameOptions{
		RealmName:     c.CurrentIdentity.Realm,
		OwnerClientID: ownerClientID,
		ShareeOwnerID: revokeClientID,
		SecretName:    options.SecretName,
		SecretType:    options.SecretType,
	}
	groupName := GetSecretGroupName(groupNamingOptions)
	listRequest := storageClient.ListGroupsRequest{
		GroupNames: []string{groupName},
	}
	listGroupResponse, err := c.StorageClient.ListGroups(ctx, listRequest)
	if err != nil {
		return err
	}
	// Group does not exist, so secret isn't shared with this identity and unsharing doesn't need to happen.
	if len(listGroupResponse.Groups) < 1 {
		return fmt.Errorf("UnshareSecretFromUsername: sharing group does not exist")
	}
	// Unshare secret's record type from the group
	groupID := listGroupResponse.Groups[0].GroupID
	recordTypeOptions := GetRecordTypeOptions{
		SecretType: options.SecretType,
		SecretName: options.SecretName,
	}
	recordType := GetRecordType(recordTypeOptions)
	recordRemoveShareRequest := storageClient.RemoveRecordSharedWithGroupRequest{
		GroupID:    groupID,
		RecordType: recordType,
	}
	err = c.StorageClient.RemoveSharedRecordWithGroup(ctx, recordRemoveShareRequest)
	if err != nil {
		return err
	}
	return nil
}

type UnshareBeforeDeleteOptions struct {
	SecretID       uuid.UUID
	CallerClientID uuid.UUID
	Type           string
}

// UnshareSecretBeforeDelete unshares the secret with SecretID from every group it's shared with
// and deletes the group if it contains no other secrets.
func (c *ToznySDKV3) UnshareSecretBeforeDelete(ctx context.Context, options UnshareBeforeDeleteOptions) ([]error, error) {
	listRequest := storageClient.ListGroupsRequest{
		ClientID: options.CallerClientID,
	}
	listGroupResponse, err := c.StorageClient.ListGroups(ctx, listRequest)
	if err != nil {
		return nil, err
	}
	secretID := options.SecretID
	var processingErrors []error
	// Check each group the calling client belongs to for the secret
	for _, group := range listGroupResponse.Groups {
		if !ValidToznySecretNamespace(group.Name) {
			continue
		}
		listRequest := storageClient.ListGroupRecordsRequest{
			GroupID:   group.GroupID,
			WriterIDs: []string{options.CallerClientID.String()},
		}
		// Get all the records shared with the group
		listGroupRecords, err := c.StorageClient.GetSharedWithGroup(ctx, listRequest)
		if err != nil {
			msg := fmt.Errorf("UnshareSecretBeforeDelete: could not access group %s. Err: %+v", group.GroupID, err)
			processingErrors = append(processingErrors, msg)
			continue
		}
		numberRecordsInGroup := len(listGroupRecords.ResultList)
		// unshare the record from the group
		recordRemoveShareRequest := storageClient.RemoveRecordSharedWithGroupRequest{
			GroupID:    group.GroupID,
			RecordType: options.Type,
		}
		err = c.StorageClient.RemoveSharedRecordWithGroup(ctx, recordRemoveShareRequest)
		if err != nil {
			msg := fmt.Errorf("UnshareSecretBeforeDelete: failed to remove secret %s from group %s. Err: %+v", secretID, group.GroupID, err)
			processingErrors = append(processingErrors, msg)
			continue
		}
		// If the group only contains the secret, delete the group
		if numberRecordsInGroup == 1 && listGroupRecords.ResultList[0].Metadata.RecordID == secretID.String() {
			deleteGroupOptions := storageClient.DeleteGroupRequest{
				GroupID:   group.GroupID,
				AccountID: group.AccountID,
				ClientID:  options.CallerClientID,
			}
			err = c.StorageClient.DeleteGroup(ctx, deleteGroupOptions)
			if err != nil {
				msg := fmt.Errorf("UnshareSecretBeforeDelete: failed to delete empty group %s. Err: %+v", group.GroupID, err)
				processingErrors = append(processingErrors, msg)
			}
		}
	}
	return processingErrors, nil
}

type DeleteSecretOptions struct {
	WriterID   string
	SecretID   uuid.UUID
	RecordType string
}

// DeleteSecret deletes the secret with SecretID. It requires that the calling client is the secret owner.
func (c *ToznySDKV3) DeleteSecret(ctx context.Context, options DeleteSecretOptions) ([]error, error) {
	callerClientID, err := uuid.Parse(c.StorageClient.ClientID)
	if err != nil {
		return nil, fmt.Errorf("DeleteSecret: Client ID must be a valid UUID, got %s", c.StorageClient.ClientID)
	}
	// Check that the person trying to delete the secret is the owner. If not, return an error
	if callerClientID.String() != options.WriterID {
		return nil, fmt.Errorf("DeleteSecret: Calling client %s does not own secret %s", options.WriterID, options.SecretID)
	}
	sharedListOptions := UnshareBeforeDeleteOptions{
		SecretID:       options.SecretID,
		CallerClientID: callerClientID,
		Type:           options.RecordType,
	}
	// Unshare the secret from all groups it's shared with
	processingErrors, err := c.UnshareSecretBeforeDelete(ctx, sharedListOptions)
	if err != nil {
		return processingErrors, err
	}
	deleteRecordOptions := pdsClient.DeleteRecordRequest{
		RecordID: options.SecretID.String(),
	}
	// Delete the secret
	err = c.E3dbPDSClient.DeleteRecord(ctx, deleteRecordOptions)
	if err != nil {
		return processingErrors, err
	}
	return processingErrors, nil
}

// ExecuteSearch takes the given request and returns all records that match that request. Record data for non-files is decrypted. Files must be downloaded separately
func (c *ToznySDKV3) ExecuteSearch(executorRequest *searchExecutorClient.ExecutorQueryRequest) (*[]pdsClient.ListedRecord, error) {
	client := searchExecutorClient.New(c.config)
	results, _, err := searchExecutorClient.TimePaginateSearch(client, *executorRequest)
	if err != nil {
		return nil, err
	}
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.E3dbPDSClient.EncryptionKeys.Private.Material)
	if err != nil {
		return nil, err
	}
	for index, record := range *results {
		// TODO: fix root of below problem or support partial success
		// If a record is indexed that the user does not actually have access to, the record won't have
		// an access key which causes the call to `getAKForListedRecord` to panic. Any error in this loop
		// results in a total failure of search. I needed this partial success implemented quick & dirty
		// so I just skip attempting to decrypt. It should be handled more properly by allowing this func
		// to support partial success.
		if record.AccessKey == nil {
			fmt.Printf("failure: NO ACCESS KEY! skipping record id: %+s\n", record.Metadata.RecordID)
			continue
		}
		accessKey, err := c.getAKForListedRecord(rawEncryptionKey, record)
		if err != nil {
			return nil, err
		}
		data, err := e3dbClients.DecryptData(record.Data, accessKey)
		if err != nil {
			return nil, err
		}
		(*results)[index].Data = data
	}
	return results, nil
}

func (c *ToznySDKV3) getAKForListedRecord(symmetricKey e3dbClients.SymmetricKey, record pdsClient.ListedRecord) (e3dbClients.SymmetricKey, error) {
	if c.akCache == nil {
		c.akCache = make(map[akCacheKey]e3dbClients.SymmetricKey)
	}
	key, exists := c.akCache[akCacheKey{record.Metadata.WriterID, record.Metadata.UserID, record.Metadata.Type}]
	if exists {
		return key, nil
	}
	accessKey, err := e3dbClients.DecryptEAK(record.AccessKey.EAK, record.AccessKey.AuthorizerPublicKey.Curve25519, symmetricKey)
	if err != nil {
		return nil, err
	}
	c.akCache[akCacheKey{record.Metadata.WriterID, record.Metadata.UserID, record.Metadata.Type}] = accessKey
	return accessKey, nil
}
