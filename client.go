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

	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/identityClient"
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
func RegisterClient(registrationToken string, clientName string, publicKey string, privateKey string, backup bool, apiURL string) (*ClientDetails, error) {
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
		return nil, err
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)

	var details *ClientDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		closeResp(resp)
		return nil, err
	}

	backupClient := resp.Header.Get("X-Backup-Client")

	if backup {
		if privateKey == "" {
			return nil, errors.New("Cannot back up client credentials without a private key!")
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
			return nil, err
		}

		client.Backup(context.Background(), backupClient, registrationToken)
	}

	return details, nil
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
	// Account public authentication material for creating and deriving account credentials
	AccountUsername string
	// Account private authentication material for creating and deriving account credentials
	AccountPassword string
	// Network location of the Tozny services to communicate with.
	APIEndpoint string
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
	return &ToznySDKV3{
		E3dbAccountClient:  &accountServiceClient,
		E3dbIdentityClient: &identityClient,
		AccountUsername:    config.AccountUsername,
		AccountPassword:    config.AccountPassword,
		APIEndpoint:        config.APIEndpoint,
	}, nil
}

// GetSDKV3 creates a V3 Tozny SDK based off the JSON contents
// of the file at the specified path, returning config and error (if any).
func GetSDKV3(configJSONFilePath string) (*ToznySDKV3, error) {
	config, err := LoadConfigFile(configJSONFilePath)
	if err != nil {
		return nil, err
	}
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

// CreateResponse wraps the value return from the account creation method
type RegisterAccountResponse struct {
	PaperKey string
	Account  Account
}

// Account wraps the data needed to make TozStore account calls
type Account struct {
	AccountID string
	Token     string
	Config    ClientConfig
	Client    *accountClient.E3dbAccountClient
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
func (c *ToznySDKV3) Register(ctx context.Context, name string, email string, password string) (RegisterAccountResponse, error) {
	const (
		pwEncSalt  = "pwEncSalt"
		pwAuthSalt = "pwAuthSalt"
		pkEncSalt  = "pkEncSalt"
		pkAuthSalt = "pkAuthSalt"
	)
	// Boot client
	bootClientConfig := e3dbClients.ClientConfig{
		Host:      c.APIEndpoint,
		AuthNHost: c.APIEndpoint,
	}
	bootClient := accountClient.New(bootClientConfig)
	var createResponse RegisterAccountResponse
	var accountClientConfig = e3dbClients.ClientConfig{
		Host:      c.APIEndpoint,
		AuthNHost: c.APIEndpoint,
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
		APIURL:            c.APIEndpoint,
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
	err = e3dbClients.MakeProxiedUserCall(context.Background(), accountToken, request, nil)
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
