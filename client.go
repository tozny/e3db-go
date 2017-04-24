//
// client.go --- Golang e3db client.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

const defaultStorageURL = "http://localhost:8000/v1"
const defaultAuthURL = "http://localhost:7000/v1"

type akCacheKey struct {
	WriterID string
	UserID   string
	Type     string
}

// ClientOpts contains options for configuring an E3DB client.
type ClientOpts struct {
	ClientID    string
	APIKeyID    string
	APISecret   string
	PublicKey   publicKey
	PrivateKey  privateKey
	APIBaseURL  string
	AuthBaseURL string
	Logging     bool
}

// Client is an authenticated connection to the E3DB service, providing
// access to end-to-end encrypted data stored in the database.
type Client struct {
	clientID    string
	apiKeyID    string
	apiSecret   string
	publicKey   publicKey
	privateKey  privateKey
	apiBaseURL  string
	authBaseURL string
	logging     bool
	httpClient  *http.Client
	akCache     map[akCacheKey]secretKey
}

type clientKey struct {
	Curve25519 string `json:"curve25519"`
}

type clientInfo struct {
	ClientID  string    `json:"client_id"`
	PublicKey clientKey `json:"public_key"`
	Validated bool      `json:"validated"`
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
	opts, err := loadConfig("~/.tozny/e3db.json", "~/.tozny/e3db_key.json")
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
		clientID:    opts.ClientID,
		apiBaseURL:  opts.APIBaseURL,
		authBaseURL: opts.AuthBaseURL,
		apiKeyID:    opts.APIKeyID,
		apiSecret:   opts.APISecret,
		publicKey:   opts.PublicKey,
		privateKey:  opts.PrivateKey,
		logging:     opts.Logging,
	}, nil
}

func (c *Client) apiURL() string {
	if c.apiBaseURL == "" {
		return defaultStorageURL
	}

	return c.apiBaseURL
}

func (c *Client) authURL() string {
	if c.authBaseURL == "" {
		return defaultAuthURL
	}

	return c.authBaseURL
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

func (c *Client) rawCall(ctx context.Context, req *http.Request, jsonResult interface{}) (*http.Response, error) {
	if c.httpClient == nil {
		config := clientcredentials.Config{
			ClientID:     c.apiKeyID,
			ClientSecret: c.apiSecret,
			TokenURL:     c.authURL() + "/token",
		}
		c.httpClient = config.Client(ctx)
	}

	if c.logging {
		logRequest(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if c.logging {
		logResponse(resp)
	}

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		return nil, fmt.Errorf("e3db: server http error %d", resp.StatusCode)
	}

	if jsonResult != nil {
		if err := json.NewDecoder(resp.Body).Decode(jsonResult); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// getClientKey queries the E3DB server for a client's public key
// given its client UUID. (This was exported in the Java SDK but
// I'm not sure why since it's rather low level.)
func (c *Client) getClientKey(ctx context.Context, clientID string) (publicKey, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/clients/%s", c.apiURL(), clientID), nil)
	if err != nil {
		return nil, err
	}

	var info clientInfo
	resp, err := c.rawCall(ctx, req, &info)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	key, err := base64Decode(info.PublicKey.Curve25519)
	if err != nil {
		return nil, err
	}

	return makePublicKey(key), nil
}

// ReadRaw reads a record given a record ID and returns the record without
// decrypting data fields.
func (c *Client) ReadRaw(ctx context.Context, recordID string) (*Record, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/records/%s", c.apiURL(), recordID), nil)
	if err != nil {
		return nil, err
	}

	var record Record
	resp, err := c.rawCall(ctx, req, &record)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return &record, nil
}

// Read reads a record given a record ID, decrypts it, and returns the result.
func (c *Client) Read(ctx context.Context, recordID string) (*Record, error) {
	record, err := c.ReadRaw(ctx, recordID)
	if err != nil {
		return nil, err
	}

	if err := c.decryptRecord(ctx, record); err != nil {
		return nil, err
	}

	return record, nil
}

// NewRecord creates a new record of the given content type.
func (c *Client) NewRecord(recordType string) *Record {
	return &Record{
		Meta: Meta{
			Type:     recordType,
			WriterID: c.clientID,
			UserID:   c.clientID, // for now
		},
		Data: make(map[string]string),
	}
}

// Write writes a new encrypted record to the database, returning the new record's
// unique ID.
func (c *Client) Write(ctx context.Context, record *Record) (string, error) {
	encryptedRecord := *record
	if err := c.encryptRecord(ctx, &encryptedRecord); err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(&encryptedRecord)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/records", c.apiURL()), buf)
	if err != nil {
		return "", err
	}

	resp, err := c.rawCall(ctx, req, &encryptedRecord)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	return encryptedRecord.Meta.RecordID, nil
}
