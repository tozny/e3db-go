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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/oauth2/clientcredentials"
)

const defaultStorageURL = "https://api.dev.e3db.tozny.com/v1"
const defaultAuthURL = "https://api.dev.tot.tozny.com/v1"
const defaultEventsURL = "wss://api.dev.e3db.tozny.com/v1/events"

type akCacheKey struct {
	WriterID string
	UserID   string
	Type     string
}

// ClientOpts contains options for configuring an E3DB client.
type ClientOpts struct {
	ClientID      string
	APIKeyID      string
	APISecret     string
	PublicKey     publicKey
	PrivateKey    privateKey
	APIBaseURL    string
	AuthBaseURL   string
	EventsBaseURL string
	Logging       bool
}

// Client is an authenticated connection to the E3DB service, providing
// access to end-to-end encrypted data stored in the database.
type Client struct {
	ClientID      string
	APIKeyID      string
	APISecret     string
	PublicKey     publicKey
	PrivateKey    privateKey
	APIBaseURL    string
	AuthBaseURL   string
	EventsBaseURL string
	Logging       bool

	httpClient *http.Client
	akCache    map[akCacheKey]secretKey
}

type clientKey struct {
	Curve25519 string `json:"curve25519"`
}

// ClientInfo contains information sent by the E3DB service
// about a client.
type ClientInfo struct {
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

// Channel contains information defining the channel to which a client
// wishes to connect.
type Channel struct {
	Application string `json:"application"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
}

// Subscription wraps a subscribe/unsubscribe request for the event system
type Subscription struct {
	Action  string  `json:"action"`
	Channel Channel `json:"subscription"`
}

// Event is an object representing the JSON blob dispatched from e3db in
// response to serverside events.
type Event struct {
	Time        time.Time         `json:"time"`
	Application string            `json:"application"`
	Type        string            `json:"type"`
	Action      string            `json:"action"`
	Subject     string            `json:"subject"`
	Producer    string            `json:"producer"`
	Context     map[string]string `json:"context"`
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
		ClientID:      opts.ClientID,
		APIBaseURL:    opts.APIBaseURL,
		AuthBaseURL:   opts.AuthBaseURL,
		EventsBaseURL: opts.EventsBaseURL,
		APIKeyID:      opts.APIKeyID,
		APISecret:     opts.APISecret,
		PublicKey:     opts.PublicKey,
		PrivateKey:    opts.PrivateKey,
		Logging:       opts.Logging,
	}, nil
}

func (c *Client) apiURL() string {
	if c.APIBaseURL == "" {
		return defaultStorageURL
	}

	return c.APIBaseURL
}

func (c *Client) authURL() string {
	if c.AuthBaseURL == "" {
		return defaultAuthURL
	}

	return c.AuthBaseURL
}

func (c *Client) eventsURL() string {
	if c.EventsBaseURL == "" {
		return defaultEventsURL
	}

	return c.EventsBaseURL
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
			ClientID:     c.APIKeyID,
			ClientSecret: c.APISecret,
			TokenURL:     c.authURL() + "/token",
		}
		c.httpClient = config.Client(ctx)
	}

	if c.Logging {
		logRequest(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if c.Logging {
		logResponse(resp)
	}

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		closeResp(resp)
		return nil, &httpError{
			StatusCode: resp.StatusCode,
			URL:        req.URL.String(),
			message:    fmt.Sprintf("e3db: server http error %d", resp.StatusCode),
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
// information given its client UUID or email (if enabled).
func (c *Client) GetClientInfo(ctx context.Context, clientID string) (*ClientInfo, error) {
	var u, method string

	if strings.Contains(clientID, "@") {
		u = fmt.Sprintf("%s/clients/find?email=%s", c.apiURL(), url.QueryEscape(clientID))
		method = "POST"
	} else {
		u = fmt.Sprintf("%s/clients/%s", c.apiURL(), url.QueryEscape(clientID))
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
func (c *Client) getClientKey(ctx context.Context, clientID string) (publicKey, error) {
	info, err := c.GetClientInfo(ctx, clientID)
	if err != nil {
		return nil, err
	}

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

	defer closeResp(resp)
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
			WriterID: c.ClientID,
			UserID:   c.ClientID, // for now
		},
		Data: make(map[string]string),
	}
}

// Write writes a new encrypted record to the database, returning the new record's
// unique ID.
func (c *Client) Write(ctx context.Context, record *Record) (string, error) {
	encryptedRecord, err := c.encryptRecord(ctx, record)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(encryptedRecord)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/records", c.apiURL()), buf)
	if err != nil {
		return "", err
	}

	resp, err := c.rawCall(ctx, req, encryptedRecord)
	if err != nil {
		return "", err
	}

	defer closeResp(resp)
	return encryptedRecord.Meta.RecordID, nil
}

// Delete deletes a record given a record ID.
func (c *Client) Delete(ctx context.Context, recordID string) error {
	u := fmt.Sprintf("%s/records/%s", c.apiURL(), url.QueryEscape(recordID))
	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return nil
	}

	defer closeResp(resp)
	return nil
}

const allowReadPolicy = `{"allow": [{"read": {}}]}`
const denyReadPolicy = `{"deny": [{"read": {}}]}`

// Share grants another e3db client permission to read records of the
// specified record type.
func (c *Client) Share(ctx context.Context, recordType string, reader string) error {
	info, err := c.GetClientInfo(ctx, reader)
	if err != nil {
		return err
	}

	ak, err := c.getAccessKey(ctx, c.ClientID, c.ClientID, c.ClientID, recordType)
	if err != nil {
		return err
	}

	if ak == nil {
		return errors.New("no applicable records exist to share")
	}

	// FIXME: This makes an additional unnecessary request to obtain the
	// reader's public key again. We probably should maintain a cache of
	// these as well, but I do start to worry about invalidation...
	err = c.putAccessKey(ctx, c.ClientID, c.ClientID, info.ClientID, recordType, ak)
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/policy/%s/%s/%s/%s", c.apiURL(), c.ClientID, c.ClientID, info.ClientID, recordType)
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
func (c *Client) Unshare(ctx context.Context, recordType string, reader string) error {
	info, err := c.GetClientInfo(ctx, reader)
	if err != nil {
		return err
	}

	// TODO: Need to delete their access key!

	u := fmt.Sprintf("%s/policy/%s/%s/%s/%s", c.apiURL(), c.ClientID, c.ClientID, info.ClientID, recordType)
	req, err := http.NewRequest("PUT", u, strings.NewReader(denyReadPolicy))
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

// Subscribe to a given event channel published by the e3db system
func (c *Client) Subscribe(ctx context.Context, subscription Subscription, callback func(Event)) error {
	// Get an auth token
	config := clientcredentials.Config{
		ClientID:     c.APIKeyID,
		ClientSecret: c.APISecret,
		TokenURL:     c.authURL() + "/token",
	}

	token, err := config.Token(ctx)
	if err != nil {
		return err
	}

	authHeader := make(http.Header)
	authHeader.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	// Set up interrupt flags
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := fmt.Sprintf("%s/subscribe", c.eventsURL())
	conn, _, err := websocket.DefaultDialer.Dial(u, authHeader)
	if err != nil {
		return err
	}

	defer conn.Close()

	done := make(chan struct{})

	go func() {
		defer conn.Close()
		defer close(done)

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}

			event := Event{}
			json.Unmarshal(message, &event)

			// Do something with the message
			callback(event)
		}
	}()

	// Send the subscription after a short delay (to allow for the connection to open)
	go func() {
		select {
		case <-time.After(1 * time.Second):
			buf, _ := json.Marshal(subscription)
			writeErr := conn.WriteMessage(websocket.TextMessage, buf)
			if writeErr != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-interrupt:
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			conn.Close()
			return nil
		}
	}
}
