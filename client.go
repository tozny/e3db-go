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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/oauth2/clientcredentials"
)

const defaultStorageURL = "http://localhost:8000/v1"
const defaultAuthURL = "http://localhost:7000/v1"

type AKCacheKey struct {
	WriterID string
	UserID   string
	Type     string
}

type Client struct {
	ClientID   string
	ApiKey     string
	ApiSecret  string
	PublicKey  []byte
	PrivateKey []byte
	ApiURL     string
	AuthURL    string
	Logging    bool

	httpClient *http.Client
	akCache    map[AKCacheKey][]byte
}

type ClientKey struct {
	Curve25519 string `json:"curve25519"`
}

type ClientInfo struct {
	ClientID  string    `json:"client_id"`
	PublicKey ClientKey `json:"public_key"`
	Validated bool      `json:"validated"`
}

type Meta struct {
	RecordID     string            `json:"record_id"`
	WriterID     string            `json:"writer_id"`
	UserID       string            `json:"user_id"`
	Type         string            `json:"type"`
	Plain        map[string]string `json:"plain"`
	Created      time.Time         `json:"created"`
	LastModified time.Time         `json:"last_modified"`
}

type Record struct {
	Meta Meta              `json:"meta"`
	Data map[string]string `json:"data"`
}

type configFile struct {
	ApiURL    string `json:"api_url"`
	AuthURL   string `json:"auth_url"`
	ApiKeyID  string `json:"api_key_id"`
	ApiSecret string `json:"api_secret"`
	ClientID  string `json:"client_id"`
}

type keyFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func loadJSON(path string, obj interface{}) error {
	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, obj)
	if err != nil {
		return err
	}

	return nil
}

func createClient(configPath, keyPath string) (*Client, error) {
	var config configFile
	var key keyFile

	if err := loadJSON(configPath, &config); err != nil {
		return nil, err
	}

	if err := loadJSON(keyPath, &key); err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := base64.RawURLEncoding.DecodeString(key.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &Client{
		ClientID:   config.ClientID,
		ApiURL:     config.ApiURL,
		AuthURL:    config.AuthURL,
		ApiKey:     config.ApiKeyID,
		ApiSecret:  config.ApiSecret,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func GetDefaultClient() (*Client, error) {
	client, err := createClient("~/.tozny/e3db.json", "~/.tozny/e3db_key.json")
	return client, err
}

func GetClient(profile string) (*Client, error) {
	client, err := createClient(
		fmt.Sprintf("~/.tozny/%s/e3db.json", profile),
		fmt.Sprintf("~/.tozny/%s/e3db_key.json", profile))
	return client, err
}

func (c *Client) apiURL() string {
	if c.ApiURL == "" {
		return defaultStorageURL
	}

	return c.ApiURL
}

func (c *Client) authURL() string {
	if c.AuthURL == "" {
		return defaultAuthURL
	}

	return c.AuthURL
}

func (c *Client) logRequest(req *http.Request) {
	reqDump, _ := httputil.DumpRequestOut(req, true)
	scanner := bufio.NewScanner(bytes.NewReader(reqDump))
	for scanner.Scan() {
		fmt.Printf("> %s\n", scanner.Text())
	}
}

func (c *Client) logResponse(resp *http.Response) {
	respDump, _ := httputil.DumpResponse(resp, true)
	scanner := bufio.NewScanner(bytes.NewReader(respDump))
	for scanner.Scan() {
		fmt.Printf("< %s\n", scanner.Text())
	}
}

func (c *Client) rawCall(ctx context.Context, req *http.Request, jsonResult interface{}) (*http.Response, error) {
	if c.httpClient == nil {
		config := clientcredentials.Config{
			ClientID:     c.ApiKey,
			ClientSecret: c.ApiSecret,
			TokenURL:     c.authURL() + "/token",
		}
		c.httpClient = config.Client(ctx)
	}

	if c.Logging {
		c.logRequest(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if c.Logging {
		c.logResponse(resp)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, errors.New(fmt.Sprintf("Invalid status code: %d", resp.StatusCode))
	}

	if jsonResult != nil {
		if err := json.NewDecoder(resp.Body).Decode(jsonResult); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (c *Client) GetClientKey(ctx context.Context, clientID string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/clients/%s", c.apiURL(), clientID), nil)
	if err != nil {
		return nil, err
	}

	var info ClientInfo
	resp, err := c.rawCall(ctx, req, &info)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	key, err := base64.RawURLEncoding.DecodeString(info.PublicKey.Curve25519)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (c *Client) GetRaw(ctx context.Context, recordID string) (*Record, error) {
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

func (c *Client) Get(ctx context.Context, recordID string) (*Record, error) {
	record, err := c.GetRaw(ctx, recordID)
	if err != nil {
		return nil, err
	}

	if err := c.decryptRecord(ctx, record); err != nil {
		return nil, err
	}

	return record, nil
}
