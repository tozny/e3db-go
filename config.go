//
// config.go --- Configuration and profile management.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	homedir "github.com/mitchellh/go-homedir"
)

type configFile struct {
	APIBaseURL  string `json:"api_url"`
	AuthBaseURL string `json:"auth_url"`
	APIKeyID    string `json:"api_key_id"`
	APISecret   string `json:"api_secret"`
	ClientID    string `json:"client_id"`
}

type keyFile struct {
	Version    int    `json:"version"`
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

func loadConfig(configPath, keyPath string) (*ClientOpts, error) {
	var config configFile
	var key keyFile

	if err := loadJSON(configPath, &config); err != nil {
		return nil, err
	}

	if err := loadJSON(keyPath, &key); err != nil {
		return nil, err
	}

	if key.Version != 1 {
		return nil, fmt.Errorf("e3db.loadConfig: unsupported key file version: %d", key.Version)
	}

	pubKey, err := decodePublicKey(key.PublicKey)
	if err != nil {
		return nil, err
	}

	privKey, err := decodePrivateKey(key.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &ClientOpts{
		ClientID:    config.ClientID,
		APIBaseURL:  config.APIBaseURL,
		AuthBaseURL: config.AuthBaseURL,
		APIKeyID:    config.APIKeyID,
		APISecret:   config.APISecret,
		PublicKey:   pubKey,
		PrivateKey:  privKey,
		Logging:     false,
	}, nil
}

func saveConfig(configPath, keyPath string, opts *ClientOpts) error {
	configFullPath, err := homedir.Expand(configPath)
	if err != nil {
		return err
	}

	keyFullPath, err := homedir.Expand(keyPath)
	if err != nil {
		return err
	}

	err = os.MkdirAll(path.Dir(keyFullPath), 0700)
	if err != nil {
		return err
	}

	configFd, err := os.OpenFile(configFullPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer configFd.Close()

	keyFd, err := os.OpenFile(keyFullPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer keyFd.Close()

	configObj := configFile{
		ClientID:    opts.ClientID,
		APIBaseURL:  opts.APIBaseURL,
		AuthBaseURL: opts.AuthBaseURL,
		APIKeyID:    opts.APIKeyID,
		APISecret:   opts.APISecret,
	}

	if err = json.NewEncoder(configFd).Encode(&configObj); err != nil {
		return err
	}

	keyObj := keyFile{
		Version:    1,
		PublicKey:  encodePublicKey(opts.PublicKey),
		PrivateKey: encodePrivateKey(opts.PrivateKey),
	}

	if err = json.NewEncoder(keyFd).Encode(&keyObj); err != nil {
		return err
	}

	return nil
}

func fileExists(name string) (bool, error) {
	path, err := homedir.Expand(name)
	if err != nil {
		return false, err
	}

	if _, err = os.Stat(path); err == nil {
		return true, nil
	}

	return false, err
}

// ProfileExists returns true if a configuration exists for the
// given profile name.
func ProfileExists(profile string) bool {
	configExists, _ := fileExists(fmt.Sprintf("~/.tozny/%s/e3db.json", profile))
	keyExists, _ := fileExists(fmt.Sprintf("~/.tozny/%s/e3db_key.json", profile))
	return configExists && keyExists
}

// GetConfig loads an E3DB client configuration from a configuration
// file given the name of the profile.
func GetConfig(profile string) (*ClientOpts, error) {
	opts, err := loadConfig(
		fmt.Sprintf("~/.tozny/%s/e3db.json", profile),
		fmt.Sprintf("~/.tozny/%s/e3db_key.json", profile))
	return opts, err
}

// SaveConfig writes an E3DB client configuration to a profile.
func SaveConfig(profile string, opts *ClientOpts) error {
	return saveConfig(
		fmt.Sprintf("~/.tozny/%s/e3db.json", profile),
		fmt.Sprintf("~/.tozny/%s/e3db_key.json", profile),
		opts)
}

// SaveDefaultConfig writes an E3DB client configuration to a profile.
func SaveDefaultConfig(opts *ClientOpts) error {
	return SaveConfig("", opts)
}
