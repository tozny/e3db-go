//
// config.go --- Configuration and profile management.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	homedir "github.com/mitchellh/go-homedir"
)

type configFile struct {
	Version     int    `json:"version"`
	APIBaseURL  string `json:"api_url"`
	AuthBaseURL string `json:"auth_url"`
	APIKeyID    string `json:"api_key_id"`
	APISecret   string `json:"api_secret"`
	ClientID    string `json:"client_id"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
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

func loadConfig(configPath string) (*ClientOpts, error) {
	var config configFile

	if err := loadJSON(configPath, &config); err != nil {
		return nil, err
	}

	if config.Version != 1 {
		return nil, fmt.Errorf("e3db.loadConfig: unsupported config version: %d", config.Version)
	}

	if config.PublicKey == "" {
		return nil, errors.New("e3db.loadConfig: missing public key")
	}

	if config.PrivateKey == "" {
		return nil, errors.New("e3db.loadConfig: missing private key")
	}

	pubKey, err := decodePublicKey(config.PublicKey)
	if err != nil {
		return nil, err
	}

	privKey, err := decodePrivateKey(config.PrivateKey)
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

func saveConfig(configPath string, opts *ClientOpts) error {
	configFullPath, err := homedir.Expand(configPath)
	if err != nil {
		return err
	}

	err = os.MkdirAll(path.Dir(configFullPath), 0700)
	if err != nil {
		return err
	}

	configFd, err := os.OpenFile(configFullPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer configFd.Close()

	configObj := configFile{
		Version:     1,
		ClientID:    opts.ClientID,
		APIBaseURL:  opts.APIBaseURL,
		AuthBaseURL: opts.AuthBaseURL,
		APIKeyID:    opts.APIKeyID,
		APISecret:   opts.APISecret,
		PublicKey:   encodePublicKey(opts.PublicKey),
		PrivateKey:  encodePrivateKey(opts.PrivateKey),
	}

	if err = json.NewEncoder(configFd).Encode(&configObj); err != nil {
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
	opts, err := loadConfig(fmt.Sprintf("~/.tozny/%s/e3db.json", profile))
	return opts, err
}

// SaveConfig writes an E3DB client configuration to a profile.
func SaveConfig(profile string, opts *ClientOpts) error {
	return saveConfig(fmt.Sprintf("~/.tozny/%s/e3db.json", profile), opts)
}

// SaveDefaultConfig writes an E3DB client configuration to a profile.
func SaveDefaultConfig(opts *ClientOpts) error {
	return SaveConfig("", opts)
}
