//
// config.go --- Configuration and profile management.
//
// Copyright (C) 2020, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

const (
	ProfileInterpolationConfigFilePath = "~/.tozny/%s/e3db.json"
)

var (
	// Currently supported versions of config for a Tozny client used by this SDK
	SupportedVesions = []int{1, 2}
)

type configFile struct {
	Version     int    `json:"version"`
	APIBaseURL  string `json:"api_url"`
	APIKeyID    string `json:"api_key_id"`
	APISecret   string `json:"api_secret"`
	ClientID    string `json:"client_id"`
	ClientEmail string `json:"client_email"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
}

type ConfigFile = configFile

func loadJSON(path string, obj interface{}) error {
	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	b, err := os.ReadFile(path)
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
	config, err := LoadConfigFile(configPath)

	if err != nil {
		return nil, err
	}
	// Determine if the provided config version is supported
	var configVersionSupported bool
	providedVersion := config.Version
	for _, supportedVersion := range SupportedVesions {
		if providedVersion == supportedVersion {
			configVersionSupported = true
			break
		}
	}

	if !configVersionSupported {
		return nil, fmt.Errorf("e3db.loadConfig: unsupported config version: %d, supportedVersions %v", config.Version, SupportedVesions)
	}

	if config.PublicKey == "" {
		return nil, errors.New(fmt.Sprintf("e3db.loadConfig: missing public key %+v", config))
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
		ClientEmail: config.ClientEmail,
		APIBaseURL:  config.APIBaseURL,
		APIKeyID:    config.APIKeyID,
		APISecret:   config.APISecret,
		PublicKey:   pubKey,
		PrivateKey:  privKey,
		Logging:     false,
	}, nil
}

func saveJson(configPath string, obj interface{}) error {
	configFullPath, err := homedir.Expand(configPath)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(configFullPath), 0700)
	if err != nil {
		return err
	}

	configFd, err := os.OpenFile(configFullPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer configFd.Close()

	if err = json.NewEncoder(configFd).Encode(&obj); err != nil {
		return err
	}

	return nil
}

func saveConfig(configPath string, opts *ClientOpts) error {
	configObj := configFile{
		Version:     1,
		ClientID:    opts.ClientID,
		ClientEmail: opts.ClientEmail,
		APIBaseURL:  opts.APIBaseURL,
		APIKeyID:    opts.APIKeyID,
		APISecret:   opts.APISecret,
		PublicKey:   encodePublicKey(opts.PublicKey),
		PrivateKey:  encodePrivateKey(opts.PrivateKey),
	}

	return saveJson(configPath, configObj)
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
	configExists, _ := fileExists(fmt.Sprintf(ProfileInterpolationConfigFilePath, profile))
	keyExists, _ := fileExists(fmt.Sprintf("~/.tozny/%s/e3db_key.json", profile))
	return configExists && keyExists
}

// DefaultConfig loads the default E3DB configuration.
func DefaultConfig() (*ClientOpts, error) {
	return loadConfig(fmt.Sprintf(ProfileInterpolationConfigFilePath, ""))
}

// GetConfig loads an E3DB client configuration from a configuration
// file given the name of the profile.
func GetConfig(profile string) (*ClientOpts, error) {
	opts, err := loadConfig(fmt.Sprintf(ProfileInterpolationConfigFilePath, profile))
	return opts, err
}

// SaveConfig writes an E3DB client configuration to a profile.
func SaveConfig(profile string, opts *ClientOpts) error {
	return saveConfig(fmt.Sprintf(ProfileInterpolationConfigFilePath, profile), opts)
}

// SaveDefaultConfig writes an E3DB client configuration to a profile.
func SaveDefaultConfig(opts *ClientOpts) error {
	return SaveConfig("", opts)
}

/**
SDK V3 prototyping below.
Not for external production use.
Interface is rapidly evolving.
*/

// ToznySDKConfig wraps json file configuration
// needed to initialize the Tozny SDK for account and or client operations.
type ToznySDKJSONConfig struct {
	// Embed all config for v1 and v2 clients
	ConfigFile
	TozIDSessionIdentityData `json:"toz_id_session_identity_data"`
	PublicSigningKey         string `json:"public_signing_key"`
	PrivateSigningKey        string `json:"private_signing_key"`
	AccountUsername          string `json:"account_user_name"`
	AccountPassword          string `json:"account_password"`
	// TozIDRealmIDPAccessToken is populated during the login process.
	// The token can expire so is purposefully not preserved in the saved JSON, and so can be empty.
	TozIDRealmIDPAccessToken *string
}

// LoadConfigFile loads JSON configuration for a Tozny SDK from the file
// at the specified path, returning an instance of that config or error (if any).
func LoadConfigFile(configPath string) (ToznySDKJSONConfig, error) {
	var config ToznySDKJSONConfig

	if err := loadJSON(configPath, &config); err != nil {
		return config, err
	}
	return config, nil
}

func StoreConfigFile(configPath string, config ToznySDKJSONConfig) error {
	return saveJson(configPath, config)
}
