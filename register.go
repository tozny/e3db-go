//
// register.go --- Client registration.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type registerRequest struct {
	Email       string    `json:"email"`
	PublicKey   clientKey `json:"public_key"`
	FindByEmail bool      `json:"find_by_email"`
}

type registerResponse struct {
	ClientID  string `json:"client_id"`
	APIKeyID  string `json:"api_key_id"`
	APISecret string `json:"api_secret"`
}

// RegistrationOpts holds options for the registration process,
// such as which server to register against and whether to log.
type RegistrationOpts struct {
	APIBaseURL  string
	FindByEmail bool
	Logging     bool
}

func (opts *RegistrationOpts) apiURL() string {
	if opts.APIBaseURL == "" {
		return defaultStorageURL
	}
	return opts.APIBaseURL
}

// RegisterClient creates a new E3DB client registration by submitting
// a newly generated public key to the server. Returns a Registration
// containing the generated keypair and API credentials. Often this will
// be saved to a configuration file using 'SaveConfig'.
func RegisterClient(email string, opts RegistrationOpts) (*ClientOpts, error) {
	pub, priv, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	regReq := registerRequest{
		Email:       email,
		PublicKey:   clientKey{Curve25519: base64Encode(pub[:])},
		FindByEmail: opts.FindByEmail,
	}

	client := http.Client{}

	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(&regReq)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/storage/clients", opts.apiURL()), buf)
	if err != nil {
		return nil, err
	}

	if opts.Logging {
		logRequest(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer closeResp(resp)

	if opts.Logging {
		logResponse(resp)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, errors.New("a client with that e-mail is already registered")
	} else if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("e3db.RegisterClient: server returned error %d", resp.StatusCode)
	}

	var regResp registerResponse
	json.NewDecoder(resp.Body).Decode(&regResp)

	return &ClientOpts{
		ClientID:   regResp.ClientID,
		APIBaseURL: opts.apiURL(),
		APIKeyID:   regResp.APIKeyID,
		APISecret:  regResp.APISecret,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}
