//
// client_integration_test.go
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

// +build integration

package e3db

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	cli "github.com/jawher/mow.cli"
)

var client *Client
var clientOpts *ClientOpts
var altClient *Client
var client2 *Client
var clientSharedWithID string

// TestMain bootstraps the environment and sets up our client instance.
func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func dieErr(err error) {
	fmt.Fprintf(os.Stderr, "Unhandled error: %s\n", err)
	cli.Exit(1)
}

func setup() {
	apiURL := os.Getenv("API_URL")
	token := os.Getenv("REGISTRATION_TOKEN")

	clientName := "test-client-" + base64Encode(randomSecretKey()[:8])
	shareClientName := "share-client-" + base64Encode(randomSecretKey()[:8])

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		dieErr(err)
	}
	pubBytes, _ := base64Decode(pub)
	privBytes, _ := base64Decode(priv)
	pubKey := ClientKey{Curve25519: pub}

	pub2, priv2, err := GenerateKeyPair()
	if err != nil {
		dieErr(err)
	}
	pubBytes2, _ := base64Decode(pub2)
	privBytes2, _ := base64Decode(priv2)
	pubKey2 := ClientKey{Curve25519: pub2}

	clientDetails, err := RegisterClient(token, clientName, pubKey, "", false, apiURL)
	if err != nil {
		dieErr(err)
	}

	shareClientDetails, err := RegisterClient(token, shareClientName, pubKey2, "", false, apiURL)
	if err != nil {
		dieErr(err)
	}

	clientOpts = &ClientOpts{
		ClientID:    clientDetails.ClientID,
		ClientEmail: "",
		APIKeyID:    clientDetails.ApiKeyID,
		APISecret:   clientDetails.ApiSecret,
		PublicKey:   MakePublicKey(pubBytes),
		PrivateKey:  MakePrivateKey(privBytes),
		APIBaseURL:  apiURL,
		Logging:     false,
	}

	client, err = GetClient(*clientOpts)
	if err != nil {
		dieErr(err)
	}
	altClient, err = GetClient(*clientOpts)
	if err != nil {
		dieErr(err)
	}

	// Load another client for later sharing tests
	opts := &ClientOpts{
		ClientID:    shareClientDetails.ClientID,
		ClientEmail: "",
		APIKeyID:    shareClientDetails.ApiKeyID,
		APISecret:   shareClientDetails.ApiSecret,
		PublicKey:   MakePublicKey(pubBytes2),
		PrivateKey:  MakePrivateKey(privBytes2),
		APIBaseURL:  apiURL,
		Logging:     false,
	}

	client2, err = GetClient(*opts)
	if err != nil {
		dieErr(err)
	}

	clientSharedWithID = client2.Options.ClientID
}

func shutdown() {

}

func TestRegistration(t *testing.T) {
	apiURL := os.Getenv("API_URL")
	token := os.Getenv("REGISTRATION_TOKEN")

	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubKey := ClientKey{Curve25519: pub}
	clientName := "test-client-" + base64Encode(randomSecretKey()[:8])

	client, err := RegisterClient(token, clientName, pubKey, "", false, apiURL)

	if err != nil {
		t.Fatal(err)
	}

	if clientName != client.Name {
		t.Errorf("Client name does not match: %s != %s", clientName, client.Name)
	}

	if pubKey.Curve25519 != client.PublicKey.Curve25519 {
		t.Errorf("Client keys do not match: %s != %s", pubKey.Curve25519, client.PublicKey.Curve25519)
	}

	if client.ClientID == "" {
		t.Error("Client ID is not set")
	}

	if client.ApiKeyID == "" {
		t.Error("API Key ID is not set")
	}

	if client.ApiSecret == "" {
		t.Error("API Secret is not set")
	}
}

func TestConfig(t *testing.T) {
	profile := "p_" + base64Encode(randomSecretKey()[:8])

	if ProfileExists(profile) {
		t.Error("Profile already exists")
	}

	err := SaveConfig(profile, clientOpts)
	if err != nil {
		t.Error("Unable to save profile")
	}

	newOpts, err := GetConfig(profile)
	if err != nil {
		t.Error("Unable to re-read profile")
	}

	if newOpts.ClientID != clientOpts.ClientID {
		t.Error("Invalid profile retrieved")
	}
}

func TestGetClientInfo(t *testing.T) {
	info, err := client.GetClientInfo(context.Background(), client.Options.ClientID)
	if err != nil {
		t.Fatal(err)
	}

	if info.ClientID != client.Options.ClientID {
		t.Errorf("Client IDs don't match: %s != %s", info.ClientID, client.Options.ClientID)
	}

	k, err := decodePublicKey(info.PublicKey.Curve25519)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k[:], client.Options.PublicKey[:]) {
		t.Errorf("Public keys don't match: %v != %v", k, client.Options.PublicKey)
	}
}

func TestWriteRead(t *testing.T) {
	data := make(map[string]string)
	data["message"] = "Hello, world!"
	rec1, err := client.Write(context.Background(), "test-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordID := rec1.Meta.RecordID

	rec2, err := client.Read(context.Background(), recordID)
	if err != nil {
		t.Fatal(err)
	}

	if rec1.Meta.WriterID != rec2.Meta.WriterID {
		t.Errorf("Writer IDs don't match: %s != %s", rec1.Meta.WriterID, rec2.Meta.WriterID)
	}

	if rec1.Meta.UserID != rec2.Meta.UserID {
		t.Errorf("User IDs don't match: %s != %s", rec1.Meta.UserID, rec2.Meta.UserID)
	}

	if rec1.Meta.Type != rec2.Meta.Type {
		t.Errorf("Record types don't match: %s != %s", rec1.Meta.Type, rec2.Meta.Type)
	}

	if rec1.Data["message"] != rec2.Data["message"] {
		t.Errorf("Record field doesn't match: %s != %s", rec1.Data["message"], rec2.Data["message"])
	}
}

func TestWriteReadNoCache(t *testing.T) {
	data := make(map[string]string)
	data["message"] = "Hello, world!"
	rec1, err := client.Write(context.Background(), "test-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordID := rec1.Meta.RecordID

	rec2, err := altClient.Read(context.Background(), recordID)
	if err != nil {
		t.Fatal(err)
	}

	if rec1.Meta.WriterID != rec2.Meta.WriterID {
		t.Errorf("Writer IDs don't match: %s != %s", rec1.Meta.WriterID, rec2.Meta.WriterID)
	}

	if rec1.Meta.UserID != rec2.Meta.UserID {
		t.Errorf("User IDs don't match: %s != %s", rec1.Meta.UserID, rec2.Meta.UserID)
	}

	if rec1.Meta.Type != rec2.Meta.Type {
		t.Errorf("Record types don't match: %s != %s", rec1.Meta.Type, rec2.Meta.Type)
	}

	if rec1.Data["message"] != rec2.Data["message"] {
		t.Errorf("Record field doesn't match: %s != %s", rec1.Data["message"], rec2.Data["message"])
	}
}

// TestWriteThenDelete should delete a record
func TestWriteThenDelete(t *testing.T) {
	data := make(map[string]string)
	data["message"] = "Hello, world!"
	record, err := client.Write(context.Background(), "test-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordID := record.Meta.RecordID

	err = client.Delete(context.Background(), recordID)
	if err != nil {
		t.Errorf("Delete failed: %s", err)
	}
}

func TestShare(t *testing.T) {
	data := make(map[string]string)
	ctype := "test-data-" + base64Encode(randomSecretKey()[:8])

	data["message"] = "Hello, world!"
	record, err := client.Write(context.Background(), ctype, data, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Share(context.Background(), ctype, client2.Options.ClientID)
	if err != nil {
		t.Error(err)
	}

	record2, err := client2.Read(context.Background(), record.Meta.RecordID)
	if err != nil {
		t.Fatal(err)
	}

	if record.Data["message"] != record2.Data["message"] {
		t.Error("Shared record unreadable!")
	}
}

func haveSharedWith(id, recordType string) (bool, error) {
	osps, err := client.GetOutgoingSharing(context.Background())
	if err != nil {
		return false, err
	}

	for _, osp := range osps {
		if osp.ReaderID == id && osp.Type == recordType {
			return true, nil
		}
	}

	return false, nil
}

// TestShareThenUnshare should share then revoke sharing
func TestShareThenUnshare(t *testing.T) {
	data := make(map[string]string)
	ctype := "test-share-data-" + base64Encode(randomSecretKey()[:8])
	data["message"] = "Hello, world!"
	_, err := client.Write(context.Background(), ctype, data, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Share(context.Background(), ctype, clientSharedWithID)
	if err != nil {
		t.Error(err)
	}

	isShared, err := haveSharedWith(clientSharedWithID, ctype)
	if err != nil {
		t.Errorf("share failed: %s", err)
	} else if !isShared {
		t.Error("share: have not shared with client")
	}

	err = client.Unshare(context.Background(), ctype, clientSharedWithID)
	if err != nil {
		t.Errorf("Unshare failed: %s", err)
	}

	isShared, err = haveSharedWith(clientSharedWithID, ctype)
	if err != nil {
		t.Errorf("unshare failed: %s", err)
	} else if isShared {
		t.Error("unshare: have unexpectedly shared with client")
	}
}

// TestIncomingSharing currently tests that the incoming sharing endpoint
// works and returns a non-error result.
func TestIncomingSharing(t *testing.T) {
	_, err := client.GetIncomingSharing(context.Background())
	if err != nil {
		t.Errorf("TestIncomingSharing: %s", err)
	}
}

// TestEvents should create and utilize an event stream
func TestEvents(t *testing.T) {
	channel := Channel{
		Application: "e3db",
		Type:        "producer",
		Subject:     client.Options.ClientID,
	}

	source, err := client.NewEventSource(context.Background())
	if err != nil {
		dieErr(err)
	}
	defer source.Close()

	events := 0
	done := make(chan struct{})

	go func() {
		for range source.Events() {
			events = events + 1
			if events == 3 {
				close(done)
			}
		}
	}()

	source.Subscribe(channel)

	source.Unsubscribe(channel)

	for range done {
	}
}

func TestCounter(t *testing.T) {
	data := make(map[string]string)
	data["counter"] = "1"
	rec1, err := client.Write(context.Background(), "test-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordID := rec1.Meta.RecordID

	// Update w/ correct version
	err = client.Update(context.Background(), rec1)
	if err != nil {
		t.Fatal(err)
	}

	rec1.Data["counter"] = "X"
	rec1.Meta.Version = "6bc381c7-a41d-45ae-89aa-0890ad654673"
	// should not update
	err = client.Update(context.Background(), rec1)
	if err == nil {
		t.Fatal("Should not be able to update record with wrong version.")
	}

	if httpErr, ok := err.(*httpError); ok {
		if httpErr.StatusCode != http.StatusConflict {
			t.Fatal("Version conflict not reported.")
		}
	}

	rec2, err := client.Read(context.Background(), recordID)
	if err != nil {
		t.Fatal(err)
	}

	if rec2.Data["counter"] != "1" {
		t.Fatal("Counter had wrong value.")
	}

	rec2.Data["counter"] = "2"
	err = client.Update(context.Background(), rec2)
	if err != nil {
		t.Fatal(err)
	}

	rec3, err := client.Read(context.Background(), recordID)
	if err != nil {
		t.Fatal(err)
	}

	if rec3.Data["counter"] != "2" {
		t.Fatal("Counter had wrong value")
	}
}
