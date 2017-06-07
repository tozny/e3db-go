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

const TEST_SHARE_CLIENT = "dac7899f-c474-4386-9ab8-f638dcc50dec"

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
	opts, err := GetConfig("integration-test")
	if err != nil {
		dieErr(err)
	}

	opts.Logging = false

	client, err = GetClient(*opts)
	if err != nil {
		dieErr(err)
	}
}

func shutdown() {

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
	data["message"] = "Hello, world!"
	_, err := client.Write(context.Background(), "test-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Share(context.Background(), "test-data", TEST_SHARE_CLIENT)
	if err != nil {
		t.Error(err)
	}
}

// TestShareThenUnshare should share then revoke sharing
func TestShareThenUnshare(t *testing.T) {
	data := make(map[string]string)
	data["message"] = "Hello, world!"
	_, err := client.Write(context.Background(), "test-share-data", data, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Share(context.Background(), "test-share-data", TEST_SHARE_CLIENT)
	if err != nil {
		t.Error(err)
	}

	err = client.Unshare(context.Background(), "test-share-date", TEST_SHARE_CLIENT)
	if err != nil {
		t.Errorf("Unshare failed: %s", err)
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
