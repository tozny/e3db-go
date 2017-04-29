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
	"testing"
)

var testClient *Client

const TEST_SHARE_CLIENT = "17d19999-f985-445b-a26a-7737d1b4e031"

func getIntegrationTestClient() (*Client, error) {
	if testClient != nil {
		return testClient, nil
	}

	opts, err := GetConfig("integration-test")
	if err != nil {
		return nil, err
	}

	testClient, err := GetClient(*opts)
	if err != nil {
		return nil, err
	}

	return testClient, nil
}

func TestGetClientInfo(t *testing.T) {
	client, err := getIntegrationTestClient()
	if err != nil {
		t.Fatal(err)
	}

	info, err := client.GetClientInfo(context.Background(), client.ClientID)
	if err != nil {
		t.Fatal(err)
	}

	if info.ClientID != client.ClientID {
		t.Errorf("Client IDs don't match: %s != %s", info.ClientID, client.ClientID)
	}

	k, err := decodePublicKey(info.PublicKey.Curve25519)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k[:], client.PublicKey[:]) {
		t.Errorf("Public keys don't match: %v != %v", k, client.PublicKey)
	}
}

func TestWriteRead(t *testing.T) {
	client, err := getIntegrationTestClient()
	if err != nil {
		t.Fatal(err)
	}

	rec1 := client.NewRecord("test-data")
	rec1.Data["message"] = "Hello, world!"
	recordID, err := client.Write(context.Background(), rec1)
	if err != nil {
		t.Fatal(err)
	}

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

func TestShare(t *testing.T) {
	client, err := getIntegrationTestClient()
	if err != nil {
		t.Fatal(err)
	}

	rec1 := client.NewRecord("test-data")
	rec1.Data["message"] = "Hello, world!"
	_, err = client.Write(context.Background(), rec1)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Share(context.Background(), "test-data", TEST_SHARE_CLIENT)
	if err != nil {
		t.Error(err)
	}
}
