package e3db

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	realmName         = os.Getenv("ID_REALM_NAME")
	username          = os.Getenv("USERNAME")
	password          = os.Getenv("PASSWORD")
	baseURL           = os.Getenv("API_URL")
	testCtx           = context.Background()
	plaintextFileName = "plainfile"
)

func TestCreateAndListSecrets(t *testing.T) {
	request := TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	secretReq := CreateSecretOptions{
		SecretName:  fmt.Sprintf("client-%s", uuid.New().String()),
		SecretType:  "Credential",
		SecretValue: uuid.New().String(),
		Description: "a credential test",
		RealmName:   realmName,
	}
	validClient := `{
		"version": "2",
		"public_signing_key": "A5QXkIKW5dBN_IOhjGoUBtT-xuVmqRXDB2uaqiKuTao",
		"private_signing_key": "qIqG9_81kd2gOY-yggIpahQG1MDnlBeQj7G4MHa5p0E1WapQxLVlyU6hXA6rp-Ci5DFf8g6GMaqy5t_H1g5Nqg",
		"client_id": "4f20ca95-1b3b-b78f-b5bd-6d469ac804eb",
		"api_key_id": "63807026e9a23850307429e52d2f607eaa5be43488cbb819b075ade91735b180",
		"api_secret": "730e6b18dc9668fe1758304283c73060619f6596f11bf42bdd3f16d6fc6cd6d0",
		"public_key": "6u73qLgJniPi9S2t99A7lNfvi3xjxMsPB_Z-CEGWZmo",
		"private_key": "BnBt9_tquBvSAHL04bQm0HkQ7eXtvuj1WSHegQeho6E",
		"api_url": "http://platform.local.tozny.com:8000",
		"client_email": ""
	}`
	secretReq2 := CreateSecretOptions{
		SecretName:  fmt.Sprintf("cred-%s", uuid.New().String()),
		SecretType:  "Client",
		SecretValue: validClient,
		Description: "a client cred test",
		RealmName:   realmName,
	}
	secret1, err := sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v Err: %+v", secretReq, err)
	}
	secret2, err := sdk.CreateSecret(testCtx, secretReq2)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v  Err: %+v", secretReq2, err)
	}
	listOptions := ListSecretsOptions{
		RealmName: realmName,
		Limit:     30,
		NextToken: 0,
	}
	listSecrets, err := sdk.ListSecrets(testCtx, listOptions)
	if err != nil {
		t.Fatalf("Could not list secrets: Err: %+v", err)
	}
	found1 := false
	found2 := false
	for _, secret := range listSecrets.List {
		if secret.Record.Metadata.RecordID == secret1.Record.Metadata.RecordID && secretReq.SecretValue == secret.Record.Data["secretValue"] {
			found1 = true
		}
		if secret.Record.Metadata.RecordID == secret2.Record.Metadata.RecordID && secretReq2.SecretValue == secret.Record.Data["secretValue"] {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("Did not find secret1 or secret2 in listSecrets")
	}
}

func TestInvalidCredSecretFails(t *testing.T) {
	request := TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	invalidClient := `{
		"version": "2",
		"public_signing_key": "A5QX5dBN_IOhjGoUBtT-xuVmqRXDB2uaqiKuTao",
		"private_signing_key": "qIqG9_81kd2gOY-yggIpahQG1MDnlBeQj7G4MHa5p0E1WapQxLVlyU6hXA6rp-Ci5DFf8g6GMaqy5t_H1g5Nqg",
		"client_id": "4f20ca95-1b3b-b78f-b5bd-6d469ac804eb",
		"api_key_id": "63807026e9a23850307429e52d2f607eaa5be43488cbb819b075ade91735b180",
		"api_secret": "730e6b18dc9668fe1758304283c73060619f6596f11bf42bdd3f16d6fc6cd6d0",
		"public_key": "6u73qLgJniPi9S2t99A7lNfvi3xjxMsPB_Z-CEGWZmo",
		"private_key": "BnBt9_tquBvSAHL04bQm0HkQ7eXtvuj1WSHegQeho6E",
		"api_url": "http://platform.local.tozny.com:8000",
		"client_email": ""
	}`
	secretReq := CreateSecretOptions{
		SecretName:  fmt.Sprintf("cred-%s", uuid.New().String()),
		SecretType:  "Client",
		SecretValue: invalidClient,
		Description: "a client cred test",
		RealmName:   realmName,
	}
	_, err = sdk.CreateSecret(testCtx, secretReq)
	if err == nil {
		t.Fatal("Secret creation should have failed.")
	}
	invalidClient = `{
		"version": "2",
		"public_signing_key": "A5QX5dBN_IOhjGoUBtT-xuVmqRXDB2uaqiKuTao",
		"private_signing_key": "qIqG9_81kd2gOY-yggIpahQG1MDnlBeQj7G4MHa5p0E1WapQxLVlyU6hXA6rp-Ci5DFf8g6GMaqy5t_H1g5Nqg",
		"client_id": "4f20ca95-1b3b-b78f-b5bd-6d469ac804eb",
		"api_key_id": "63807026e9a23850307429e52d2f607eaa5be43488cbb819b075ade91735b180",
		"api_secret": "730e6b18dc9668fe1758304283c73060619f6596f11bf42bdd3f16d6fc6cd6d0",
		"public_key": "6u73qLgJniPi9S2t99A7lNfvi3xjxMsPB_Z-CEGWZmo",
		"private_key": "BnBt9_tquBvSAHL04bQm0HkQ7eXtvuj1WSHegQeho6E",
		"client_email": ""
	}`
	secretReq = CreateSecretOptions{
		SecretName:  fmt.Sprintf("cred-%s", uuid.New().String()),
		SecretType:  "Client",
		SecretValue: invalidClient,
		Description: "a client cred test",
		RealmName:   realmName,
	}
	_, err = sdk.CreateSecret(testCtx, secretReq)
	if err == nil {
		t.Fatal("Secret creation should have failed.")
	}
}

func TestCreateAndViewSecretSucceeds(t *testing.T) {
	request := TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	secretReq := CreateSecretOptions{
		SecretName:  fmt.Sprintf("client-%s", uuid.New().String()),
		SecretType:  "Credential",
		SecretValue: uuid.New().String(),
		Description: "a credential test",
		RealmName:   realmName,
	}
	secretCreated, err := sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v Err: %+v", secretReq, err)
	}
	viewOptions := ViewSecretOptions{
		SecretID: secretCreated.Record.Metadata.RecordID,
	}
	secretView, err := sdk.ViewSecret(testCtx, viewOptions)
	if err != nil {
		t.Fatalf("Could not view secret: Err: %+v", err)
	}
	if secretReq.SecretValue != secretView.Record.Data["secretValue"] {
		t.Fatalf("SecretValue doesn't match. Created: %s Viewed: %s", secretCreated.Record.Data["secretValue"], secretView.Record.Data["secretValue"])
	}
}

func TestCreateAndViewFileSecretSucceeds(t *testing.T) {
	request := TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	plainFile, err := os.Create(plaintextFileName)
	if err != nil {
		t.Fatalf("Could not create plainFile: %+v", err)
	}
	defer func() {
		err := os.Remove(plaintextFileName)
		if err != nil {
			t.Logf("Could not delete %s: %+v", plaintextFileName, err)
		}
	}()
	randTxt, _ := e3dbClients.GenerateRandomString(500)
	_, err = plainFile.WriteString(randTxt)
	if err != nil {
		t.Fatalf("Could not write to plainFile: %+v", err)
	}
	secretReq := CreateSecretOptions{
		SecretName:  fmt.Sprintf("client-%s", uuid.New().String()),
		SecretType:  "File",
		SecretValue: "",
		Description: "a file test",
		FileName:    plaintextFileName,
		RealmName:   realmName,
	}
	_, err = sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v  Err: %+v", secretReq, err)
	}
}

func mfaHandler(sessionResponse *IdentitySessionIntermediateResponse) (LoginActionData, error) {
	if sessionResponse.LoginActionType == "login-totp" {
		totpValue := make(map[string]string)
		totpValue["otp"] = ""
		return totpValue, nil
	}
	return nil, fmt.Errorf("mfaHandler cannot support \"%s\" action types", sessionResponse.LoginActionType)
}
