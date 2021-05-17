package e3db

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	realmName         = os.Getenv("TEST_IDENTITY_REALM_NAME")
	username          = os.Getenv("TEST_IDENTITY_USERNAME")
	username2         = os.Getenv("TEST_IDENTITY_USERNAME2")
	password          = os.Getenv("TEST_IDENTITY_PASSWORD")
	baseURL           = os.Getenv("TEST_IDENTITY_API_URL")
	secret1ID         = os.Getenv("TEST_CREATED_SECRET1_ID")
	secret2ID         = os.Getenv("TEST_CREATED_SECRET2_ID")
	testCtx           = context.Background()
	plaintextFileName = "plainfile"
	decryptedFileName = "decrypted"
)

func TestListSecrets(t *testing.T) {
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
	listOptions := ListSecretsOptions{
		RealmName: realmName,
		Limit:     1000,
		NextToken: 0,
	}
	listSecrets, err := sdk.ListSecrets(testCtx, listOptions)
	if err != nil {
		t.Fatalf("Could not list secrets: Err: %+v", err)
	}
	found1 := false
	found2 := false
	// Check that the two pre-created secrets are in the list
	for _, secret := range listSecrets.List {
		if secret.Record.Metadata.RecordID == secret1ID {
			found1 = true
		}
		if secret.Record.Metadata.RecordID == secret2ID {
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
		SecretType:  ClientSecretType,
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
		SecretType:  ClientSecretType,
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
		SecretType:  CredentialSecretType,
		SecretValue: uuid.New().String(),
		Description: "a credential test",
		RealmName:   realmName,
	}
	secretCreated, err := sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v Err: %+v", secretReq, err)
	}
	viewOptions := ViewSecretOptions{
		SecretID:   secretCreated.SecretID,
		MaxSecrets: 1000,
	}
	secretView, err := sdk.ViewSecret(testCtx, viewOptions)
	if err != nil {
		t.Fatalf("Could not view secret: Err: %+v", err)
	}
	if secretReq.SecretValue != secretView.SecretValue {
		t.Fatalf("SecretValue doesn't match. Created: %s Viewed: %s", secretCreated.Record.Data["secretValue"], secretView.Record.Data["secretValue"])
	}
}

func TestCreateAndReadFileSecretSucceeds(t *testing.T) {
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
		SecretType:  FileSecretType,
		SecretValue: "",
		Description: "a file test",
		FileName:    plaintextFileName,
		RealmName:   realmName,
	}
	createdSecret, err := sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v  Err: %+v", secretReq, err)
	}
	readFileOptions := ReadFileOptions{
		RecordID:         createdSecret.SecretID,
		DownloadFileName: decryptedFileName,
	}
	err = sdk.ReadFile(testCtx, readFileOptions)
	if err != nil {
		t.Fatalf("Could not read file: Err: %+v", err)
	}
	defer func() {
		err := os.Remove(decryptedFileName)
		if err != nil {
			t.Logf("Could not delete %s: %+v", decryptedFileName, err)
		}
	}()
	// Compare plaintext and decrypted file contents
	plaintext, err := ioutil.ReadFile(plaintextFileName)
	if err != nil {
		t.Fatalf("Could not read %s file: %+v", plaintextFileName, err)
	}
	decrypted, err := ioutil.ReadFile(decryptedFileName)
	if err != nil {
		t.Fatalf("Could not read %s file: %+v", decryptedFileName, err)
	}
	compare := bytes.Equal(plaintext, decrypted)
	if !compare {
		t.Fatalf("%s and %s files do not match", plaintextFileName, decryptedFileName)
	}
}

func TestShareSecretByUsernameSucceeds(t *testing.T) {
	// login id 1
	request := TozIDLoginRequest{
		Username:     username2,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	// login id 2
	request = TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   baseURL,
		LoginHandler: mfaHandler,
	}
	sdk2, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	// id 1 makes a secret
	secretReq := CreateSecretOptions{
		SecretName:  fmt.Sprintf("client-%s", uuid.New().String()),
		SecretType:  CredentialSecretType,
		SecretValue: uuid.New().String(),
		Description: "a credential test",
		RealmName:   realmName,
	}
	secretCreated, err := sdk.CreateSecret(testCtx, secretReq)
	if err != nil {
		t.Fatalf("Could not create secret: Req: %+v Err: %+v", secretReq, err)
	}
	// id 1 shares the secret with id 2
	shareOptions := ShareSecretInfo{
		SecretName:    secretCreated.SecretName,
		SecretType:    secretCreated.SecretType,
		UsernameToAdd: username,
	}
	err = sdk.ShareSecretWithUsername(testCtx, shareOptions)
	if err != nil {
		t.Fatalf("Error sharing with username: Err: %+v\n", err)
	}
	// id 2 tries to view secret
	viewOptions := ViewSecretOptions{
		SecretID:   secretCreated.SecretID,
		MaxSecrets: 1000,
	}
	secretView, err := sdk2.ViewSecret(testCtx, viewOptions)
	if err != nil {
		t.Fatalf("Error viewing shared secret: Err: %+v", err)
	}
	if secretReq.SecretValue != secretView.SecretValue {
		t.Fatalf("SecretValue doesn't match. Created: %s Viewed: %s", secretCreated.Record.Data["secretValue"], secretView.Record.Data["secretValue"])
	}
}

func TestShareSecretInvalidUsernameFails(t *testing.T) {
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
	viewOptions := ViewSecretOptions{
		SecretID:   uuid.MustParse(secret1ID),
		MaxSecrets: 1000,
	}
	secret, err := sdk.ViewSecret(testCtx, viewOptions)
	if err != nil {
		t.Fatalf("Error viewing shared secret: Err: %+v", err)
	}
	// share secret with a username that doesn't exist
	shareOptions := ShareSecretInfo{
		SecretName:    secret.SecretName,
		SecretType:    secret.SecretType,
		UsernameToAdd: "invalid-user",
	}
	err = sdk.ShareSecretWithUsername(testCtx, shareOptions)
	if err == nil {
		t.Fatal("Should error since username doesn't exist\n")
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
