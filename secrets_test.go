package e3db

import (
	"context"
	"fmt"
	"os"
	"testing"
)

var (
	realmName = os.Getenv("ID_REALM_NAME")
	username  = os.Getenv("USERNAME")
	password  = os.Getenv("PASSWORD")
	baseURL   = os.Getenv("API_URL")
	testCtx   = context.Background()
)

func TestCreateSecret(t *testing.T) {
	fmt.Println("api: ", baseURL)
	request := TozIDLoginRequest{
		Username:     username,
		Password:     password,
		RealmName:    realmName,
		APIBaseURL:   "https://api.e3db.com",
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatalf("Could not log in %+v", err)
	}
	fmt.Println("sdk", sdk)
	// secretReq := SecretRequest{
	// 	SecretName:  "client-test1",
	// 	SecretType:  "Credential",
	// 	SecretValue: "password",
	// 	Description: "this is a secret",
	// }
	// secret, resp, err := sdk.CreateSecret(testCtx, request, secretReq)
	// if err != nil {
	// 	t.Fatalf("Could not create secret: Resp: %+v  Err: %+v", resp, err)
	// }
	// fmt.Println("secret", secret)
}
