package e3db

import (
	"fmt"
	"testing"
)

func TestToznySDKV3_Login(t *testing.T) {
	request := TozIDLoginRequest{
		Username:   "",
		Password:   "",
		RealmName:  "",
		APIBaseURL: "https://api.e3db.com",
		LoginHandler: mfaHandler,
	}
	sdk, err := GetSDKV3ForTozIDUser(request)
	if err != nil {
		t.Fatal("Abort", err)
	}
	fmt.Printf("%v", sdk)
}

func mfaHandler(sessionResponse *IdentitySessionIntermediateResponse) (LoginActionData, error) {
	if sessionResponse.LoginActionType == "login-totp" {
		totpValue := make(map[string]string)
		totpValue["otp"] = ""
		return totpValue, nil
	}
	return nil, fmt.Errorf("mfaHandler cannot support \"%s\" action types", sessionResponse.LoginActionType)
}