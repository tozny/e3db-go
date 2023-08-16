package e3db

import (
	"context"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"os"
	"testing"
)

func getToznySDKV3() (*ToznySDKV3, error) {
	toznySDKConfig := ToznySDKConfig{
		ClientConfig:             e3dbClients.ClientConfig{},
		TozIDSessionIdentityData: TozIDSessionIdentityData{},
		AccountUsername:          os.Getenv("ACCOUNT_USERNAME"),
		AccountPassword:          os.Getenv("ACCOUNT_PASSWORD"),
		APIEndpoint:              os.Getenv("API_URL"),
		TozIDRealmIDPAccessToken: nil,
	}
	return NewToznySDKV3(toznySDKConfig)
}

func TestToznySDKV3_IdPLoginToClientApp(t *testing.T) {
	toznySDKV3, err := getToznySDKV3()
	if err != nil {
		t.Error(err)
		return
	}
	realmName := os.Getenv("REALM_NAME")
	clientAppName := os.Getenv("CLIENT_APP_NAME")
	clientLoginUrl := os.Getenv("CLIENT_LOGIN_URL")
	err = toznySDKV3.IdPLoginToClientApp(context.Background(), realmName, DefaultStorageURL, clientAppName, clientLoginUrl)
	if err != nil {
		t.Error(err)
		return
	}
}
