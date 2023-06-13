//
// main.go --- e3db command line tool.
//
// Copyright (C) 2020, Tozny, LLC.
// All Rights Reserved.
//

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	cli "github.com/jawher/mow.cli"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/identityClient"
	"github.com/tozny/e3db-go/v2"
	"golang.org/x/crypto/nacl/box"
)

type cliOptions struct {
	Logging *bool
	Profile *string
}

// MaxFileSize is the maximum number of bytes allowed for writefile commands.
const MaxFileSize int64 = 1000000

func dieErr(err error) {
	fmt.Fprintf(os.Stderr, "e3db-cli: %s\n", err)
	cli.Exit(1)
}

func dieFmt(format string, args ...interface{}) {
	fmt.Fprint(os.Stderr, "e3db-cli: ")
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprint(os.Stderr, "\n")
	cli.Exit(1)
}

func (o *cliOptions) getClient() *e3db.Client {
	var client *e3db.Client
	var err error

	opts, err := e3db.GetConfig(*o.Profile)
	if err != nil {
		dieErr(err)
	}

	if *o.Logging {
		opts.Logging = true
	}

	client, err = e3db.GetClient(*opts)
	if err != nil {
		dieErr(err)
	}

	return client
}

func getClientID(client *e3db.Client, maybeEmail string) (string, error) {
	_, err := mail.ParseAddress(maybeEmail)
	if err != nil {
		// If the string isn't an email, it must be an ID. Return it.
		return maybeEmail, nil
	}

	ci, err := client.GetClientInfo(context.Background(), maybeEmail)
	if err != nil {
		return "", err
	}

	return ci.ClientID, nil
}

var options cliOptions

func doQuery(client *e3db.Client, useJSON bool, q *e3db.Q) {
	cursor := client.Query(context.Background(), *q)
	first := true
	for {
		record, err := cursor.Next()
		if err == e3db.Done {
			break
		} else if err != nil {
			dieErr(err)
		}

		if useJSON {
			if first {
				first = false
				fmt.Println("[")
			} else {
				fmt.Printf(",\n")
			}

			buffer := bytes.Buffer{}
			encoder := json.NewEncoder(&buffer)
			encoder.SetEscapeHTML(false)
			encoder.SetIndent("  ", "  ")
			encoder.Encode(record)
			fmt.Printf("  %s", buffer.Bytes())
		} else {
			fmt.Printf("%-40s %s\n", record.Meta.RecordID, record.Meta.Type)
		}
	}

	if useJSON {
		if first {
			first = false
			fmt.Println("[")
		}
		fmt.Println("\n]")
	}
}

func cmdRead(cmd *cli.Cmd) {
	recordIDs := cmd.Strings(cli.StringsArg{
		Name:      "RECORD_ID",
		Value:     nil,
		Desc:      "record IDs to read",
		HideValue: true,
	})

	cmd.Spec = "RECORD_ID..."
	cmd.Action = func() {
		client := options.getClient()
		doQuery(client, true, &e3db.Q{
			RecordIDs:         *recordIDs,
			IncludeData:       true,
			IncludeAllWriters: true,
		})
	}
}

func cmdList(cmd *cli.Cmd) {
	data := cmd.BoolOpt("d data", false, "include data in JSON format")
	outputJSON := cmd.BoolOpt("j json", false, "output in JSON format")
	contentTypes := cmd.StringsOpt("t type", nil, "record content types")
	writerIDs := cmd.StringsOpt("w writer", nil, "record writer IDs or email addresses")
	userIDs := cmd.StringsOpt("u user", nil, "record user IDs")

	var allWritersSpecified bool = false
	allWriters := cmd.Bool(cli.BoolOpt{
		Name:      "a all-writers",
		Value:     false,
		Desc:      "include records from all writers (including those shared with you).",
		EnvVar:    "",
		SetByUser: &allWritersSpecified,
	})

	recordIDs := cmd.Strings(cli.StringsArg{
		Name:      "RECORD_ID",
		Value:     nil,
		Desc:      "record IDs to read",
		HideValue: true,
	})

	cmd.Spec = "[OPTIONS] [RECORD_ID...]"

	cmd.Action = func() {
		client := options.getClient()
		ctx := context.Background()

		// We assume user wants records from all writers if no writer IDs
		// were given on command line (and they did not specify --all-writers
		// explicitly).
		var allWritersFlag bool = false
		if allWritersSpecified {
			allWritersFlag = *allWriters
		} else if len(*writerIDs) == 0 {
			allWritersFlag = true
		}

		// Convert e-mail addresses in write list to writer IDs.
		for ix, writerID := range *writerIDs {
			if strings.Contains(writerID, "@") {
				info, err := client.GetClientInfo(ctx, writerID)
				if err != nil {
					dieErr(err)
				}

				(*writerIDs)[ix] = info.ClientID
			}
		}

		doQuery(client, *outputJSON, &e3db.Q{
			ContentTypes:      *contentTypes,
			RecordIDs:         *recordIDs,
			WriterIDs:         *writerIDs,
			UserIDs:           *userIDs,
			IncludeData:       *data,
			IncludeAllWriters: allWritersFlag,
		})
	}
}

func cmdWrite(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of record to write",
		Value:     "",
		HideValue: true,
	})

	data := cmd.String(cli.StringArg{
		Name:      "DATA",
		Desc:      "json data or @FILENAME",
		Value:     "",
		HideValue: true,
	})

	meta := cmd.String(cli.StringOpt{
		Name:      "META",
		Desc:      "json UNENCRYPTED record metadata for search or @FILENAME",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()
		var recordData string
		// Read record data
		dataRunes := []rune(*data)
		if dataRunes[0] == '@' {
			b, err := ioutil.ReadFile(string(dataRunes[1:]))
			if err != nil {
				dieErr(err)
			}

			recordData = string(b)
		} else {
			recordData = *data
		}
		jsonData := make(map[string]string)
		err := json.NewDecoder(strings.NewReader(recordData)).Decode(&jsonData)
		if err != nil {
			dieErr(err)
		}
		// Read record meta meta search able tags
		var recordMeta string
		metaRunes := []rune(*meta)
		jsonMetaData := make(map[string]string)
		if len(metaRunes) > 0 {
			if metaRunes[0] == '@' {
				b, err := ioutil.ReadFile(string(metaRunes[1:]))
				if err != nil {
					dieErr(err)
				}

				recordMeta = string(b)
			} else {
				recordMeta = *meta
			}

			err = json.NewDecoder(strings.NewReader(recordMeta)).Decode(&jsonMetaData)
		}
		// Write the record to TozStore
		record, err := client.Write(context.Background(), *recordType, jsonData, jsonMetaData)
		if err != nil {
			dieErr(err)
		}

		fmt.Println(record.Meta.RecordID)
	}
}

func cmdWriteFile(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of record to write",
		Value:     "",
		HideValue: true,
	})

	filename := cmd.String(cli.StringArg{
		Name:      "FILENAME",
		Desc:      "path to file to write to e3db",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()
		data := make(map[string]string)

		f, err := os.Open(*filename)
		if err != nil {
			dieErr(err)
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			dieErr(err)
		}

		// If the file is larger than 1MB, err
		if fi.Size() > MaxFileSize {
			dieErr(errors.New("Files must be less than 1MB in size."))
		}

		// Get the file itself
		buf := new(bytes.Buffer)
		buf.ReadFrom(f)

		data["filename"] = fi.Name()
		data["contents"] = base64.RawURLEncoding.EncodeToString(buf.Bytes())
		data["size"] = strconv.FormatInt(fi.Size(), 10)

		record, err := client.Write(context.Background(), *recordType, data, nil)
		if err != nil {
			dieErr(err)
		}

		fmt.Println(record.Meta.RecordID)
	}
}

func cmdReadFile(cmd *cli.Cmd) {
	recordID := cmd.String(cli.StringArg{
		Name:      "RECORD_ID",
		Desc:      "record ID to read",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()

		record, err := client.Read(context.Background(), *recordID)
		if err != nil {
			dieErr(err)
		}

		filename := filepath.Base(record.Data["filename"])

		f, err := os.Create(filename)
		if err != nil {
			dieErr(err)
		}
		defer f.Close()

		contents, err := base64.RawURLEncoding.DecodeString(record.Data["contents"])
		if err != nil {
			dieErr(err)
		}

		n, err := f.Write(contents)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Wrote %d bytes to file: %-20s\n", n, filename)
	}
}

func cmdDelete(cmd *cli.Cmd) {
	recordID := cmd.String(cli.StringArg{
		Name:      "RECORD_ID",
		Desc:      "record ID to delete",
		Value:     "",
		HideValue: true,
	})

	version := cmd.String(cli.StringArg{
		Name:      "VERSION",
		Desc:      "version ID of the record to delete",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()

		err := client.Delete(context.Background(), *recordID, *version)
		if err != nil {
			dieErr(err)
		}
	}
}

func cmdInfo(cmd *cli.Cmd) {
	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client unique id or email",
		Value:     "",
		HideValue: true,
	})

	cmd.Spec = "[CLIENT_ID]"

	cmd.Action = func() {
		client := options.getClient()
		if *clientID == "" {
			fmt.Printf("Client ID:    %s\n", client.Options.ClientID)
			fmt.Printf("Client Email: %s\n", client.Options.ClientEmail)
			fmt.Printf("Public Key:   %s\n", base64.RawURLEncoding.EncodeToString(client.Options.PublicKey[:]))
			fmt.Printf("API Key ID:   %s\n", client.Options.APIKeyID)
			fmt.Printf("API Secret:   %s\n", client.Options.APISecret)
		} else {
			info, err := client.GetClientInfo(context.Background(), *clientID)
			if err != nil {
				dieErr(err)
			}

			fmt.Printf("Client ID:   %s\n", info.ClientID)
			fmt.Printf("Public Key:  %s\n", info.PublicKey.Curve25519)
		}
	}
}

func cmdShare(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to share",
		Value:     "",
		HideValue: true,
	})

	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client unique id or email",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()

		realClientID, e := getClientID(client, *clientID)
		if e != nil {
			dieErr(e)
		}

		err := client.Share(context.Background(), *recordType, realClientID)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' are now shared with client '%s'\n", *recordType, *clientID)
	}
}

func cmdUnshare(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to share",
		Value:     "",
		HideValue: true,
	})

	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client unique id or email",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		client := options.getClient()

		realClientID, e := getClientID(client, *clientID)
		if e != nil {
			dieErr(e)
		}

		err := client.Unshare(context.Background(), *recordType, realClientID)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' are no longer shared with client '%s'\n", *recordType, *clientID)
	}
}

func cmdFeedback(cmd *cli.Cmd) {
	cmd.Action = func() {
		client := options.getClient()

		// Get input from the user
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("What's your impression so far?\n")
		text, _ := reader.ReadString('\n')

		toznyClientID := "db1744b9-3fb6-4458-a291-0bc677dba08b"

		// Write feedback to the database
		data := make(map[string]string)
		data["comment"] = text

		id, err := client.Write(context.Background(), "feedback", data, nil)
		if err != nil {
			dieErr(err)
		}

		// Share with Tozny
		shareErr := client.Share(context.Background(), "feedback", toznyClientID)
		if shareErr != nil {
			dieErr(err)
		}

		// Done!
		fmt.Printf("Your record ID: %s\n", id)
	}
}

func cmdPolicyOutgoing(cmd *cli.Cmd) {
	cmd.Action = func() {
		client := options.getClient()
		osps, err := client.GetOutgoingSharing(context.Background())
		if err != nil {
			dieErr(err)
		}

		for _, osp := range osps {
			var displayName *string
			if osp.ReaderName != "" {
				displayName = &osp.ReaderName
			} else {
				displayName = &osp.ReaderID
			}

			fmt.Printf("%-40s %s\n", *displayName, osp.Type)
		}
	}
}

func cmdPolicyIncoming(cmd *cli.Cmd) {
	cmd.Action = func() {
		client := options.getClient()
		isps, err := client.GetIncomingSharing(context.Background())
		if err != nil {
			dieErr(err)
		}

		for _, isp := range isps {
			var displayName *string
			if isp.WriterName != "" {
				displayName = &isp.WriterName
			} else {
				displayName = &isp.WriterID
			}

			fmt.Printf("%-40s %s\n", *displayName, isp.Type)
		}
	}
}

func cmdRegister(cmd *cli.Cmd) {
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "api",
		Desc:      "e3db api base url",
		Value:     "",
		HideValue: true,
	})

	email := cmd.String(cli.StringArg{
		Name:      "EMAIL",
		Desc:      "client e-mail address",
		Value:     "",
		HideValue: true,
	})

	token := cmd.String(cli.StringArg{
		Name:      "TOKEN",
		Desc:      "registration token from the InnoVault admin console",
		Value:     "",
		HideValue: false,
	})

	cmd.Action = func() {
		// Preflight check for existing configuration file to prevent a later
		// failure writing the file (since we use O_EXCL) after registration.
		if e3db.ProfileExists(*options.Profile) {
			var name string
			if *options.Profile != "" {
				name = *options.Profile
			} else {
				name = "(default)"
			}

			dieFmt("register: profile %s already registered", name)
		}

		// minimally validate that email looks like an email address
		_, err := mail.ParseAddress(*email)
		if err != nil {
			dieErr(err)
		}

		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			dieErr(err)
		}

		publicKey := base64.RawURLEncoding.EncodeToString(pub[:])

		details, apiURL, err := e3db.RegisterClient(*token, *email, publicKey, "", false, *apiBaseURL)

		if err != nil {
			dieErr(err)
		}

		info := &e3db.ClientOpts{
			ClientID:    details.ClientID,
			ClientEmail: details.Name,
			APIKeyID:    details.ApiKeyID,
			APISecret:   details.ApiSecret,
			PublicKey:   pub,
			PrivateKey:  priv,
			APIBaseURL:  apiURL,
			Logging:     false,
		}

		err = e3db.SaveConfig(*options.Profile, info)
		if err != nil {
			dieErr(err)
		}
	}
}
func cmdDeriveAccountCredentials(cmd *cli.Cmd) {
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "api",
		Desc:      "e3db api base url",
		Value:     "",
		HideValue: true,
	})
	accountName := cmd.String(cli.StringArg{
		Name:      "NAME",
		Desc:      "Account display name",
		Value:     "",
		HideValue: true,
	})
	accountEmail := cmd.String(cli.StringArg{
		Name:      "EMAIL",
		Desc:      "Account email",
		Value:     "",
		HideValue: true,
	})

	accountPassword := cmd.String(cli.StringArg{
		Name:      "PASSWORD",
		Desc:      "Account password",
		Value:     "",
		HideValue: true,
	})

	cmd.Spec = "[OPTIONS] [NAME] [EMAIL] [PASSWORD]"

	cmd.Action = func() {
		sdk := e3db.ToznySDKV3{}
		ctx := context.Background()
		accountCredentials, err := sdk.DeriveAccountCredentials(ctx, *accountName, *accountEmail, *accountPassword, *apiBaseURL)
		if err != nil {
			dieErr(err)
		}
		fmt.Printf("%+v", accountCredentials)
	}
}

/**
SDK V3 prototyping below.
Not for external production use.
Interface is rapidly evolving.
*/

func cmdListRealms(cmd *cli.Cmd) {
	useJSON := *cmd.BoolOpt("j json", false, "output in JSON format")
	enabledRealmsOnly := *cmd.BoolOpt("e enabled-realms-only", false, "only include enabled realms in output")
	if enabledRealmsOnly {

	}
	cmd.Spec = "[OPTIONS] "

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}
		ctx := context.Background()
		first := true
		listRealmResponse, err := sdk.ListRealms(ctx)
		if err != nil {
			dieErr(err)
		}
		for _, realm := range listRealmResponse.Realms {
			if useJSON {
				if first {
					first = false
					fmt.Println("[")
				} else {
					fmt.Printf(",\n")
				}

				buffer := bytes.Buffer{}
				encoder := json.NewEncoder(&buffer)
				encoder.SetEscapeHTML(false)
				encoder.SetIndent("  ", "  ")
				encoder.Encode(realm)
				fmt.Printf("  %s", buffer.Bytes())
			} else {
				fmt.Printf("%d %s\n", realm.ID, realm.AdminURL)
			}
		}

		if useJSON {
			fmt.Println("\n]")
		}
	}
}

func cmdSignup(cmd *cli.Cmd) {
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "api",
		Desc:      "e3db api base url",
		Value:     "",
		HideValue: true,
	})
	accountName := cmd.String(cli.StringArg{
		Name:      "NAME",
		Desc:      "Account display name",
		Value:     "",
		HideValue: true,
	})
	accountEmail := cmd.String(cli.StringArg{
		Name:      "EMAIL",
		Desc:      "Account email",
		Value:     "",
		HideValue: true,
	})

	accountPassword := cmd.String(cli.StringArg{
		Name:      "PASSWORD",
		Desc:      "Account password",
		Value:     "",
		HideValue: true,
	})

	cmd.Spec = "[OPTIONS] [NAME] [EMAIL] [PASSWORD]"

	cmd.Action = func() {
		sdk := e3db.ToznySDKV3{}
		ctx := context.Background()
		createdAccount, err := sdk.Register(ctx, *accountName, *accountEmail, *accountPassword, *apiBaseURL)
		if err != nil {
			dieErr(err)
		}
		accountClientConfig := createdAccount.Account.Config
		accountClientInfo := &e3db.ClientOpts{
			ClientID:    accountClientConfig.ClientID,
			ClientEmail: accountClientConfig.ClientEmail,
			APIKeyID:    accountClientConfig.APIKeyID,
			APISecret:   accountClientConfig.APISecret,
			PublicKey:   e3db.MakePublicKey([]byte(accountClientConfig.PublicKey)),
			PrivateKey:  e3db.MakePrivateKey([]byte(accountClientConfig.PrivateKey)),
			APIBaseURL:  accountClientConfig.APIURL,
			Logging:     false,
		}

		err = e3db.SaveConfig(*options.Profile, accountClientInfo)
		if err != nil {
			dieErr(err)
		}
	}
}

func cmdListIdPs(cmd *cli.Cmd) {
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "API",
		Desc:      "e3db api base url",
		Value:     "https://api.e3db.com",
		HideValue: true,
	})
	realmName := cmd.String(cli.StringArg{
		Name:      "REALM_NAME",
		Desc:      "Realm name to fetch",
		Value:     "",
		HideValue: false,
	})
	appName := cmd.String(cli.StringArg{
		Name:      "APP_NAME",
		Desc:      "App to fetch",
		Value:     "account",
		HideValue: false,
	})

	scopes := cmd.String(cli.StringArg{
		Name:      "SCOPES",
		Desc:      "Scopes used for the Identity Login",
		Value:     "openid",
		HideValue: false,
	})

	cmd.Spec = "[REALM_NAME] [APP_NAME] [SCOPES]"

	cmd.Action = func() {
		clientConfig := e3dbClients.ClientConfig{
			Host:      *apiBaseURL,
			AuthNHost: *apiBaseURL,
		}
		identityClientConfig := identityClient.New(clientConfig)
		sdk := e3db.ToznySDKV3{
			APIEndpoint:        *apiBaseURL,
			E3dbIdentityClient: &identityClientConfig,
		}
		ctx := context.Background()

		realmInfo, err := sdk.RealmInfo(ctx, *realmName)
		if err != nil {
			dieErr(err)
		}
		// If we have IdPs Configured, get a List
		if realmInfo.DoIdPsExist {
			dataBytes, err := e3dbClients.GenerateRandomBytes(32)
			pkceVerifier := e3dbClients.Base64Encode(dataBytes)
			request := identityClient.InitiateIdentityProviderLoginRequest{
				RealmName:     *realmName,
				AppName:       *appName,
				CodeChallenge: pkceVerifier,
				LoginStyle:    "api",
				RedirectURL:   "",
				Scope:         *scopes,
			}
			idPInfo, err := sdk.InitiateIdentityProviderLogin(ctx, request)
			if err != nil {
				dieErr(err)
			}
			providers := idPInfo.Context.(map[string]interface{})["idp_providers"].(map[string]interface{})["providers"].([]interface{})
			for _, provider := range providers {
				fmt.Printf("%+v \n", provider.(map[string]interface{})["displayName"])
			}
		}
	}
}

func cmdLogin(cmd *cli.Cmd) {
	accountUsername := cmd.String(cli.StringArg{
		Name:      "ACCOUNT_EMAIL",
		Desc:      "Account username",
		Value:     "",
		HideValue: true,
	})
	accountPassword := cmd.String(cli.StringArg{
		Name:      "ACCOUNT_PASSWORD",
		Desc:      "Account password",
		Value:     "",
		HideValue: true,
	})

	loginEndpoint := cmd.String(cli.StringArg{
		Name:      "ENDPOINT",
		Desc:      "Endpoint to use for attempting the login password",
		Value:     "",
		HideValue: true,
	})

	loginType := cmd.String(cli.StringArg{
		Name:      "LOGIN_TYPE",
		Desc:      "Login type. Valid values are `password` or `paper`",
		Value:     "password",
		HideValue: false,
	})

	cmd.Spec = "[OPTIONS] [ACCOUNT_EMAIL] [ACCOUNT_PASSWORD] [ENDPOINT] [LOGIN_TYPE]"

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}
		ctx := context.Background()
		accountSession, err := sdk.Login(ctx, *accountUsername, *accountPassword, *loginType, *loginEndpoint)
		if err != nil {
			dieErr(err)
		}
		fmt.Printf("Account Session Token: %+v\n", accountSession.Token)
	}
}

func cmdLoginIdP(cmd *cli.Cmd) {
	realmName := cmd.String(cli.StringArg{
		Name:      "REALM_NAME",
		Desc:      "Realm name to fetch",
		Value:     "",
		HideValue: false,
	})
	appName := cmd.String(cli.StringArg{
		Name:      "APP_NAME",
		Desc:      "App to fetch",
		Value:     "account",
		HideValue: false,
	})
	scopes := cmd.String(cli.StringArg{
		Name:      "SCOPES",
		Desc:      "Scopes used for the Identity Login",
		Value:     "openid",
		HideValue: false,
	})

	idP := cmd.String(cli.StringArg{
		Name:      "IDENTITY_PROVIDER",
		Desc:      "The identity provider being used for the identity Login",
		Value:     "openid",
		HideValue: false,
	})
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "API",
		Desc:      "e3db api base url",
		Value:     "https://api.e3db.com",
		HideValue: true,
	})

	cmd.Spec = "[REALM_NAME] [IDENTITY_PROVIDER] [APP_NAME] [SCOPES]"
	cmd.Action = func() {
		clientConfig := e3dbClients.ClientConfig{
			Host:      *apiBaseURL,
			AuthNHost: *apiBaseURL,
		}
		identityClientConfig := identityClient.New(clientConfig)
		sdk := e3db.ToznySDKV3{
			APIEndpoint:        *apiBaseURL,
			E3dbIdentityClient: &identityClientConfig,
		}
		ctx := context.Background()

		realmInfo, err := sdk.RealmInfo(ctx, *realmName)
		if err != nil {
			dieErr(err)
		}
		// If we have IdPs Configured, get a List
		if realmInfo.DoIdPsExist {
			// Generate PKCE
			dataBytes, err := e3dbClients.GenerateRandomBytes(32)
			pkceVerifier := e3dbClients.Base64Encode(dataBytes)

			// Set up Request
			// TODO: Verify Redirect URL is not needed since this is a cli tool and wouldnt need to redirect to example jenkins
			request := identityClient.InitiateIdentityProviderLoginRequest{
				RealmName:     *realmName,
				AppName:       *appName,
				CodeChallenge: pkceVerifier,
				LoginStyle:    "api",
				RedirectURL:   "",
				Scope:         *scopes,
			}
			idPInfo, err := sdk.InitiateIdentityProviderLogin(ctx, request)
			if err != nil {
				dieErr(err)
			}
			// Grab Cookies required for the rest of the login flow
			cookiesMap := idPInfo.Cookie

			// Grab Providers available for realm
			providers := idPInfo.Context.(map[string]interface{})["idp_providers"].(map[string]interface{})["providers"].([]interface{})
			providerRequestedFound := false
			var allCookies string
			for _, provider := range providers {
				if strings.ToLower(*idP) == strings.ToLower(provider.(map[string]interface{})["displayName"].(string)) {
					// Need to set these cookies in the browser
					// Making sure to set them for use of frame realmInfo.IdentityServiceProviderBaseURL
					for key, value := range cookiesMap {
						allCookies += fmt.Sprintf("%s=;Path=/;Expires=Thu, 01 Jan 1970 00:00:01 GMT;", key)
						allCookies += fmt.Sprintf("%s=%s;Path=/;", key, value)
					}
					// Cookies to set on browser
					fmt.Printf(" Cookies  %+v\n", allCookies)
					// URL to redirect to
					url := realmInfo.IdentityServiceProviderBaseURL + provider.(map[string]interface{})["loginUrl"].(string)
					fmt.Printf(" URL  %+v\n", url)
					providerRequestedFound = true
				}

			}
			if !providerRequestedFound {
				fmt.Printf("Provider %+v Not Found for Realm %+v \n", idP, realmName)
			}
		} else {
			fmt.Printf("No Providers Found for Realm %+v \n", realmName)
		}
	}
}

func cmdAuthorizeSharer(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to authorize another client to share on behalf of the authorizing client.",
		Value:     "",
		HideValue: true,
	})

	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client id to authorize for sharing the specific record type",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}

		ctx := context.Background()
		err = sdk.AddAuthorizedSharer(ctx, *clientID, *recordType)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' are now authorized to be shared by client '%s'\n", *recordType, *clientID)
	}
}

func cmdDeauthorizeSharer(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to de-authorize another client to share on behalf of the authorizing client.",
		Value:     "",
		HideValue: true,
	})

	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client id to deauthorize for sharing the specific record type",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}

		ctx := context.Background()
		err = sdk.RemoveAuthorizedSharer(ctx, *clientID, *recordType)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' are now de-authorized to be shared by client '%s'\n", *recordType, *clientID)
	}
}

func cmdBrokerShare(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to share from one client to another client",
		Value:     "",
		HideValue: true,
	})

	authorizerID := cmd.String(cli.StringArg{
		Name:      "AUTHORIZER_ID",
		Desc:      "client id to authorize for sharing records",
		Value:     "",
		HideValue: true,
	})

	readerID := cmd.String(cli.StringArg{
		Name:      "READER_ID",
		Desc:      "client id to authorize for sharing records",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}

		ctx := context.Background()
		err = sdk.BrokerShare(ctx, *authorizerID, *readerID, *recordType)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' from client '%s' are now shared with client '%s'\n", *recordType, *authorizerID, *readerID)
	}
}

func cmdUnbrokerShare(cmd *cli.Cmd) {
	recordType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "type of records to unshare from one client to another client",
		Value:     "",
		HideValue: true,
	})

	authorizerID := cmd.String(cli.StringArg{
		Name:      "AUTHORIZER_ID",
		Desc:      "client id to authorize for sharing records",
		Value:     "",
		HideValue: true,
	})

	readerID := cmd.String(cli.StringArg{
		Name:      "READER_ID",
		Desc:      "client id to authorize for sharing records",
		Value:     "",
		HideValue: true,
	})

	cmd.Action = func() {
		sdk, err := e3db.GetSDKV3(fmt.Sprintf(e3db.ProfileInterpolationConfigFilePath, *options.Profile))
		if err != nil {
			dieErr(err)
		}

		ctx := context.Background()
		err = sdk.UnbrokerShare(ctx, *authorizerID, *readerID, *recordType)
		if err != nil {
			dieErr(err)
		}

		fmt.Printf("Records of type '%s' from client '%s' are now unshared with client '%s'\n", *recordType, *authorizerID, *readerID)
	}
}

func main() {
	app := cli.App("e3db-cli", "E3DB Command Line Interface")

	app.Version("v version", "e3db-cli 2.1.1")

	options.Logging = app.BoolOpt("d debug", false, "enable debug logging")
	options.Profile = app.StringOpt("p profile", "", "e3db configuration profile")

	app.Command("register", "register a client", cmdRegister)
	app.Command("info", "get client information", cmdInfo)
	app.Command("ls", "list records", cmdList)
	app.Command("write", "write a record", cmdWrite)
	app.Command("read", "read records by ID", cmdRead)
	app.Command("delete", "delete a record", cmdDelete)
	app.Command("share", "share records with another client", cmdShare)
	app.Command("unshare", "stop sharing records with another client", cmdUnshare)
	app.Command("authorize", "authorize another client to share records. on behalf of this client", cmdAuthorizeSharer)
	app.Command("deauthorize", "deauthoize another client to share records on behalf of this client", cmdDeauthorizeSharer)
	app.Command("broker", "share records belonging to another client with a third party", cmdBrokerShare)
	app.Command("unbroker", "stop sharing records belonging to another client with a third party", cmdUnbrokerShare)
	app.Command("policy", "operations on sharing policy", func(cmd *cli.Cmd) {
		cmd.Command("incoming", "list incoming sharing policy (who shares with me?)", cmdPolicyIncoming)
		cmd.Command("outgoing", "list outgoing sharing policy (who have I shared with?)", cmdPolicyOutgoing)
	})
	app.Command("feedback", "provde e3db feedback to Tozny", cmdFeedback)
	app.Command("file", "work with small files", func(cmd *cli.Cmd) {
		cmd.Command("read", "read a small file", cmdReadFile)
		cmd.Command("write", "write a small file", cmdWriteFile)
	})
	app.Command("lsrealms", "list realms", cmdListRealms)
	app.Command("lsIdP", "list available IdPs", cmdListIdPs)
	app.Command("signup", "signup for a new account", cmdSignup)
	app.Command("login", "login to fetch credentials and account token", cmdLogin)
	app.Command("idp-login", "login to Tozny using an IdP", cmdLoginIdP)
	app.Command("derive-account-credentials", "Ouputs Account Credentials", cmdDeriveAccountCredentials)
	app.Run(os.Args)
}
