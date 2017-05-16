//
// main.go --- e3db command line tool.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jawher/mow.cli"
	"github.com/tozny/e3db-go"
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
	fmt.Fprintf(os.Stderr, format, args)
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

			bytes, _ := json.MarshalIndent(record, "  ", "  ")
			fmt.Printf("  %s", bytes)
		} else {
			fmt.Printf("%-40s %s\n", record.Meta.RecordID, record.Meta.Type)
		}
	}

	if useJSON {
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
			RecordIDs:   *recordIDs,
			IncludeData: true,
		})
	}
}

func cmdList(cmd *cli.Cmd) {
	data := cmd.BoolOpt("d data", false, "include data in JSON format")
	outputJSON := cmd.BoolOpt("j json", false, "output in JSON format")
	contentTypes := cmd.StringsOpt("t type", nil, "record content types")
	writerIDs := cmd.StringsOpt("w writer", nil, "record writer IDs or email addresses")
	userIDs := cmd.StringsOpt("u user", nil, "record user IDs")
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
			ContentTypes: *contentTypes,
			RecordIDs:    *recordIDs,
			WriterIDs:    *writerIDs,
			UserIDs:      *userIDs,
			IncludeData:  *data,
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

	cmd.Action = func() {
		client := options.getClient()
		var recordData string

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

		record := client.NewRecord(*recordType)
		err := json.NewDecoder(strings.NewReader(recordData)).Decode(&record.Data)
		if err != nil {
			dieErr(err)
		}

		id, err := client.Write(context.Background(), record)
		if err != nil {
			dieErr(err)
		}

		fmt.Println(id)
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
		record := client.NewRecord(*recordType)

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

		record.Data["filename"] = fi.Name()
		record.Data["contents"] = base64.RawURLEncoding.EncodeToString(buf.Bytes())
		record.Data["size"] = strconv.FormatInt(fi.Size(), 10)

		id, err := client.Write(context.Background(), record)
		if err != nil {
			dieErr(err)
		}

		fmt.Println(id)
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
	recordIDs := cmd.Strings(cli.StringsArg{
		Name:      "RECORD_ID",
		Desc:      "record IDs to delete",
		Value:     nil,
		HideValue: true,
	})

	cmd.Spec = "RECORD_ID..."
	cmd.Action = func() {
		client := options.getClient()

		for _, recordID := range *recordIDs {
			err := client.Delete(context.Background(), recordID)
			if err != nil {
				dieErr(err)
			}
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

func cmdRegister(cmd *cli.Cmd) {
	apiBaseURL := cmd.String(cli.StringOpt{
		Name:      "api",
		Desc:      "e3db api base url",
		Value:     "",
		HideValue: true,
	})

	isPublic := cmd.Bool(cli.BoolOpt{
		Name:      "public",
		Desc:      "allow other clients to find you by email",
		Value:     true,
		HideValue: false,
	})

	email := cmd.String(cli.StringArg{
		Name:      "EMAIL",
		Desc:      "client e-mail address",
		Value:     "",
		HideValue: true,
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

		info, err := e3db.RegisterClient(*email, e3db.RegistrationOpts{
			APIBaseURL:  *apiBaseURL,
			Logging:     *options.Logging,
			FindByEmail: *isPublic,
		})

		if err != nil {
			dieErr(err)
		}

		err = e3db.SaveConfig(*options.Profile, info)
		if err != nil {
			dieErr(err)
		}
	}
}

func cmdSubscribe(cmd *cli.Cmd) {
	app := cmd.String(cli.StringArg{
		Name:      "APP",
		Desc:      "application name",
		Value:     "e3db",
		HideValue: true,
	})

	eventType := cmd.String(cli.StringArg{
		Name:      "TYPE",
		Desc:      "channel type",
		Value:     "",
		HideValue: true,
	})

	clientID := cmd.String(cli.StringArg{
		Name:      "CLIENT_ID",
		Desc:      "client unique id or email",
		Value:     "",
		HideValue: true,
	})

	cmd.Spec = "APP [TYPE] [CLIENT_ID]"

	cmd.Action = func() {
		client := options.getClient()

		if *clientID == "" {
			*clientID = client.Options.ClientID
		}
		if *eventType == "" {
			*eventType = "producer"
		}

		channel := e3db.Channel{
			Application: *app,
			Type:        *eventType,
			Subject:     *clientID,
		}

		source, err := client.NewEventSource(context.Background())
		if err != nil {
			dieErr(err)
		}
		defer source.Close()

		source.Subscribe(channel)

		go func() {
			for event := range source.Events() {
				b, _ := json.MarshalIndent(event, "  ", "  ")
				log.Println(string(b))
			}
		}()

		var input string
		fmt.Scanln(&input)
		fmt.Println("done")
	}
}

func cmdFeedback(cmd *cli.Cmd) {
	cmd.Action = func() {
		client := options.getClient()

		// Get input from the user
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("What's your impression so far?\n")
		text, _ := reader.ReadString('\n')

		toznyClientID, e := getClientID(client, "ijones+feedback@tozny.com")
		if e != nil {
			dieErr(errors.New("Feedback address not registered."))
		}

		// Write feedback to the database
		record := client.NewRecord("feedback")
		record.Data["comment"] = text
		id, err := client.Write(context.Background(), record)
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

func main() {
	app := cli.App("e3db-cli", "E3DB Command Line Interface")

	app.Version("v version", "e3db-cli 1.0.1")

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
	app.Command("policy", "operations on sharing policy", func(cmd *cli.Cmd) {
		cmd.Command("incoming", "list incoming sharing policy (who shares with me?)", cmdPolicyIncoming)
		cmd.Command("outgoing", "list outgoing sharing policy (who have I shared with?)", cmdPolicyOutgoing)
	})
	app.Command("subscribe", "subscribe to a stream of events produced by a client", cmdSubscribe)
	app.Command("feedback", "provde e3db feedback to Tozny", cmdFeedback)
	app.Command("file", "work with small files", func(cmd *cli.Cmd) {
		cmd.Command("read", "read a small file", cmdReadFile)
		cmd.Command("write", "write a small file", cmdWriteFile)
	})
	app.Run(os.Args)
}
