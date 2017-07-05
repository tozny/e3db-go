//
// main.go --- e3db command line tool.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package main

import (
	"context"
	"fmt"
	"net/mail"
	"os"

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

func main() {
	app := cli.App("e3db-cli", "E3DB Command Line Interface")

	app.Version("v version", "e3db-cli 2.0.0-rc1")

	options.Logging = app.BoolOpt("d debug", false, "enable debug logging")
	options.Profile = app.StringOpt("p profile", "", "e3db configuration profile")

	app.Command("register", "register a client", cmdRegister)
	app.Run(os.Args)
}
