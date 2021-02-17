[![Build Status][travis-image]][travis-url] [![Coverage Status][coveralls-image]][coveralls-url]

# Overview

TozStore is an end-to-end encrypted database (E3DB). It's a storage platform
with powerful sharing and consent management features.
[Read more on our website.](https://tozny.com/tozstore)

TozStore provides a familiar JSON-based NoSQL-style API for reading, writing,
and querying data stored securely in the cloud.

This repository contains a client library and command-line tool E3DB.

## Build Prerequisites

e3db uses native go modules for dependency management, which requires a version of go >= 1.11.

# Command-Line Interface

The E3DB command-line interface (CLI) is a powerful tool for administrating
and interacting with the E3DB service. Binary releases for many
platforms are available from this project's Releases page.

## Building the CLI

To build a local version of the command-line interface, check out the
sources locally, install
dependencies, and build the `github.com/tozny/e3db/cmd/e3db` package:

```shell
git clone https://github.com/tozny/e3db-go
cd e3db-go
go build
go install ./cmd/e3db
```

# Client Library

## Installation

If your project uses go modules for managing dependencies and
reproducible builds, add the E3DB client library to your `go.mod`
by running:

```shell
$ go get github.com/tozny/e3db-go/v2
```

Note that prior to go version 1.14, modules are non-standard and require setting GOMODULE11=on.

## Registering a client

Get an API key by [registring a free account](https://dashboard.tozny.com/register) to get started. From the Admin Console you can create clients directly (and grab their credentials from the console) or create registration tokens to dynamically create clients with `e3db.RegisterClient()`. Clients registered from within the console will automatically back their credentials up to your account. Clients created dynamically via the SDK can _optionally_ back their credentials up to your account.

For a more complete walkthrough, see [`/example_registration_test.go`](https://github.com/tozny/e3db-go/blob/master/example_registration_test.go).

### Without Credential Backup

```go
token := ""
client_name := ""

public_key, private_key, _ := e3db.GenerateKeyPair()
client_info, _ := e3db.RegisterClient(token, client_name, public_key, "", false, "https://api.e3db.com")
```

The object returned from the server contains the client's UUID, API key, and API secret (as well as echos back the public key passed during registration). It's your responsibility to store this information locally as it _will not be recoverable_ without credential backup.

### With Credential Backup

```go
token := ""
client_name := ""

public_key, private_key, _ := e3db.GenerateKeyPair()
client_info, _ := e3db.RegisterClient(token, client_name, public_key, private_key, true, "https://api.e3db.com")
```

The private key must be passed to the registration handler when backing up credentials as it is used to cryptographically sign the encrypted backup file stored on the server. The private key never leaves the system, and the stored credentials will only be accessible to the newly-registered client itself or the account with which it is registered.

## Usage

Here is some simple example code to connect and list records:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/tozny/e3db-go/v2"
)

func main() {
	client, err := e3db.GetDefaultClient()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	cursor := client.Query(context.Background(), e3db.Q{})
	for {
		record, err := cursor.Next()
		if err == e3db.Done {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		fmt.Println(record.Meta.RecordID)
	}
}
```

## Reading and Writing Records

To write new records to the database, first create a blank record of
the correct type with NewRecord. Then fill in the fields of the record's
`Data` field. Finally, write the record to the database with
`Write`, which returns the unique ID of the newly created record.

```go
// Create data for a record
var recordData map[string]string
recordType := "contact"
recordData["first_name"] = "Jon"
recordData["last_name"]  = "Snow"
recordData["phone"]      = "555-555-1212"
// Create optional metadata for the record(metadata can be used for searching)
var metadata map[string]string
matadata["realm"] = "The North"
metadata["pet"]   = "Ghost"
// Encrypt and save the record
recordID, err := client.Write(context.Background(), recordType, recordData, metadata)
if err != nil {
	//Error handling omitted
}
fmt.Println("Wrote record: " + recordID)
// Retrieve the saved record
newRecord, err := client.Read(context.Background(), recordID)
if err != nil {
	//Error handling omitted
}
fmt.Println (newRecord.Data["first_name"])
```

## Documentaton

The SDK is documented with standard Go documentation that most IDEs can parse.

[travis-image]: https://travis-ci.org/tozny/e3db-go.svg?branch=master
[travis-url]: https://travis-ci.org/tozny/e3db-go
[coveralls-image]: https://coveralls.io/repos/github/tozny/e3db-go/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/tozny/e3db-go
