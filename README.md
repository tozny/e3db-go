[![Build Status][travis-image]][travis-url] [![Coverage Status][coveralls-image]][coveralls-url]

# Overview

The Tozny End-to-End Encrypted Database (E3DB) is a storage platform
with powerful sharing and consent management features.
[Read more on our blog.](https://tozny.com/blog/announcing-project-e3db-the-end-to-end-encrypted-database/)

E3DB provides a familiar JSON-based NoSQL-style API for reading, writing,
and querying data stored securely in the cloud.

This repository contains a client library and command-line tool E3DB.

## Build Prerequisites

e3db uses Glide for dependency management. For more information
and installation instructions, see the [Glide Web Site](https://glide.sh).
Binaries for many platforms can be downloaded from the
[GitHub Releases Page](https://github.com/Masterminds/glide/releases).

# Command-Line Interface

The E3DB command-line interface (CLI) is a powerful tool for administrating
and interacting with the E3DB service. Binary releases for many
platforms are available from this project's Releases page.

## Building the CLI

To build a local version of the command-line interface, check out the
sources into the appropriate location within `$GOPATH`, install
dependencies using Glide, and build the `github.com/tozny/e3db/cmd/e3db` package:

```shell
git clone https://github.com/tozny/e3db-go $GOPATH/src/github.com/tozny/e3db-go
cd $GOPATH/src/github.com/tozny/e3db-go
glide install
go install ./cmd/e3db
```

# Client Library

## Installation

If your project uses Glide for managing dependencies and
reproducible builds, add the E3DB client library to your `glide.yaml`
by running:

```shell
$ glide get github.com/tozny/e3db-go
```

If you aren't using Glide and want to depend on the latest
version of E3DB, check out the repository to the correct
location within `$GOPATH` and install dependencies using Glide.

```shell
git clone https://github.com/tozny/e3db-go $GOPATH/src/github.com/tozny/e3db-go
cd $GOPATH/src/github.com/tozny/e3db-go
glide install
```

## Usage

Here is some simple example code to connect and list records:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/tozny/e3db-go"
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

## Writing a record

To write new records to the database, first create a blank record of
the correct type with NewRecord. Then fill in the fields of the record's
`Data` field. Finally, write the record to the database with
`Write`, which returns the unique ID of the newly created record.

```go
record := client.NewRecord("contact")
record.Data["first_name"] = "Jon"
record.Data["last_name"]  = "Snow"
record.Data["phone"]      = "555-555-1212"
recordID, err := client.Write(context.Background(), record)
fmt.Println("Wrote record: " + recordID)
// Read it back out:
newRecord, err := client.Read(context.Background(), recordID)
fmt.Println (newRecord.Data["first_name"])

```

## Documentaton

Comprehensive documentation for the SDK can be found online [via GoDoc](https://godoc.org/github.com/tozny/e3db-go).

[travis-image]: https://travis-ci.org/tozny/e3db-go.svg?branch=master
[travis-url]: https://travis-ci.org/tozny/e3db-go
[coveralls-image]: https://coveralls.io/repos/github/tozny/e3db-go/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/tozny/e3db-go
