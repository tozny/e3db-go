# Overview

This repository contains a client library and command-line tool
for the Tozny End-to-End Encrypted Database (E3DB).

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
	"os"

	"github.com/tozny/e3db-go"
)

func main() {
	client, err := e3db.GetClient("local")
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return
	}

	cursor := client.Query(context.Background(), e3db.Q{})
	for cursor.Next() {
		record := cursor.Get()
		fmt.Println(record.Meta.RecordID)
	}
}
```
