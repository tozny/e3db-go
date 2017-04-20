# Installation

To install the e3db client library:

```shell
go get github.com/tozny/e3db-go
```

# Usage

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
