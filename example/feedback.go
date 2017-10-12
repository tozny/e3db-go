package main

// This example interacts with the "feedback" mechanism in the CLI. If you run
// this code, it will share text with Tozny in an end-to-end encrypted manner.

import (
	"context"
	"fmt"
	"log"

	"github.com/tozny/e3db-go"
)

func chk(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printRecords(recordType string) {
	client, err := e3db.GetDefaultClient()
	chk(err)

	// Query for all records and print them out
	query := e3db.Q{} // queries all records
	if recordType != "" {
		query = e3db.Q{ContentTypes: []string{recordType}}
	}
	cursor := client.Query(context.Background(), query)
	for {
		record, err := cursor.Next()
		if err == e3db.Done {
			break
		} else if err != nil {
			chk(err)
		}
		fmt.Println("\t" + record.Meta.RecordID + " " + record.Meta.Type)
	}
}

func main() {

	// Accessing the default profile.
	// You must run e3db register before this will work:
	client, err := e3db.GetDefaultClient()
	chk(err)

	fmt.Println("Current list of records:")
	printRecords("")

	// Create a new "feedback" record; this is the type the CLI uses
	feedbackData := make(map[string]string)
	feedbackData["comment"] = "This is some example feedback!"
	feedbackData["interface"] = "Go Example Code"
	record, err := client.Write(context.Background(), "feedback", feedbackData, nil)
	chk(err)

	// Read back the feedback we just put into the database
	newFeedbackRecord, err := client.Read(context.Background(), record.Meta.RecordID)
	chk(err)
	fmt.Println("Read record id " + record.Meta.RecordID + ": " + newFeedbackRecord.Data["comment"])

	// Fetch the Tozny feedback email address public key and client ID
	feedbackClient, err := client.GetClientInfo(context.Background(), "db1744b9-3fb6-4458-a291-0bc677dba08b")
	chk(err)

	// Share all "feedback" records with that user ID.
	err = client.Share(context.Background(), "feedback", feedbackClient.ClientID)
	chk(err)

	fmt.Println("Current list of records after adding:")
	printRecords("feedback")

	// Delete the record we just created to keep things tidy.
	// Comment out this line if you want to keep it
	err = client.Delete(context.Background(), record.Meta.RecordID, record.Meta.Version)
	chk(err)

	fmt.Println("Current list of records after deleting:")
	printRecords("feedback")
}
