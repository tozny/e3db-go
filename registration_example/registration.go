package main

// This program provides a simple example illustrating how to programmatically
// register a client with InnoVault and e3db. In some situations, it's preferable
// to register a client from the server or system that will be using its
// credentials (to ensure that all data is truly encrypted from end-to-end
// with no possibilities of a credential leak). For more detailed information,
// please see the documentation home page: https://tozny.com/documentation/e3db
//
// Author::    Eric Mann (eric@tozny.com)
// Copyright:: Copyright (c) 2017 Tozny, LLC
// License::   Public Domain

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/tozny/e3db-go"
)

// randomSecretKey is otherwise private to the client and is used to generate
// a random string ... it's not actually used for cryptographic operations
// in this example.
func randomSecretKey() *[32]byte {
	key := &[32]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		// we don't expect this to fail
		panic("random number generation failed")
	}

	return key
}

func main() {
	// A registration token is required to set up a client. In this situation,
	// we assume an environment variable called REGISTRATION_TOKEN is set
	token := os.Getenv("REGISTRATION_TOKEN")

	// Clients can either create new cryptographic keypairs, or load in a pre-defined
	// pair of Curve25519 keys. In this situation, we will generate a new keypair.
	public_key, private_key, err := e3db.GenerateKeyPair()

	fmt.Fprintf(os.Stdout, "Public Key:  %s\n", public_key)
	fmt.Fprintf(os.Stdout, "Private Key: %s\n", private_key)

	// Clients must be registered with a name unique to your account to help
	// differentiate between different sets of credentials in the Admin Console.
	// In this example, the name is set at random
	client_name := "client_" + base64.RawURLEncoding.EncodeToString(randomSecretKey()[:8])

	fmt.Fprintf(os.Stdout, "Client Name: %s\n", client_name)

	// Passing all of the data above into the registration routine will create
	// a new client with the system. Remember to keep your private key private!
	client_info, err := e3db.RegisterClient(token, client_name, public_key, "", false, "https://api.e3db.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unhandled error: %s\n", err)
		log.Fatal(err)
	}

	// Optionally, you can automatically back up the credentials of the newly-created
	// client to your InnoVault account (accessible via https://console.tozny.com) by
	// passing your private key and a backup flag when registering. The private key is
	// not sent anywhere, but is used by the newly-created client to sign an encrypted
	// copy of its credentials that is itself stored in e3db for later use.
	//
	// Client credentials are not backed up by default.

	// client_info := e3db.RegisterClient(token, client_name, public_key, private_key, true, "https://api.e3db.com")
	// if err != nil {
	//   fmt.Fprintf(os.Stderr, "Unhandled error: %s\n", err)
	//   log.Fatal(err)
	// }

	fmt.Fprintf(os.Stdout, "Client ID:   %s\n", client_info.ClientID)
	fmt.Fprintf(os.Stdout, "API Key ID:  %s\n", client_info.ApiKeyID)
	fmt.Fprintf(os.Stdout, "API Secret:  %s\n", client_info.ApiSecret)

	// ---------------------------------------------------------
	// Usage
	// ---------------------------------------------------------

	// Once the client is registered, you can use it immediately to create the
	// configuration used to instantiate a Client that can communicate with
	// e3db directly.

	pubBytes, _ := base64.RawURLEncoding.DecodeString(public_key)
	privBytes, _ := base64.RawURLEncoding.DecodeString(private_key)

	config := &e3db.ClientOpts{
		ClientID:    client_info.ClientID,
		ClientEmail: "",
		APIKeyID:    client_info.ApiKeyID,
		APISecret:   client_info.ApiSecret,
		PublicKey:   e3db.MakePublicKey(pubBytes),
		PrivateKey:  e3db.MakePrivateKey(privBytes),
		APIBaseURL:  "https://api.e3db.com",
		Logging:     false,
	}

	// Now create a client using that configuration.
	_, err = e3db.GetClient(*config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unhandled error: %s\n", err)
		log.Fatal(err)
	}

	// From this point on, the new client can be used as any other client to read
	// write, delete, and query for records. See the `simple.rb` documentation
	// for more complete examples ...
}
