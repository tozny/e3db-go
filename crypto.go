//
// crypto.go --- E3db client crypto operations.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

type CABEntry struct {
	EAK                 string `json:"eak"`
	AuthorizerID        string `json:"authorizer_id"`
	AuthroizerPublicKey string `json:"authorizer_public_key"`
}

type decodedCABEntry struct {
	eak                 []byte
	nonce               [24]byte
	authorizerPublicKey [32]byte
}

func (e *CABEntry) decode() (*decodedCABEntry, error) {
	fields := strings.SplitN(e.EAK, ".", 2)
	var r decodedCABEntry
	var err error
	var nonceSlice, pubKSlice []byte

	if r.eak, err = base64.RawURLEncoding.DecodeString(fields[0]); err != nil {
		return nil, err
	}

	if nonceSlice, err = base64.RawURLEncoding.DecodeString(fields[1]); err != nil {
		return nil, err
	}
	copy(r.nonce[:], nonceSlice)

	if pubKSlice, err = base64.RawURLEncoding.DecodeString(e.AuthroizerPublicKey); err != nil {
		return nil, err
	}
	copy(r.authorizerPublicKey[:], pubKSlice)

	return &r, nil
}

type decodedField struct {
	edk  []byte
	edkN [24]byte
	ef   []byte
	efN  [24]byte
}

func decodeEncryptedField(s string) (*decodedField, error) {
	var r decodedField
	var edkNSlice []byte
	var efNSlice []byte
	var err error

	fields := strings.SplitN(s, ".", 4)

	if r.edk, err = base64.RawURLEncoding.DecodeString(fields[0]); err != nil {
		return nil, err
	}

	if edkNSlice, err = base64.RawURLEncoding.DecodeString(fields[1]); err != nil {
		return nil, err
	}
	copy(r.edkN[:], edkNSlice)

	if r.ef, err = base64.RawURLEncoding.DecodeString(fields[2]); err != nil {
		return nil, err
	}

	if efNSlice, err = base64.RawURLEncoding.DecodeString(fields[3]); err != nil {
		return nil, err
	}
	copy(r.efN[:], efNSlice)

	return &r, nil
}

// TODO: Distinguish between HTTP errors like "NotFound" vs. actual unexpected
// errors so we can figure out if we should generate a new AK.
func (c *Client) getAccessKey(ctx context.Context, writerID, userID, readerID, recordType string) ([]byte, error) {
	var ak []byte

	// TODO: Is this the best place to do this?
	if c.akCache == nil {
		c.akCache = make(map[AKCacheKey][]byte)
	}

	cacheKey := AKCacheKey{writerID, userID, recordType}
	ak, ok := c.akCache[cacheKey]
	if ok {
		return ak, nil
	}

	u := fmt.Sprintf("%s/cab/entry/%s/%s/%s/%s", defaultStorageURL, writerID, userID, readerID, recordType)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var cabEntry CABEntry
	resp, err := c.rawCall(ctx, req, &cabEntry)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	dentry, err := cabEntry.decode()
	if err != nil {
		return nil, err
	}

	var privKey [32]byte
	copy(privKey[:], c.PrivateKey)

	ak, good := box.Open(nil, dentry.eak, &dentry.nonce, &dentry.authorizerPublicKey, &privKey)
	if !good {
		return nil, errors.New("access key decryption failure")
	}

	c.akCache[cacheKey] = ak
	return ak, nil
}

// decryptRecord modifies a record in-place, decrypting all data fields
// using an access key granted by an authorizer.
func (c *Client) decryptRecord(ctx context.Context, record *Record) error {
	var ak [32]byte
	akSlice, err := c.getAccessKey(ctx, record.Meta.WriterID, record.Meta.UserID, c.ClientID, record.Meta.Type)
	if err != nil {
		return err
	}
	copy(ak[:], akSlice)

	for k, v := range record.Data {
		e, err := decodeEncryptedField(v)
		if err != nil {
			return err
		}

		var dk [32]byte
		dkSlice, ok := secretbox.Open(nil, e.edk, &e.edkN, &ak)
		if !ok {
			return errors.New("decryption of data key failed")
		}
		copy(dk[:], dkSlice)

		field, ok := secretbox.Open(nil, e.ef, &e.efN, &dk)
		if !ok {
			return errors.New("decryption of field data failed")
		}

		record.Data[k] = string(field)
	}

	return nil
}
