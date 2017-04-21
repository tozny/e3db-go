//
// crypto.go --- E3db client crypto operations.
//
// Copyright (C) 2017, Tozny, LLC.
// All Rights Reserved.
//

package e3db

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const nonceSize = 24
const keySize = 32

func randomNonce() (*[nonceSize]byte, error) {
	nonce := [nonceSize]byte{}
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	return &nonce, nil
}

func randomKey() (*[keySize]byte, error) {
	key := [keySize]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	return &key, nil
}

type GetEAK struct {
	EAK                 string    `json:"eak"`
	AuthorizerID        string    `json:"authorizer_id"`
	AuthorizerPublicKey ClientKey `json:"authorizer_public_key"`
}

type decodedGetEAK struct {
	eak                 []byte
	nonce               [nonceSize]byte
	authorizerPublicKey [keySize]byte
}

func (e *GetEAK) decode() (*decodedGetEAK, error) {
	fields := strings.SplitN(e.EAK, ".", 2)
	var r decodedGetEAK
	var err error
	var nonceSlice, pubKSlice []byte

	if r.eak, err = base64.RawURLEncoding.DecodeString(fields[0]); err != nil {
		return nil, err
	}

	if nonceSlice, err = base64.RawURLEncoding.DecodeString(fields[1]); err != nil {
		return nil, err
	}
	copy(r.nonce[:], nonceSlice)

	if pubKSlice, err = base64.RawURLEncoding.DecodeString(e.AuthorizerPublicKey.Curve25519); err != nil {
		return nil, err
	}
	copy(r.authorizerPublicKey[:], pubKSlice)

	return &r, nil
}

type PutEAK struct {
	EAK string `json:"eak"`
}

func encodePutEAK(eak []byte, nonce *[nonceSize]byte) *PutEAK {
	return &PutEAK{
		EAK: base64.RawURLEncoding.EncodeToString(eak) + "." + base64.RawURLEncoding.EncodeToString(nonce[:]),
	}
}

type decodedField struct {
	edk  []byte
	edkN [nonceSize]byte
	ef   []byte
	efN  [nonceSize]byte
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

	u := fmt.Sprintf("%s/access_keys/%s/%s/%s/%s", c.apiURL(), writerID, userID, readerID, recordType)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var getEAK GetEAK
	resp, err := c.rawCall(ctx, req, &getEAK)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	dentry, err := getEAK.decode()
	if err != nil {
		return nil, err
	}

	privKey := [keySize]byte{}
	copy(privKey[:], c.PrivateKey)

	ak, good := box.Open(nil, dentry.eak, &dentry.nonce, &dentry.authorizerPublicKey, &privKey)
	if !good {
		return nil, errors.New("access key decryption failure")
	}

	c.akCache[cacheKey] = ak
	return ak, nil
}

func (c *Client) putAccessKey(ctx context.Context, writerID, userID, readerID, recordType string, ak []byte) error {
	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	readerPubKey, err := c.GetClientKey(ctx, readerID)
	if err != nil {
		return err
	}

	pubKey := [keySize]byte{}
	copy(pubKey[:], readerPubKey)
	privKey := [keySize]byte{}
	copy(privKey[:], c.PrivateKey)

	eak := box.Seal(nil, ak, nonce, &pubKey, &privKey)

	body := encodePutEAK(eak, nonce)
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(&body)

	u := fmt.Sprintf("%s/access_keys/%s/%s/%s/%s", c.apiURL(), writerID, userID, readerID, recordType)
	req, err := http.NewRequest("PUT", u, buf)
	if err != nil {
		return err
	}

	resp, err := c.rawCall(ctx, req, nil)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// TODO: Is this the best place to do this?
	if c.akCache == nil {
		c.akCache = make(map[AKCacheKey][]byte)
	}

	cacheKey := AKCacheKey{writerID, userID, recordType}
	c.akCache[cacheKey] = ak

	return nil
}

// decryptRecord modifies a record in-place, decrypting all data fields
// using an access key granted by an authorizer.
func (c *Client) decryptRecord(ctx context.Context, record *Record) error {
	akSlice, err := c.getAccessKey(ctx, record.Meta.WriterID, record.Meta.UserID, c.ClientID, record.Meta.Type)
	if err != nil {
		return err
	}
	ak := [keySize]byte{}
	copy(ak[:], akSlice)

	for k, v := range record.Data {
		e, err := decodeEncryptedField(v)
		if err != nil {
			return err
		}

		dkSlice, ok := secretbox.Open(nil, e.edk, &e.edkN, &ak)
		if !ok {
			return errors.New("decryption of data key failed")
		}
		dk := [keySize]byte{}
		copy(dk[:], dkSlice)

		field, ok := secretbox.Open(nil, e.ef, &e.efN, &dk)
		if !ok {
			return errors.New("decryption of field data failed")
		}

		record.Data[k] = string(field)
	}

	return nil
}
