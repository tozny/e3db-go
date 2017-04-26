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

func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

const nonceSize = 24

type nonce *[nonceSize]byte

// makeNonce loads an existing nonce from a byte array.
func makeNonce(b []byte) nonce {
	n := [nonceSize]byte{}
	copy(n[:], b)
	return &n
}

func randomNonce() nonce {
	b := [nonceSize]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		// we don't expect this to fail
		panic("random number generation failed")
	}

	return &b
}

// decodeNonce constructs a nonce from a Base64URL encoded string
// containing a 192-bit nonce, returning an error if the decode
// operation fails.
func decodeNonce(s string) (nonce, error) {
	bytes, err := base64Decode(s)
	if err != nil {
		return nil, err
	}

	return makeNonce(bytes), nil
}

const secretKeySize = 32

type secretKey *[secretKeySize]byte

// randomSecretKey generates a random secret key.
func randomSecretKey() secretKey {
	key := &[secretKeySize]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		// we don't expect this to fail
		panic("random number generation failed")
	}

	return key
}

// makeSecretKey loads an existing secret key from a byte array.
func makeSecretKey(b []byte) secretKey {
	key := [secretKeySize]byte{}
	copy(key[:], b)
	return &key
}

// secretBoxEncryptToBase64 uses an NaCl secret_box to encrypt a byte
// slice with the given secret key and a random nonce,
// returning the Base64URL encoded ciphertext and nonce.
func secretBoxEncryptToBase64(data []byte, key secretKey) (string, string) {
	n := randomNonce()
	box := secretbox.Seal(nil, data, n, key)
	return base64Encode(box), base64Encode(n[:])
}

// secretBoxDecryptFromBase64 uses NaCl secret_box to decrypt a
// string containing ciphertext along with the associated
// nonce, both Base64URL encoded. Returns the ciphertext bytes,
// or an error if the authentication check fails when decrypting.
func secretBoxDecryptFromBase64(ciphertext, nonce string, key secretKey) ([]byte, error) {
	ciphertextBytes, err := base64Decode(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := base64Decode(nonce)
	if err != nil {
		return nil, err
	}

	n := makeNonce(nonceBytes)
	plaintext, ok := secretbox.Open(nil, ciphertextBytes, n, key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

const publicKeySize = 32
const privateKeySize = 32

type publicKey *[publicKeySize]byte
type privateKey *[privateKeySize]byte

func generateKeyPair() (publicKey, privateKey, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

func makePublicKey(b []byte) publicKey {
	key := [publicKeySize]byte{}
	copy(key[:], b)
	return &key
}

// decodePublicKey decodes a public key from a Base64URL encoded
// string containing a 256-bit Curve25519 public key, returning an
// error if the decode operation fails.
func decodePublicKey(s string) (publicKey, error) {
	bytes, err := base64Decode(s)
	if err != nil {
		return nil, err
	}

	return makePublicKey(bytes), nil
}

func encodePublicKey(k publicKey) string {
	return base64Encode(k[:])
}

func makePrivateKey(b []byte) privateKey {
	key := [privateKeySize]byte{}
	copy(key[:], b)
	return &key
}

// decodePrivateKey decodes a private key from a Base64URL encoded
// string containing a 256-bit Curve25519 private key, returning an
// error if the decode operation fails.
func decodePrivateKey(s string) (privateKey, error) {
	bytes, err := base64Decode(s)
	if err != nil {
		return nil, err
	}

	return makePrivateKey(bytes), nil
}

func encodePrivateKey(k privateKey) string {
	return base64Encode(k[:])
}

func boxEncryptToBase64(data []byte, pubKey publicKey, privKey privateKey) (string, string) {
	n := randomNonce()
	ciphertext := box.Seal(nil, data, n, pubKey, privKey)
	return base64Encode(ciphertext), base64Encode(n[:])
}

func boxDecryptFromBase64(ciphertext, nonce string, pubKey publicKey, privKey privateKey) ([]byte, error) {
	ciphertextBytes, err := base64Decode(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := base64Decode(nonce)
	if err != nil {
		return nil, err
	}

	n := makeNonce(nonceBytes)
	plaintext, ok := box.Open(nil, ciphertextBytes, n, pubKey, privKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

func (c *Client) getAKCache(akID akCacheKey) (secretKey, bool) {
	if c.akCache == nil {
		c.akCache = make(map[akCacheKey]secretKey)
	}

	k, ok := c.akCache[akID]
	return k, ok
}

func (c *Client) putAKCache(akID akCacheKey, k secretKey) {
	if c.akCache == nil {
		c.akCache = make(map[akCacheKey]secretKey)
	}

	c.akCache[akID] = k
}

type getEAKResponse struct {
	EAK                 string    `json:"eak"`
	AuthorizerID        string    `json:"authorizer_id"`
	AuthorizerPublicKey clientKey `json:"authorizer_public_key"`
}

type putEAKRequest struct {
	EAK string `json:"eak"`
}

// TODO: Distinguish between HTTP errors like "NotFound" vs. actual unexpected
// errors so we can figure out if we should generate a new AK.
func (c *Client) getAccessKey(ctx context.Context, writerID, userID, readerID, recordType string) (secretKey, error) {
	akID := akCacheKey{writerID, userID, recordType}
	if ak, ok := c.getAKCache(akID); ok {
		return ak, nil
	}

	u := fmt.Sprintf("%s/access_keys/%s/%s/%s/%s", c.apiURL(), writerID, userID, readerID, recordType)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var getEAK getEAKResponse
	resp, err := c.rawCall(ctx, req, &getEAK)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			if httpErr.StatusCode == http.StatusNotFound {
				return nil, nil
			}
		}

		return nil, err
	}

	defer resp.Body.Close()

	fields := strings.SplitN(getEAK.EAK, ".", 2)
	if len(fields) != 2 {
		return nil, errors.New("invalid access key format")
	}

	authorizerPublicKey, err := decodePublicKey(getEAK.AuthorizerPublicKey.Curve25519)
	if err != nil {
		return nil, err
	}

	akBytes, err := boxDecryptFromBase64(fields[0], fields[1], authorizerPublicKey, c.PrivateKey)
	if err != nil {
		return nil, errors.New("access key decryption failure")
	}

	ak := makeSecretKey(akBytes)
	c.putAKCache(akID, ak)
	return ak, nil
}

func (c *Client) putAccessKey(ctx context.Context, writerID, userID, readerID, recordType string, ak secretKey) error {
	readerPubKey, err := c.getClientKey(ctx, readerID)
	if err != nil {
		return err
	}

	eak, eakN := boxEncryptToBase64(ak[:], readerPubKey, c.PrivateKey)
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(&putEAKRequest{EAK: fmt.Sprintf("%s.%s", eak, eakN)})

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
		c.akCache = make(map[akCacheKey]secretKey)
	}

	cacheKey := akCacheKey{writerID, userID, recordType}
	c.akCache[cacheKey] = ak

	return nil
}

// decryptRecord modifies a record in-place, decrypting all data fields
// using an access key granted by an authorizer.
func (c *Client) decryptRecord(ctx context.Context, record *Record) error {
	ak, err := c.getAccessKey(ctx, record.Meta.WriterID, record.Meta.UserID, c.ClientID, record.Meta.Type)
	if err != nil {
		return err
	}

	if ak == nil {
		return errors.New("cannot obtain access key")
	}

	for k, v := range record.Data {
		fields := strings.SplitN(v, ".", 4)
		if len(fields) != 4 {
			return errors.New("invalid record data format")
		}

		edk := fields[0]
		edkN := fields[1]
		ef := fields[2]
		efN := fields[3]

		dkBytes, err := secretBoxDecryptFromBase64(edk, edkN, ak)
		if err != nil {
			return err
		}

		dk := makeSecretKey(dkBytes)
		field, err := secretBoxDecryptFromBase64(ef, efN, dk)
		if err != nil {
			return errors.New("decryption of field data failed")
		}

		record.Data[k] = string(field)
	}

	return nil
}

// encryptRecord modifies a record in-place, encrypting all data fields
// using an access key granted by the authorizer.
func (c *Client) encryptRecord(ctx context.Context, record *Record) error {
	ak, err := c.getAccessKey(ctx, record.Meta.WriterID, record.Meta.UserID, c.ClientID, record.Meta.Type)
	if err != nil {
		return nil
	}

	// If no access key was present, create a random one and store it.
	if ak == nil {
		ak = randomSecretKey()
		err = c.putAccessKey(ctx, record.Meta.WriterID, record.Meta.UserID, c.ClientID, record.Meta.Type, ak)
		if err != nil {
			return err
		}
	}

	for k, v := range record.Data {
		dk := randomSecretKey()
		ef, efN := secretBoxEncryptToBase64([]byte(v), dk)
		edk, edkN := secretBoxEncryptToBase64(dk[:], ak)

		record.Data[k] = fmt.Sprintf("%s.%s.%s.%s", edk, edkN, ef, efN)
	}

	return nil
}
