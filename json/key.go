package json

import (
	"encoding/hex"
	stdjson "encoding/json"
	"errors"

	ejsoncrypto "github.com/Shopify/ejson/crypto"
)

const (
	// PublicKeyField is the key name at which the public key should be
	// stored in an EJSON document.
	PublicKeyField = "_public_key"
)

// ErrPublicKeyMissing indicates that the PublicKeyField key was not found
// at the top level of the JSON document provided.
var ErrPublicKeyMissing = errors.New("public key not present in EJSON file")

// ErrPublicKeyInvalid means that the PublicKeyField key was found, but the
// value could not be parsed into a valid key.
var ErrPublicKeyInvalid = errors.New("public key has invalid format")

// ExtractPublicKey finds the _public_key value in an EJSON document and
// parses it into a legacy v1 key usable with the crypto library.
func ExtractPublicKey(data []byte) (key [32]byte, err error) {
	ks, err := extractPublicKeyString(data)
	if err != nil {
		return key, err
	}

	if len(ks) != 64 {
		return key, ErrPublicKeyInvalid
	}
	bs, err := hex.DecodeString(ks)
	if err != nil {
		return key, ErrPublicKeyInvalid
	}
	if len(bs) != 32 {
		return key, ErrPublicKeyInvalid
	}
	copy(key[:], bs)
	return key, nil
}

// ExtractCryptoPublicKey finds the _public_key value in an EJSON document and
// parses it into a schema-aware key usable with the crypto library.
func ExtractCryptoPublicKey(data []byte) (ejsoncrypto.PublicKey, error) {
	ks, err := extractPublicKeyString(data)
	if err != nil {
		return nil, err
	}
	key, err := ejsoncrypto.ParsePublicKeyString(ks)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}
	return key, nil
}

func extractPublicKeyString(data []byte) (string, error) {
	var obj map[string]interface{}
	if err := stdjson.Unmarshal(data, &obj); err != nil {
		return "", err
	}
	k, ok := obj[PublicKeyField]
	if !ok {
		return "", ErrPublicKeyMissing
	}
	ks, ok := k.(string)
	if !ok {
		return "", ErrPublicKeyInvalid
	}
	return ks, nil
}
