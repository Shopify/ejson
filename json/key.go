package json

import (
	"encoding/hex"
	"encoding/json"
	"errors"
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
// parses it into a key usable with the crypto library.
func ExtractPublicKey(data []byte) (*[32]byte, error) {
	var obj map[string]interface{}
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return nil, err
	}
	k, ok := obj[PublicKeyField]
	if !ok {
		return nil, ErrPublicKeyMissing
	}
	ks, ok := k.(string)
	if !ok {
		return nil, ErrPublicKeyInvalid
	}
	if len(ks) != 64 {
		return nil, ErrPublicKeyInvalid
	}
	bs, err := hex.DecodeString(ks)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}
	if len(bs) != 32 {
		return nil, ErrPublicKeyInvalid
	}
	var key [32]byte
	copy(key[:], bs)
	return &key, nil
}
