package json

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
func ExtractPublicKey(data []byte) (key [32]byte, err error) {
	var (
		obj map[string]interface{}
		ks  string
		ok  bool
		bs  []byte
	)
	err = json.Unmarshal(data, &obj)
	if err != nil {
		return
	}
	k, ok := obj[PublicKeyField]
	if !ok {
		goto missing
	}
	ks, ok = k.(string)
	if !ok {
		goto invalid
	}
	if len(ks) != 64 {
		goto invalid
	}
	bs, err = hex.DecodeString(ks)
	if err != nil {
		goto invalid
	}
	if len(bs) != 32 {
		goto invalid
	}
	copy(key[:], bs)
	return
missing:
	err = ErrPublicKeyMissing
	return
invalid:
	err = ErrPublicKeyInvalid
	return
}

func ExtractPublicKeyArray(data []byte) (keys [][32]byte, err error) {
	var (
		obj []map[string]interface{}
		ks []string
		bs [][]byte
		ksAppendable string
		bsAppendable []byte
		keyAppendable [32]byte
	)
	err = json.Unmarshal(data, &obj)
	if err != nil {
		fmt.Println("key.go: could not unmarshal onto array struct")
		return
	}
	for idx, innerObj := range obj {
		k, ok := innerObj[PublicKeyField]
		if !ok {
			goto missing
		}

		ksAppendable, ok = k.(string) //appending to ks
		if !ok {
			fmt.Println("1")
			goto invalid
		}
		if len(ksAppendable) != 64 {
			fmt.Println("2")
			goto invalid
		}
		ks = append(ks, k.(string))

		bsAppendable, err = hex.DecodeString(ks[idx]) //appending to bs
		if err != nil {
			fmt.Println("3")
			goto invalid
		}
		if len(bsAppendable) != 32 {
			fmt.Println("4")
			goto invalid
		}
		bs = append(bs, bsAppendable)
		
		copy(keyAppendable[:], bs[idx])
		keys = append(keys, keyAppendable)
		continue

	missing:
		err = ErrPublicKeyMissing
		return
	invalid:
		err = ErrPublicKeyInvalid
		return
	}
	return keys, err
}
