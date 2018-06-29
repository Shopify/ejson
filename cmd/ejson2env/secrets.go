package main

import (
	"bytes"
	"encoding/json"

	"github.com/Shopify/ejson"
)

// ReadSecrets reads the secrets for the passed filename and
// returns them as a map[string]interface{}.
func ReadSecrets(filename, keyDir, privateKey string) (map[string]interface{}, error) {
	var secrets map[string]interface{}

	decrypted, err := ejson.DecryptFile(filename, keyDir, privateKey)
	if nil != err {
		return secrets, err
	}

	decoder := json.NewDecoder(bytes.NewReader(decrypted))

	err = decoder.Decode(&secrets)
	if nil != err {
		return secrets, err
	}

	return secrets, nil
}
