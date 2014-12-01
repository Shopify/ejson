// Package ejson implements the primary interface to interact with ejson
// documents and keypairs. The CLI implemented by cmd/ejson is a fairly thin
// wrapper around this package.
package ejson

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Shopify/ejson/crypto"
	"github.com/Shopify/ejson/json"
)

// GenerateKeypair is used to create a new ejson keypair. It returns the keys as
// hex-encoded strings, suitable for printing to the screen. hex.DecodeString
// can be used to load the true representation if necessary.
func GenerateKeypair() (pub string, priv string, err error) {
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		return "", "", err
	}
	return kp.PublicString(), kp.PrivateString(), nil
}

// EncryptFile takes a path to a file on disk, which must be a valid EJSON file
// (see README.md for more on what constitutes a valid EJSON file). Any
// encryptable-but-unencrypted fields in the file will be encrypted using the
// public key embdded in the file, and the resulting text will be written over
// the file present on disk.
func EncryptFile(filePath string) (int, error) {
	data, err := readFile(filePath)
	if err != nil {
		return -1, err
	}

	fileMode, err := getMode(filePath)
	if err != nil {
		return -1, err
	}

	var myKP crypto.Keypair
	if err := myKP.Generate(); err != nil {
		return -1, err
	}

	pubkey, err := json.ExtractPublicKey(data)
	if err != nil {
		return -1, err
	}

	encrypter := myKP.Encrypter(pubkey)
	walker := json.Walker{
		Action: encrypter.Encrypt,
	}

	newdata, err := walker.Walk(data)
	if err != nil {
		return -1, err
	}

	if err := writeFile(filePath, newdata, fileMode); err != nil {
		return -1, err
	}

	return len(newdata), nil
}

// DecryptFile takes a path to an encrypted EJSON file and decrypts it to
// STDOUT. If any keys in the file are encryptable but currently-unencrypted,
// ejson will print an error and exit non-zero, as this condition probably
// indicates that a plaintext secret was committed to source control, and
// requires manual intervention to rotate.
//
// The public key used to encrypt the values is embedded in the referenced
// document, and the matching private key is searched for in keydir. There must
// exist a file in keydir whose name is the public key from the EJSON document,
// and whose contents are the corresponding private key. See README.md for more
// details on this.
func DecryptFile(filePath, keydir string) (string, error) {
	data, err := readFile(filePath)
	if err != nil {
		return "", err
	}

	pubkey, err := json.ExtractPublicKey(data)
	if err != nil {
		return "", err
	}

	privkey, err := findPrivateKey(pubkey, keydir)
	if err != nil {
		return "", err
	}

	myKP := crypto.Keypair{
		Public:  pubkey,
		Private: privkey,
	}

	decrypter := myKP.Decrypter()
	walker := json.Walker{
		Action: decrypter.Decrypt,
	}

	newdata, err := walker.Walk(data)
	if err != nil {
		return "", err
	}

	return string(newdata), nil
}

func findPrivateKey(pubkey *[32]byte, keydir string) (*[32]byte, error) {
	keyFile := fmt.Sprintf("%s/%x", keydir, *pubkey)
	fileContents, err := readFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't read key file at %s, indicated by _public_key field in ejson file (%s)", keyFile, err.Error())
	}

	bs, err := hex.DecodeString(strings.TrimSpace(string(fileContents)))
	if err != nil {
		return nil, err
	}

	if len(bs) != 32 {
		return nil, fmt.Errorf("invalid private key retrieved from keydir")
	}

	var privkey [32]byte
	copy(privkey[:], bs)
	return &privkey, nil
}

// for mocking in tests
func _getMode(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode(), nil
}

// for mocking in tests
var (
	readFile  = ioutil.ReadFile
	writeFile = ioutil.WriteFile
	getMode   = _getMode
)
