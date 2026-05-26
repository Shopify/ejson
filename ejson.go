// Package ejson implements the primary interface to interact with ejson
// documents and keypairs. The CLI implemented by cmd/ejson is a fairly thin
// wrapper around this package.
package ejson

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/Shopify/ejson/crypto"
	"github.com/Shopify/ejson/json"
)

// GenerateKeypair is used to create a new legacy v1 ejson keypair. It returns
// the keys as hex-encoded strings, suitable for printing to the screen.
// hex.DecodeString can be used to load the true representation if necessary.
func GenerateKeypair() (pub string, priv string, err error) {
	var kp crypto.Keypair
	if err := kp.Generate(); err != nil {
		return "", "", err
	}
	return kp.PublicString(), kp.PrivateString(), nil
}

// GenerateKeypairForScheme is used to create a new ejson keypair for the named
// scheme. The returned public key is suitable for the _public_key field. The
// returned private key is suitable for writing into the keydir under keyID.
func GenerateKeypairForScheme(scheme string) (pub string, priv string, keyID string, err error) {
	publicKey, privateKey, err := crypto.GenerateKeypairForScheme(scheme)
	if err != nil {
		return "", "", "", err
	}
	return publicKey.String(), privateKey.String(), publicKey.KeyID(), nil
}

// Encrypt reads all contents from 'in', extracts the pubkey
// and performs the requested encryption operation, writing
// the resulting data to 'out'.
// Returns the number of bytes written and any error that might have
// occurred.
func Encrypt(in io.Reader, out io.Writer) (int, error) {
	data, err := io.ReadAll(in)
	if err != nil {
		return -1, err
	}

	data, err = json.CollapseMultilineStringLiterals(data)
	if err != nil {
		return -1, err
	}

	pubkey, err := json.ExtractCryptoPublicKey(data)
	if err != nil {
		return -1, err
	}

	encrypter, err := crypto.NewMessageEncrypter(pubkey)
	if err != nil {
		return -1, err
	}
	walker := json.Walker{
		Action: encrypter.Encrypt,
	}

	newdata, err := walker.Walk(data)
	if err != nil {
		return -1, err
	}

	return out.Write(newdata)
}

// EncryptFileInPlace takes a path to a file on disk, which must be a valid EJSON file
// (see README.md for more on what constitutes a valid EJSON file). Any
// encryptable-but-unencrypted fields in the file will be encrypted using the
// public key embedded in the file, and the resulting text will be written over
// the file present on disk.
func EncryptFileInPlace(filePath string) (int, error) {
	var fileMode os.FileMode
	if stat, err := os.Stat(filePath); err == nil {
		fileMode = stat.Mode()
	} else {
		return -1, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return -1, err
	}

	var outBuffer bytes.Buffer

	written, err := Encrypt(file, &outBuffer)
	if err != nil {
		return -1, err
	}

	if err = file.Close(); err != nil {
		return -1, err
	}

	if err := os.WriteFile(filePath, outBuffer.Bytes(), fileMode); err != nil {
		return -1, err
	}

	return written, nil
}

// Decrypt reads an ejson stream from 'in' and writes the decrypted data to 'out'.
// The private key is expected to be under 'keydir'.
// Returns error upon failure, or nil on success.
func Decrypt(in io.Reader, out io.Writer, keydir string, userSuppliedPrivateKey string) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	pubkey, err := json.ExtractCryptoPublicKey(data)
	if err != nil {
		return err
	}

	privkey, err := findPrivateKey(pubkey, keydir, userSuppliedPrivateKey)
	if err != nil {
		return err
	}

	decrypter, err := crypto.NewMessageDecrypter(pubkey, privkey)
	if err != nil {
		return err
	}
	walker := json.Walker{
		Action: decrypter.Decrypt,
	}

	newdata, err := walker.Walk(data)
	if err != nil {
		return err
	}

	_, err = out.Write(newdata)

	return err
}

// DecryptFile takes a path to an encrypted EJSON file and returns the data
// decrypted. The public key used to encrypt the values is embedded in the
// referenced document, and the matching private key is searched for in keydir.
// For legacy v1 keys, the keydir filename is the public key. For v3 hybrid
// keys, the keydir filename is the public key's short key ID.
func DecryptFile(filePath, keydir string, userSuppliedPrivateKey string) ([]byte, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var outBuffer bytes.Buffer

	err = Decrypt(file, &outBuffer, keydir, userSuppliedPrivateKey)

	return outBuffer.Bytes(), err
}

func readPrivateKeyFromDisk(pubkey crypto.PublicKey, keydir string) (privkey string, err error) {
	keyFile := fmt.Sprintf("%s/%s", keydir, pubkey.KeyID())
	var fileContents []byte
	fileContents, err = os.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("couldn't read key file (%s)", err.Error())
		return
	}
	privkey = string(fileContents)
	return
}

func findPrivateKey(pubkey crypto.PublicKey, keydir string, userSuppliedPrivateKey string) (crypto.PrivateKey, error) {
	var privkeyString string
	if userSuppliedPrivateKey != "" {
		privkeyString = userSuppliedPrivateKey
	} else {
		var err error
		privkeyString, err = readPrivateKeyFromDisk(pubkey, keydir)
		if err != nil {
			return nil, err
		}
	}

	return crypto.ParsePrivateKeyForPublic(pubkey, []byte(privkeyString))
}
