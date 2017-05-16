// Package ejson implements the primary interface to interact with ejson
// documents and keypairs. The CLI implemented by cmd/ejson is a fairly thin
// wrapper around this package.
package ejson

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"./crypto"
	"./json"
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

//TODO: update documentation here
// Encrypt reads all contents from 'in', extracts the pubkey
// and performs the requested encryption operation, writing
// the resulting data to 'out'.
// Returns the number of bytes written and any error that might have
// occurred.
func Encrypt(in io.Reader, out io.Writer) (int, error) {
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return -1, err
	}

	pubkey, err := json.ExtractPublicKey(data)
	if err != nil {
		return -1, err
	}

	newdata, err := encryptWithPubkey(pubkey, data, out)
	if err != nil {
		return -1, err
	}

	return out.Write(newdata)
}

func EncryptArray(in io.Reader, out io.Writer) (int, error) {
	var buf bytes.Buffer
	buf.Write([]byte("["))

	data, err := ioutil.ReadAll(in)
	if err != nil {
		return -1, err
	}

	pubkeys, err := json.ExtractPublicKeyArray(data)
	if err != nil {
		return -1, err
	}

	objects := splitJSONArray(data)
	for idx, pubkey := range pubkeys {
		newdata, err := encryptWithPubkey(pubkey, objects[idx], out)
		if err != nil {
			//Write anything to stderr?
			buf.Write(objects[idx])
		} else {
			buf.Write(newdata)
		}

		if (idx != len(pubkeys) - 1) {
			buf.Write([]byte(", "))
		}
	}
	buf.Write([]byte("]\n"))
	
	return out.Write(buf.Bytes())
}

func encryptWithPubkey(pubkey [32]byte, obj []byte, out io.Writer) ([]byte, error) {
	var myKP crypto.Keypair
	if err := myKP.Generate(); err != nil {
		return nil, err
	}

	encrypter := myKP.Encrypter(pubkey)
	walker := json.Walker{
		Action: encrypter.Encrypt,
	}

	newdata, err := walker.Walk(obj)

	return newdata, err
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
	if (err != nil) && (err.Error() == "json: cannot unmarshal array into Go value of type map[string]interface {}") {
		outBuffer.Reset()
		file.Seek(0, 0)
		written, err = EncryptArray(file, &outBuffer)
	}
	if err != nil {
		return -1, err
	}

	if err = file.Close(); err != nil {
		return -1, err
	}

	if err := ioutil.WriteFile(filePath, outBuffer.Bytes(), fileMode); err != nil {
		return -1, err
	}

	return written, nil
}

// decryptWithPubkey takes a public key, single json object, and the key path
// and returns the new decrypted data, or a non-nil error on failure
func decryptWithPubkey(pubkey [32]byte, obj []byte, out io.Writer, keydir string) ([]byte, error) {
	privkey, err := findPrivateKey(pubkey, keydir)
	if err != nil {
		return obj, err
	}

	myKP := crypto.Keypair{
		Public:  pubkey,
		Private: privkey,
	}

	decrypter := myKP.Decrypter()
	walker := json.Walker{
		Action: decrypter.Decrypt,
	}

	newdata, err := walker.Walk(obj)
	return newdata, err
}

//TODO: update documentation
// Decrypt reads an ejson stream from 'in' and writes the decrypted data to 'out'.
// The private key is expected to be under 'keydir'.
// Returns error upon failure, or nil on success.
func Decrypt(in io.Reader, out io.Writer, keydir string) error {
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}

	pubkey, err := json.ExtractPublicKey(data)
	if err != nil {
		return err
	}

	newdata, err := decryptWithPubkey(pubkey, data, out, keydir)
	if err != nil {
		return err
	}
	_, err = out.Write(newdata)

	return err
}

/* splitJSONArray takes a byte array and returns all inner json objects of the format:
		{
			"_public_key": "abc"
		}
	ASSUMES: JSON is not malformed, pubkey is in every outer json block, pubkey field is in top level
*/
func splitJSONArray(data []byte) (objects [][]byte) {
	dataString := string(data)
	pubkey := "_public_key"
	rightBrace := string("}")
	leftBrace := string("{")

	idxCurrentKey := strings.Index(dataString, pubkey)

	for {
		idxLeftBrace := -1
		rightBraceCount := 0
		for idxChar := len(dataString[:idxCurrentKey])-1; idxChar >= 0; idxChar-- {
			if (string(dataString[idxChar]) == rightBrace) {
				rightBraceCount += 1
			} else if (string(dataString[idxChar]) == leftBrace) {
				if (rightBraceCount == 0) {
					idxLeftBrace = idxChar
					break
				} else {
					rightBraceCount -= 1
				}
			}
		}

		idxRightBrace := -1
		leftBraceCount := 0
		for idxChar, char := range dataString[idxCurrentKey:] {
			if (string(char) == leftBrace) {
				leftBraceCount += 1
			} else if (string(char) == rightBrace) {
				if (leftBraceCount == 0) {
					idxRightBrace = idxChar + idxCurrentKey
					break
				} else {
					leftBraceCount -= 1
				}
			}
		}

		objects = append(objects, []byte(dataString[idxLeftBrace:idxRightBrace+1]))

		increment := strings.Index(dataString[idxRightBrace:], pubkey)
		if increment == -1 {
			break
		}

		idxCurrentKey = increment + idxRightBrace
	}
	return objects
}

// Same as decrypt except supports an ejson array
func DecryptArray(in io.Reader, out io.Writer, keydir string, immediate bool) error {
	var buf bytes.Buffer
	buf.Write([]byte("["))

	data, err := ioutil.ReadAll(in)
	if err != nil {
		return err
	}

	pubkeys, err := json.ExtractPublicKeyArray(data)
	if err != nil {
		return err
	}

	objects := splitJSONArray(data)
	for idx, pubkey := range pubkeys {
		newdata, err := decryptWithPubkey(pubkey, objects[idx], out, keydir)
		if err != nil {
			//Write anything to stderr?
			buf.Write(objects[idx])
		} else {
			if immediate {
				_, err = out.Write(newdata)
				_, _ = out.Write([]byte("\n"))
				return err
			}
			buf.Write(newdata)
		}

		if (idx != len(pubkeys) - 1) {
			buf.Write([]byte(", "))
		}
	}
	buf.Write([]byte("]\n"))
	
	_, err = out.Write(buf.Bytes())
	return err 
}

// DecryptFile takes a path to an encrypted EJSON file and returns the data
// decrypted. The public key used to encrypt the values is embedded in the
// referenced document, and the matching private key is searched for in keydir.
// There must exist a file in keydir whose name is the public key from the
// EJSON document, and whose contents are the corresponding private key. See
// README.md for more details on this.
func DecryptFile(filePath, keydir string, immediate bool) ([]byte, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var outBuffer bytes.Buffer

	err = Decrypt(file, &outBuffer, keydir)
	if (err != nil) && (err.Error() == "json: cannot unmarshal array into Go value of type map[string]interface {}") {
		outBuffer.Reset()
		file.Seek(0, 0)
		err = DecryptArray(file, &outBuffer, keydir, immediate)
	}

	return outBuffer.Bytes(), err
}

func findPrivateKey(pubkey [32]byte, keydir string) (privkey [32]byte, err error) {
	keyFile := fmt.Sprintf("%s/%x", keydir, pubkey)
	var fileContents []byte
	fileContents, err = ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("couldn't read key file (%s)", err.Error())
		return
	}

	bs, err := hex.DecodeString(strings.TrimSpace(string(fileContents)))
	if err != nil {
		return
	}

	if len(bs) != 32 {
		err = fmt.Errorf("invalid private key retrieved from keydir")
		return
	}

	copy(privkey[:], bs)
	return
}
