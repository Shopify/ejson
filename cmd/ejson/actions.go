package main

import (
	"fmt"
	"io/ioutil"

	"github.com/burke/ej2"
)

func encryptAction(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("at least one file path must be given")
	}
	for _, filePath := range args {
		if err := ejson.EncryptFile(filePath); err != nil {
			return err
		}
	}
	return nil
}

func decryptAction(args []string, keydir string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	decrypted, err := ejson.DecryptFile(args[0], keydir)
	if err != nil {
		return err
	}

	fmt.Println(decrypted)
	return nil
}

func keygenAction(args []string, keydir string, wFlag bool) error {
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return err
	}

	if wFlag {
		keyFile := fmt.Sprintf("%s/%s", keydir, pub)
		err := writeFile(keyFile, []byte(priv), 0440)
		if err != nil {
			return err
		}
		fmt.Println(pub)
	} else {
		fmt.Printf("Public Key:\n%s\nPrivate Key:\n%s\n", pub, priv)
	}
	return nil
}

// for mocking in tests
var (
	writeFile = ioutil.WriteFile
)
