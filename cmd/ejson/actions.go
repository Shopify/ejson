package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
)

func encryptAction(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("at least one file path must be given")
	}
	for _, filePath := range args {
		n, err := ejson.EncryptFileInPlace(filePath)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes to %s.\n", n, filePath)
	}
	return nil
}

func decryptAction(args []string, keydir, outFile string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	decrypted, err := ejson.DecryptFile(args[0], keydir)
	if err != nil {
		return err
	}

	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer func() { _ = target.Close() }()
	}

	_, err = target.Write(decrypted)
	return err
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
