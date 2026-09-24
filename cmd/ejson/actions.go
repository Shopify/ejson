package main

import (
	"fmt"
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

func decryptAction(args []string, keydir, userSuppliedPrivateKey, outFile string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	decrypted, err := ejson.DecryptFile(args[0], keydir, userSuppliedPrivateKey)
	if err != nil {
		return err
	}

	if outFile == "" {
		_, err = os.Stdout.Write(decrypted)
		return err
	}
	// Restrict new files without changing existing destinations' permissions.
	target, err := os.OpenFile(outFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = target.Write(decrypted)
	if cerr := target.Close(); err == nil {
		err = cerr
	}
	return err
}

func keygenAction(_ []string, keydir string, wFlag bool) error {
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return err
	}

	if wFlag {
		keyFile := fmt.Sprintf("%s/%s", keydir, pub)
		// Keep new keys owner-read-only without granting group access.
		err := writeFile(keyFile, append([]byte(priv), '\n'), 0o400)
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
	writeFile = os.WriteFile
)
