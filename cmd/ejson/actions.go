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
	target, err := openOutput(outFile)
	if err != nil {
		return err
	}
	_, err = target.Write(decrypted)
	if cerr := target.Close(); err == nil {
		err = cerr
	}
	return err
}

// openOutput opens the plaintext destination with the same flags as os.Create,
// except that truncation waits until a regular file owned by the caller has been
// restricted to mode 0600, so files created by earlier versions are no longer
// left readable by others. A regular file owned by another user keeps its
// permissions, and non-regular targets such as /dev/null are written unchanged.
func openOutput(outFile string) (*os.File, error) {
	f, err := os.OpenFile(outFile, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := restrictOutput(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func restrictOutput(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if ownedByCaller(info) {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("restricting permissions of %s: %w", f.Name(), err)
		}
	}
	return f.Truncate(0)
}

func keygenAction(_ []string, keydir string, wFlag bool) error {
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return err
	}

	if wFlag {
		keyFile := fmt.Sprintf("%s/%s", keydir, pub)
		// Only the creating user needs the private key. On macOS every local
		// account shares the staff group, so group read would expose it.
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
