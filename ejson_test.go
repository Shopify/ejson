package ejson

import (
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGenerateKeypair(t *testing.T) {
	Convey("GenerateKeypair", t, func() {
		pub, priv, err := GenerateKeypair()
		Convey("should return two strings that look key-like", func() {
			So(err, ShouldBeNil)
			So(pub, ShouldNotEqual, priv)
			So(pub, ShouldNotContainSubstring, "00000")
			So(priv, ShouldNotContainSubstring, "00000")
		})
	})
}

func setData(path string, data []byte) error {
	tmpFile, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = tmpFile.Write(data); err != nil {
		return err
	}
	tmpFile.Close()
	return nil
}

func TestEncryptFileInPlace(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "ejson_keys")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	tempFile, err := ioutil.TempFile(tempDir, "ejson_test")
	if err != nil {
		t.Fatal(err)
	}
	tempFile.Close()
	tempFileName := tempFile.Name()

	Convey("EncryptFileInPlace", t, func() {
		Convey("called with a non-existent file", func() {
			_, err := EncryptFileInPlace("/does/not/exist")
			Convey("should fail with ENOEXIST", func() {
				So(os.IsNotExist(err), ShouldBeTrue)
			})
		})

		Convey("called with an invalid JSON file", func() {
			setData(tempFileName, []byte(`{"a": "b"]`))
			_, err := EncryptFileInPlace(tempFileName)
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid character")
			})
		})

		Convey("called with an invalid keypair", func() {
			setData(tempFileName, []byte(`{"_public_key": "invalid"}`))
			_, err := EncryptFileInPlace(tempFileName)
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "public key has invalid format")
			})
		})

		Convey("called with a valid keypair", func() {
			setData(tempFileName, []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`))

			_, err := EncryptFileInPlace(tempFileName)
			output, err := ioutil.ReadFile(tempFileName)
			So(err, ShouldBeNil)
			Convey("should encrypt the file", func() {
				So(err, ShouldBeNil)
				match := regexp.MustCompile(`{"_public_key": "8d8.*", "a": "EJ.*"}`)
				So(match.Find(output), ShouldNotBeNil)
			})
		})

	})
}

func TestDecryptFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "ejson_keys")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	tempFile, err := ioutil.TempFile(tempDir, "ejson_test")
	if err != nil {
		t.Fatal(err)
	}
	tempFile.Close()
	tempFileName := tempFile.Name()
	validKeyPath := path.Join(tempDir, "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d")
	if err = ioutil.WriteFile(validKeyPath, []byte("c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87"), 0600); err != nil {
		t.Fatal(err)
	}

	Convey("DecryptFile", t, func() {
		Convey("called with a non-existent file", func() {
			_, err := DecryptFile("/does/not/exist", "/doesnt/matter")
			Convey("should fail with ENOEXIST", func() {
				So(os.IsNotExist(err), ShouldBeTrue)
			})
		})

		Convey("called with an invalid JSON file", func() {
			setData(tempFileName, []byte(`{"a": "b"]`))
			_, err := DecryptFile(tempFileName, tempDir)
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid character")
			})
		})

		Convey("called with an invalid keypair", func() {
			setData(tempFileName, []byte(`{"_public_key": "invalid"}`))
			_, err := DecryptFile(tempFileName, tempDir)
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "public key has invalid format")
			})
		})

		Convey("called with a valid keypair but no corresponding entry in keydir", func() {
			// notice the last 4 chars
			setData(tempFileName, []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3000000", "a": "b"}`))
			_, err := DecryptFile(tempFileName, tempDir)
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "couldn't read key file")
			})
		})

		Convey("called with a valid keypair and a corresponding entry in keydir", func() {
			setData(tempFileName, []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "EJ[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`))
			out, err := DecryptFile(tempFileName, tempDir)
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldBeNil)
				So(string(out), ShouldEqual, `{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)
			})
		})

	})
}
