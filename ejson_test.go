package ejson

import (
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGenerateKeypair(t *testing.T) {
	Convey("GenerateKeypair returns two strings that look like keys", t, func() {
		pub, priv, err := GenerateKeypair()
		So(err, ShouldBeNil)
		So(pub, ShouldNotEqual, priv)
		So(pub, ShouldNotContainSubstring, "00000")
		So(priv, ShouldNotContainSubstring, "00000")
	})
}

func TestEncryptFileInPlace(t *testing.T) {
	getMode = func(p string) (os.FileMode, error) {
		return 0400, nil
	}
	defer func() { getMode = _getMode }()
	Convey("EncryptFileInPlace", t, func() {
		Convey("called with a non-existent file", func() {
			_, err := EncryptFileInPlace("/does/not/exist")
			Convey("should fail with ENOEXIST", func() {
				So(os.IsNotExist(err), ShouldBeTrue)
			})
		})

		Convey("called with an invalid JSON file", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{"a": "b"]`), nil
			}
			_, err := EncryptFileInPlace("/doesnt/matter")
			readFile = ioutil.ReadFile
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid character")
			})
		})

		Convey("called with an invalid keypair", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{"_public_key": "invalid"}`), nil
			}
			_, err := EncryptFileInPlace("/doesnt/matter")
			readFile = ioutil.ReadFile
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "public key has invalid format")
			})
		})

		Convey("called with a valid keypair", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`), nil
			}
			var output []byte
			writeFile = func(path string, data []byte, mode os.FileMode) error {
				output = data
				return nil
			}
			_, err := EncryptFileInPlace("/doesnt/matter")
			readFile = ioutil.ReadFile
			writeFile = ioutil.WriteFile
			Convey("should encrypt the file", func() {
				So(err, ShouldBeNil)
				match := regexp.MustCompile(`{"_public_key": "8d8.*", "a": "EJ.*"}`)
				So(match.Find(output), ShouldNotBeNil)
			})
		})

	})
}

func TestDecryptFile(t *testing.T) {
	Convey("DecryptFile", t, func() {
		Convey("called with a non-existent file", func() {
			_, err := DecryptFile("/does/not/exist", "/doesnt/matter")
			Convey("should fail with ENOEXIST", func() {
				So(os.IsNotExist(err), ShouldBeTrue)
			})
		})

		Convey("called with an JSON file containing unencrypted-but-encryptable secrets", func() {
			Convey("should fail with a scary message", nil)
		})

		Convey("called with an invalid JSON file", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{"a": "b"]`), nil
			}
			_, err := DecryptFile("/doesnt/matter", "/doesnt/matter")
			readFile = ioutil.ReadFile
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid character")
			})
		})

		Convey("called with an invalid keypair", func() {
			readFile = func(p string) ([]byte, error) {
				return []byte(`{"_public_key": "invalid"}`), nil
			}
			_, err := DecryptFile("/doesnt/matter", "/doesnt/matter")
			readFile = ioutil.ReadFile
			Convey("should fail", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "public key has invalid format")
			})
		})

		Convey("called with a valid keypair but no corresponding entry in keydir", func() {
			readFile = func(p string) ([]byte, error) {
				if p == "a" {
					return []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`), nil
				}
				return ioutil.ReadFile("/does/not/exist")
			}
			_, err := DecryptFile("a", "b")
			readFile = ioutil.ReadFile
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "couldn't read key file")
			})
		})

		Convey("called with a valid keypair and a corresponding entry in keydir", func() {
			readFile = func(p string) ([]byte, error) {
				if p == "a" {
					return []byte(`{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "EJ[1:KR1IxNZnTZQMP3OR1NdOpDQ1IcLD83FSuE7iVNzINDk=:XnYW1HOxMthBFMnxWULHlnY4scj5mNmX:ls1+kvwwu2ETz5C6apgWE7Q=]"}`), nil
				}
				return []byte("c5caa31a5b8cb2be0074b37c56775f533b368b81d8fd33b94181f79bd6e47f87"), nil
			}
			out, err := DecryptFile("a", "b")
			readFile = ioutil.ReadFile
			Convey("should fail and describe that the key could not be found", func() {
				So(err, ShouldBeNil)
				So(out, ShouldEqual, `{"_public_key": "8d8647e2eeb6d2e31228e6df7da3df921ec3b799c3f66a171cd37a1ed3004e7d", "a": "b"}`)
			})
		})

	})
}
