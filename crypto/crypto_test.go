package crypto

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKeypairGeneration(t *testing.T) {
	var kp Keypair
	Convey("Generating keypairs", t, func() {
		err := kp.Generate()
		Convey("should generate something that looks vaguely key-like", func() {
			So(err, ShouldBeNil)
			So(kp.PublicString(), ShouldNotEqual, kp.PrivateString())
			So(kp.PublicString(), ShouldNotContainSubstring, "00000")
			So(kp.PrivateString(), ShouldNotContainSubstring, "00000")
		})
		Convey("should not leave the keys zeroed", func() {
			pubIsNull := kp.Public[0] == 0 && kp.Public[1] == 0 && kp.Public[2] == 0
			privIsNull := kp.Private[0] == 0 && kp.Private[1] == 0 && kp.Private[2] == 0
			So(pubIsNull, ShouldBeFalse)
			So(privIsNull, ShouldBeFalse)
		})
	})
}

func TestNonceGeneration(t *testing.T) {
	Convey("Generating a nonce", t, func() {
		Convey("should be unique", func() {
			n1, _ := genNonce()
			n2, _ := genNonce()
			So(n1, ShouldNotResemble, n2)
		})
		Convey("should complete successfully", func() {
			n, err := genNonce()
			So(err, ShouldBeNil)
			So(fmt.Sprintf("%x", n), ShouldNotContainSubstring, "00000")
		})
	})
}

func TestRoundtrip(t *testing.T) {
	var kpEphemeral, kpSecret Keypair
	kpEphemeral.Generate()
	kpSecret.Generate()

	Convey("Roundtripping", t, func() {
		encrypter := kpEphemeral.Encrypter(kpSecret.Public)
		decrypter := kpSecret.Decrypter()
		message := []byte("This is a test of the emergency broadcast system.")
		ct, err := encrypter.Encrypt(message)
		So(err, ShouldBeNil)
		ct2, err := encrypter.Encrypt(ct) // this one will leave the message unchanged
		So(err, ShouldBeNil)
		So(ct2, ShouldResemble, ct)
		pt, err := decrypter.Decrypt(ct2)
		So(err, ShouldBeNil)
		So(pt, ShouldResemble, message)
		So(pt, ShouldNotEqual, ct)
		So(len(ct), ShouldBeGreaterThan, len(pt))
	})
}

func ExampleEncrypter_Encrypt() {
	var ephemeral, recipient Keypair
	if err := ephemeral.Generate(); err != nil {
		panic(err)
	}
	if err := recipient.Generate(); err != nil {
		panic(err)
	}

	encrypter := ephemeral.Encrypter(recipient.Public)
	boxed, err := encrypter.Encrypt([]byte("this is my message"))
	fmt.Println(err == nil, len(boxed) > 0)
	// Output: true true
}

func ExampleDecrypter_Decrypt() {
	var ephemeral, recipient Keypair
	if err := ephemeral.Generate(); err != nil {
		panic(err)
	}
	if err := recipient.Generate(); err != nil {
		panic(err)
	}

	encrypter := ephemeral.Encrypter(recipient.Public)
	encrypted, err := encrypter.Encrypt([]byte("this is my message"))
	if err != nil {
		panic(err)
	}

	decrypter := recipient.Decrypter()
	plaintext, err := decrypter.Decrypt(encrypted)
	fmt.Println(string(plaintext), err)
	// Output: this is my message <nil>
}
