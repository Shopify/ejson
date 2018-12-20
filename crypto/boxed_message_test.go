package crypto

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBoxedMessageRoundtripping(t *testing.T) {
	Convey("BoxedMessage", t, func() {
		// Test Schema 0 (unencrypted)
		pk0 := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		nonce0 := [24]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		wire0 := "EJ[0:this will stay unencrypted]"
		Convey("Dump", func() {
			// test the Dump function, which should just wrap the plaintext
			bm := boxedMessage{
				SchemaVersion:   0,
				EncrypterPublic: pk0,
				Nonce:           nonce0,
				Box:             []byte("this will stay unencrypted"),
			}
			So(string(bm.Dump()), ShouldEqual, wire0)
		})
		Convey("Load", func() {
			// test the Load function, which should unwrap the plaintext
			bm := boxedMessage{}
			err := bm.Load([]byte(wire0))
			So(err, ShouldBeNil)
			So(bm.EncrypterPublic, ShouldResemble, pk0)
			So(bm.Nonce, ShouldResemble, nonce0)
			So(bm.Box, ShouldResemble, []byte("this will stay unencrypted"))
		})

		// Test Schema 1
		pk1 := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		nonce1 := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		wire1 := "EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"
		Convey("Dump", func() {
			// test the Dump function, which should encrypt and wrap the message
			bm := boxedMessage{
				SchemaVersion:   1,
				EncrypterPublic: pk1,
				Nonce:           nonce1,
				Box:             []byte{3, 3, 3},
			}
			So(string(bm.Dump()), ShouldEqual, wire1)
		})
		Convey("Load", func() {
			// test the Dump function, which should decrypt and unwrap the message
			bm := boxedMessage{}
			err := bm.Load([]byte(wire1))
			So(err, ShouldBeNil)
			So(bm.EncrypterPublic, ShouldResemble, pk1)
			So(bm.Nonce, ShouldResemble, nonce1)
			So(bm.Box, ShouldResemble, []byte{3, 3, 3})
		})

		// Test all known formats
		Convey("IsBoxedMessage", func() {
			So(IsBoxedMessage([]byte(wire0)), ShouldBeTrue)
			So(IsBoxedMessage([]byte(wire1)), ShouldBeTrue)
			So(IsBoxedMessage([]byte("nope")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[]")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[0:unencrypted]")), ShouldBeTrue)
			So(IsBoxedMessage([]byte("EJ[1:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a]")), ShouldBeTrue) // we could be stricter than this.
		})
	})
}
