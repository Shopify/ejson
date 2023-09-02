package crypto

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBoxedMessageRoundtripping(t *testing.T) {
	Convey("BoxedMessage", t, func() {
		pk := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		nonce := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		wire := "EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwMD]"
		Convey("Dump", func() {
			bm := boxedMessage{
				SchemaVersion:   1,
				EncrypterPublic: pk,
				Nonce:           nonce,
				Box:             []byte{3, 3, 3},
			}
			So(string(bm.Dump()), ShouldEqual, wire)
		})
		Convey("Load", func() {
			bm := boxedMessage{}
			err := bm.Load([]byte(wire))
			So(err, ShouldBeNil)
			So(bm.EncrypterPublic, ShouldResemble, pk)
			So(bm.Nonce, ShouldResemble, nonce)
			So(bm.Box, ShouldResemble, []byte{3, 3, 3})
		})

		Convey("IsBoxedMessage", func() {
			So(IsBoxedMessage([]byte(wire)), ShouldBeTrue)
			So(IsBoxedMessage([]byte("nope")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[]")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[1:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a]")), ShouldBeTrue) // we could be stricter than this.
			So(IsBoxedMessage([]byte("EJ[2:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a:e14a700d884f652544e3b3af689010e98be66a855bc6cd2624ff7df4a3f098a8]")), ShouldBeTrue)
		})
	})
}

func TestBoxedMessageSchemaVersion2(t *testing.T) {
	Convey("BoxedMessage", t, func() {
		pk := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		nonce := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		identity := []byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
		wire := "EJ[2:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:YQ==:0303030303030303030303030303030303030303030303030303030303030303]"

		Convey("Load", func() {
			bm := boxedMessage{}
			err := bm.Load([]byte(wire))
			So(err, ShouldBeNil)
			So(bm.EncrypterPublic, ShouldResemble, pk)
			So(bm.Nonce, ShouldResemble, nonce)
			So(bm.Box, ShouldResemble, []byte("a"))
		})
		Convey("Dump", func() {
			bm := boxedMessage{
				SchemaVersion:   2,
				EncrypterPublic: pk,
				Nonce:           nonce,
				Box:             []byte("a"),
				Identity:        identity,
			}
			So(string(bm.Dump()), ShouldEqual, wire)
		})
	})
}
