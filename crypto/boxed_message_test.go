package crypto

import (
	"crypto/sha512"
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
			So(IsBoxedMessage([]byte("EJ[2:12345678901234567890123456789012345678901234:12345678901234567890123456789012:a:162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be]")), ShouldBeTrue)
		})
	})
}

func TestBoxedMessageSchemaVersion2(t *testing.T) {
	Convey("BoxedMessage", t, func() {
		pk := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		nonce := [24]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
		wire := "EJ[2:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:YQ==:1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75]"
		hash := sha512.New()
		hash.Write([]byte("a"))
		hashSum := hash.Sum(nil)

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
				Identity:        hashSum,
			}
			So(string(bm.Dump()), ShouldEqual, wire)
		})
	})
}
