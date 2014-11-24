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
				EncrypterPublic: &pk,
				Nonce:           &nonce,
				Box:             []byte{3, 3, 3},
			}
			So(string(bm.Dump()), ShouldEqual, wire)
		})
		Convey("Load", func() {
			bm := boxedMessage{}
			err := bm.Load([]byte(wire))
			So(err, ShouldBeNil)
			So(*bm.EncrypterPublic, ShouldResemble, pk)
			So(*bm.Nonce, ShouldResemble, nonce)
			So(bm.Box, ShouldResemble, []byte{3, 3, 3})
		})

		Convey("IsBoxedMessage", func() {
			So(IsBoxedMessage([]byte(wire)), ShouldBeTrue)
			So(IsBoxedMessage([]byte("nope")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[]")), ShouldBeFalse)
			So(IsBoxedMessage([]byte("EJ[1:a:a:a]")), ShouldBeTrue) // we could be stricter than this.
		})
	})
}
