package json

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestWalker(t *testing.T) {
	action := func(a []byte) ([]byte, error) {
		return []byte{'E'}, nil
	}

	Convey("Walker passes the provided test-cases", t, func() {
		for _, tc := range testCases {
			walker := Walker{Action: action}
			act, err := walker.Walk([]byte(tc.in))
			So(err, ShouldBeNil)
			So(string(act), ShouldEqual, tc.out)
		}
	})
}

type testCase struct {
	in, out string
}

// "E" means encrypted.
var testCases = []testCase{
	{`{"a": "b"}`, `{"a": "E"}`},                     // encryption
	{`{"a" : "b"}`, `{"a" : "E"}`},                   // weird spacing
	{` {  "a"  :"b" } `, ` {  "a"  :"E"}`},           // we could but don't preserve trailing spaces
	{`{"_a": "b"}`, `{"_a": "b"}`},                   // commenting
	{`{"a": "b", "c": "d"}`, `{"a": "E", "c": "E"}`}, // order-dependence
	{`{"a": 1}`, `{"a": 1}`},                         // numbers
	{`{"a": true}`, `{"a": true}`},                   // booleans
	{`{"a": ["b", "c"]}`, `{"a": ["E", "E"]}`},       // encrypting arrays
	{`{"_a": ["b", "c"]}`, `{"_a": ["b", "c"]}`},     // commenting arrays
	{`{"a": {"b": "c"}}`, `{"a": {"b": "E"}}`},       // nesting
	{`{"a": {"_b": "c"}}`, `{"a": {"_b": "c"}}`},     // nested comment
	{`{"_a": {"b": "c"}}`, `{"_a": {"b": "E"}}`},     // comments don't inherit
}
