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
		for _, tc := range walkTestCases {
			walker := Walker{Action: action}
			act, err := walker.Walk([]byte(tc.in))
			So(err, ShouldBeNil)
			So(string(act), ShouldEqual, tc.out)
		}
	})

	Convey("CollapseMultilineStringLiterals passes the provided test-cases", t, func() {
		for _, tc := range collapseTestCases {
			act, err := CollapseMultilineStringLiterals([]byte(tc.in))
			So(err, ShouldBeNil)
			So(string(act), ShouldEqual, tc.out)
		}
	})
}

type testCase struct {
	in, out string
}

// "E" means encrypted.
var walkTestCases = []testCase{
	{`{"a": "b"}`, `{"a": "E"}`},                     // encryption
	{`{"a" : "b"}`, `{"a" : "E"}`},                   // weird spacing
	{` {  "a"  :"b" } `, ` {  "a"  :"E" } `},         // trailing spaces
	{`{"a": "b"}` + "\n", `{"a": "E"}` + "\n"},       // trailing newline
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

var collapseTestCases = []testCase{
	{
		"{\"a\": \"b\r\nc\nd\"\r\n}", 
		"{\"a\": \"b\\r\\nc\\nd\"\r\n}",
	},
}
