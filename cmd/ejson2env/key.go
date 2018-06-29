package main

import (
	"io"
	"io/ioutil"
	"strings"
)

// readKey reads the contents of the passed reader, and
// strips any preceding or ending whitespace.
func readKey(reader io.Reader) (string, error) {
	b, err := ioutil.ReadAll(reader)
	if nil != err {
		return "", err
	}

	return strings.TrimSpace(string(b)), nil
}
