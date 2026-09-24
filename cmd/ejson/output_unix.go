//go:build unix

package main

import (
	"os"
	"syscall"
)

// ownedByCaller reports whether the file belongs to the effective user. It is a
// variable so tests can exercise the other-owner path without a second account.
var ownedByCaller = func(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
