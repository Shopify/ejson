//go:build !unix

package main

import "os"

// Ownership is not checked on platforms without POSIX file ownership.
var ownedByCaller = func(os.FileInfo) bool { return true }
