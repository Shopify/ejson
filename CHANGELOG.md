# 1.6.0

* Security: `ejson decrypt -o` now restricts the output file to mode `0600` before writing, for new and existing regular files. Previously new files used the process default (usually `0644`) and existing files kept whatever permissions they had.
* Breaking change: an existing output file owned by another user is refused and left unchanged, and group or world read access on an existing output file is removed. Callers that share the plaintext with another user or group must copy it to a destination with the intended ownership and permissions after decrypting. Non-regular targets such as `/dev/null` are unaffected. See the README's decrypt section.
* A failure to close the output file is now reported instead of exiting successfully with a partial file.

# 1.5.5

* Maintenance release.

# 1.5.4

* Bumps golang.org/x/crypto from 0.17.0 to 0.31.0

# 1.5.0

* Bump Go version and update dependencies
* Build static binaries

# 1.3.2

* Bump Go version and update dependencies

# 1.3.1

* Fix rubygems build for arm64.

# 1.2.2

* Bump various dependencies and rebuild releases with a modern Go version

# 1.2.1

* Bugfix: 1.2.0 introduced an issue in informational output formatting (no obvious security impact).
  This release simply fixes that bug.

# 1.2.0

* Moves error output from `stdout` to `stderr`.
* Various development hygiene changes; should be no user impact.

# 1.1.0

* Add `--key-from-stdin` flag, where a private key, assumed to match the file's public key, is read
  directly from stdin instead of looking up a match in the keydir.
