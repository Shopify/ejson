# 1.6.0

* Security: `ejson decrypt -o` now creates new output files with mode `0600`, further restricted by the process umask, instead of `0666` before umask (usually `0644`). Existing output files keep their permissions and ownership and are updated in place.
* Compatibility: callers that need newly created output to be readable by another user or group must first create the destination with the intended ownership and permissions. Existing permissive output files need separate review; upgrading does not tighten them.
* Output-file close errors are now reported instead of being ignored.
* Security: `ejson keygen -w` now creates private-key files with mode `0400` instead of `0440`, removing default group read access while keeping owner-read-only access. Existing key files are not changed.

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
