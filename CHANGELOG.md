# 1.2.0

* Add `ejson2env` binary, which decrypts secrets from the `environment` member and prints them in
  a shell-executable format.

# 1.1.0

* Add `--key-from-stdin` flag, where a private key, assumed to match the file's public key, is read
  directly from stdin instead of looking up a match in the keydir.
