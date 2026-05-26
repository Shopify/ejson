# ejson

`ejson` is a utility for managing a collection of secrets in source control. The
secrets are encrypted using public-key cryptography. Legacy `v1` keys use
[NaCl](http://nacl.cr.yp.to/) [Box](http://nacl.cr.yp.to/box.html)
(Curve25519 + XSalsa20 + Poly1305). New hybrid `v3` keys use X25519 and
ML-KEM-768 to derive a shared secret with HKDF-SHA256, then encrypt values with
XChaCha20-Poly1305. Secrets are collected in a JSON file, in which all the
string values are encrypted. Public keys are embedded in the file, and the
decrypter looks up the corresponding private key from its local filesystem.

![demo](http://burkelibbey.s3.amazonaws.com/ejson-demo.gif)

The main benefits provided by `ejson` are:

* Secrets can be safely stored in a git repo.
* Changes to secrets are auditable on a line-by-line basis with `git blame`.
* Anyone with git commit access has access to write new secrets.
* Decryption access can easily be locked down to production servers only.
* Secrets change synchronously with application source (as opposed to secrets
  provisioned by Configuration Management).
* Simple, well-tested, easily-auditable source.

See [the manpages](https://shopify.github.io/ejson) for more technical documentation.

See [ejson2env](https://github.com/Shopify/ejson2env) for a useful tool to help with exporting
a portion of secrets as environment variables for environments/tools that require this pattern.

## Installation

You can download the `.deb` package from [Github Releases](https://github.com/Shopify/ejson/releases).

On development machines (64-bit linux or OS X), the recommended installation
method is via Homebrew:

```
brew tap shopify/shopify
brew install ejson
```

## Workflow

### 1: Create the Keydir

By default, EJSON looks for keys in `/opt/ejson/keys`. You can change this by
setting `EJSON_KEYDIR` or passing the `-keydir` option.

```
$ mkdir -p /opt/ejson/keys
```

> *For Mac OS users.* By default you won't have write permissions to `/opt/ejson` folder. Make sure to run the following command to grant these permissions:

```bash
sudo chown -R $(whoami) /opt/ejson
```

### 2: Generate a keypair

When called with `-w`, `ejson keygen` will write the keypair into the `keydir`
and print the public key. Without `-w`, it will print both keys to stdout. This
is useful if you have to distribute the key to multiple servers via
configuration management, etc.

```
$ ejson keygen
Public Key:
63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f
Private Key:
75b80b4a693156eb435f4ed2fe397e583f461f09fd99ec2bd1bdef0a56cf6e64
```

```
$ ejson keygen -w
53393332c6c7c474af603c078f5696c8fe16677a09a711bba299a6c1c1676a59
$ cat /opt/ejson/keys/5339*
888a4291bef9135729357b8c70e5a62b0bbe104a679d829cdbe56d46a4481aaf
```

By default, `keygen` still generates legacy `v1` keys. To generate a hybrid
post-quantum keypair, use `-scheme v3` or `-pqc`:

```
$ ejson keygen -scheme v3 -w
v3:<base64 X25519 public key + ML-KEM-768 encapsulation key>
$ ls /opt/ejson/keys
<32-character key id>
```

Hybrid public keys are intentionally much longer than legacy keys because the
full ML-KEM public key is embedded in the EJSON document. This preserves the
existing workflow where anyone who can edit the document can add new secrets
without access to the private keydir.

### 3: Create an `ejson` file

The format is described in more detail [later on](#format). For now, create a
file that looks something like this. Fill in the `<key>` with whatever you got
back in step 2.

Create this file as `test.ejson`:

```json
{
  "_public_key": "<key>",
  "_database_username": "1234username",
  "database_password": "1234password"
}
```

### 4: Encrypt the file

Running `ejson encrypt test.ejson` will encrypt any new plaintext keys in the
file and leave any existing encrypted keys or keys with property names prefixed with `_` untouched:

```json
{
  "_public_key": "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f",
  "_database_username": "1234username",
  "database_password": "EJ[1:WGj2t4znULHT1IRveMEdvvNXqZzNBNMsJ5iZVy6Dvxs=:kA6ekF8ViYR5ZLeSmMXWsdLfWr7wn9qS:fcHQtdt6nqcNOXa97/M278RX6w==]"
}
```

Try adding another plaintext secret to the file and run `ejson encrypt
test.ejson` again. The `database_password` field will not be changed, but the
new secret will be encrypted.

### 5: Decrypt the file

To decrypt the file, you must have the matching private key present in the
`keydir`. For legacy `v1` documents, the keydir filename is the 64-character
hex-encoded public key exactly as embedded in the `ejson` document, and the file
contains the similarly-encoded private key. For hybrid `v3` documents, the
keydir filename is a 32-character key ID derived from the public key, and the
file contains an `ejson-key v3` private key file with both X25519 and ML-KEM key
material. If you used `ejson keygen -w`, you've already got this covered.

Unlike `ejson encrypt`, which overwrites the specified files, `ejson decrypt`
only takes one file parameter, and prints the output to `stdout`:

```
$ ejson decrypt foo.ejson
{
  "_public_key": "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f",
  "_database_username": "1234username",
  "database_password": "1234password"
}
```

## Format

The `ejson` document format is simple, but there are a few points to be aware
of:

1. It's just JSON.
2. There *must* be a key at the top level named `_public_key`. For legacy `v1`
   documents, its value is a 32-byte hex-encoded (i.e. 64 ASCII byte) public key
   as generated by `ejson keygen`. For hybrid `v3` documents, its value begins
   with `v3:` and contains a base64-encoded X25519 public key plus ML-KEM-768
   encapsulation key.
3. Any string literal that isn't an object key will be encrypted by default (ie.
   in `{"a": "b"}`, `"b"` will be encrypted, but `"a"` will not.
4. Numbers, booleans, and nulls aren't encrypted.
5. If a key begins with an underscore, its corresponding value will not be
   encrypted. This is used to prevent the `_public_key` field from being
   encrypted, and is useful for implementing metadata schemes.
6. Underscores do not propagate downward. For example, in `{"_a": {"b": "c"}}`,
   `"c"` will be encrypted.
7. Encrypted values are schema-tagged. Legacy values use
   `EJ[1:<ephemeral public key>:<nonce>:<ciphertext>]`. Hybrid post-quantum
   values use
   `EJ[3:<ephemeral X25519 public key>:<ML-KEM ciphertext>:<nonce>:<ciphertext>]`.
   Existing `EJ[1:...]` values remain decryptable.

## See also

* If you use Capistrano for deployment you can use [capistrano-ejson](https://github.com/Shopify/capistrano-ejson) to automatically decrypt the secrets on deploy.
* If you use [pre-commit](https://pre-commit.com/), you can use it to automatically encrypt secrets on commit.
