# EJSON

EJSON is a small library to manage encrypted secrets using PKCS7 (asymmetric)
encryption. It provides a simple command interface to manage and update secrets
in a JSON file where keys are cleartext and values are encrypted.

## Installation

It's on rubygems. Just `gem install ejson` or add it to your `Gemfile`.

## Usage

#### 1) Generate a keypair

If you work at Shopify and are using this for a work-related project, ask the
Ops or Stack teams to generate you an `ejson` key.

Otherwise, run `ejson keygen`. It'll print two blocks in PEM format. The first
is the private key, which you should save to a file (starting with the BEGIN
RSA PRIVATE KEY line and ending with the END RSA PRIVATE KEY line, inclusive).

Copy the `-----BEGIN CERTIFICATE-----` line into your pastebuffer for now.

#### 2) Create a `secrets.ejson`:

    echo '{"a": "b"}' > config/secrets.production.ejson

Keys in this file will remain in cleartext, while values will all be encrypted.
It can be arbitrarily nested. All json types are supported, and only strings
will be encrypted.

Any keys whose names begin with an underscore will not be encrypted:

```json
{
  "secret": {
    "_decription": "super secret key",
    "value": "<encrypted value>"
  }
}
```

The file must have a toplevel key named `_public_key`, which should be an X509
certificate, in PEM format, for an RSA public key. This is what you copied to
your pastebuffer in step 1 above. You can paste it into the file now.

```json
{
  "_public_key": "-----BEGIN CERTIFICATE----\nMIID.......",
  "secret": "plaintext",
}
```

#### 3) Encrypt the file:

    ejson

This updates `config/secrets.production.ejson` in place, encrypting any newly-added or
modified values that are not yet encrypted. `ejson` is short-hand for `ejson encrypt`.

EJSON always uses the public key found in the `ejson` file to encrypt the secrets.

#### 4) Decrypt the file:

     ejson decrypt --keydir /path/to/keydir --out secrets.production.json secrets.production.ejson
     # OR
     ejson decrypt --keydir /path/to/keydir secrets.production.ejson

Unlike encrypt, decrypt doesn't update the file in-place; it prints the
decrypted contents to stdout (or a file, if provided with `--out`). It also
requires access to the private key created in step 1.

The `--keydir` parameter must be a path to a directory containing the private
key for the public key used to encrypt the `ejson` file.  The directory can
contain any number of `*.pem` files, and `ejson` will choose the correct one to
use automatically.

#### See `ejson help` for more information.
