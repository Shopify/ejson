# EJSON

EJSON is a small library to manage encrypted secrets using PKCS7 (asymmetric)
encryption. It provides a simple command interface to manage and update secrets
in a JSON file where keys are cleartext and values are encrypted.

## Installation

It's on rubygems. Just `gem install ejson` or add it to your `Gemfile`.

## Usage

#### 1) Create a `secrets.ejson`:

    echo '{"a": "b"}' > config/secrets.production.ejson

Keys in this file will remain in cleartext, while values will all be encrypted.
It can be arbitrarily nested.

#### 2) Encrypt the file:

    ejson

This updates `config/secrets.ejson` in place, encrypting any newly-added or
modified values that are not yet encrypted. `ejson` is short-hand for `ejson encrypt`.

By default, it uses a public key that you won't be able to decrypt (and
shouldn't use because we *can* decrypt it!). You can use your own by following
the "Custom keypair" directions below. Feel free to fork the gem to reference
your own keypair by default.

#### 3) Decrypt the file:

     ejson decrypt -k ~/.keys/ejson.priv.pem -p config/ejson.pub.pem secrets.production.ejson > secrets.production.json
     # OR
     ejson decrypt -i -k ~/.keys/ejson.priv.pem -p config/ejson.pub.pem secrets.production.ejson

Unlike encrypt, decrypt doesn't update the file in-place; it prints the
decrypted contents to stdout. It also requires access to the private key
created in step 1. By default, the secrets will be decrypted to stdout,
but passing the `-i` flag causes them to be overwritten to the input file.

#### See `ejson help` for more information.

## Custom keypair:

We use a single keypair internally; the default public key is fetched from S3
on each run. However, you can generate your own keypair like so:

    openssl req -x509 -nodes -days 100000 -newkey rsa:2048 -keyout privatekey.pem -out publickey.pem -subj '/'

`publickey.pem` and `privatekey.pem` are created. Move `privatekey.pem`
somewhere more private, and move `publickey.pem` somewhere more public.

Then you can encrypt like:

    ejson encrypt -p publickey.pem secrets.ejson

If you'd like to fork the gem to reference your own public key, that
information lives around line 10 of `lib/ejson/cli.rb`.

