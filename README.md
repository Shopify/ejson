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

#### 3) Decrypt the file:

     ejson decrypt -k ~/.keys/ejson.priv.pem -p config/ejson.pub.pem secrets.production.ejson > secrets.production.json

Unlike encrypt, decrypt doesn't update the file in-place; it prints the
decrypted contents to stdout. It also requires access to the private key
created in step 1.

#### See `ejson help` for more information.

## Custom keypair:

We use a single keypair internally; the default public key is fetched from S3
on each run. However, you can generate your own keypair like so:

    mkdir config && cd config
    openssl req -x509 -nodes -days 100000 -newkey rsa:2048 -keyout privatekey.pem -out publickey.pem -subj '/'

`publickey.pem` and `privatekey.pem` are created. Move `privatekey.pem`
somewhere more secure.

    mkdir -p ~/.keys
    mv config/privatekey.pem ~/.keys/ejson.pem

Then you can encrypt like:

    ejson encrypt -p config/publickey.pem secrets.ejson

