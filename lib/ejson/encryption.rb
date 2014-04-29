require 'openssl'
require 'base64'

class EJSON

  class Encryption
    PublicKeyMissing = Class.new(StandardError)
    PrivateKeyMissing = Class.new(StandardError)
    ExpectedEncryptedString = Class.new(StandardError)

    def initialize(public_key_pem, private_key_pem)
      raise PublicKeyMissing unless public_key_pem
      @public_key_x509 = load_public_key(public_key_pem)
      if private_key_pem
        @private_key_rsa = load_private_key(private_key_pem)
      end
    end

    ENCRYPTED = /\AENC\[(.*)\]\n*\z/m

    def load(str)
      if str =~ ENCRYPTED
        decrypt_string($1)
      else
        raise ExpectedEncryptedString
      end
    end

    def dump(str)
      if str =~ ENCRYPTED
        str
      else
        "ENC[#{encrypt_string(str)}]"
      end
    end

    private

    def encrypt_string(plaintext)
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      bin = OpenSSL::PKCS7.encrypt([@public_key_x509], plaintext, cipher, OpenSSL::PKCS7::BINARY).to_der
      Base64.encode64(bin).tr("\n",'')
    end

    def decrypt_string(ciphertext)
      raise PrivateKeyMissing unless @private_key_rsa
      bin = Base64.decode64(ciphertext)
      pkcs7 = OpenSSL::PKCS7.new(bin)
      pkcs7.decrypt(@private_key_rsa, @public_key_x509)
    end

    def load_public_key(public_key_pem)
      OpenSSL::X509::Certificate.new(public_key_pem)
    end

    def load_private_key(private_key_pem)
      OpenSSL::PKey::RSA.new(private_key_pem)
    end

  end
end
