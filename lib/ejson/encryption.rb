require 'openssl'
require 'base64'

require 'ejson'

module EJSON

  class Encrypter

    def initialize(public_key)
      @public_key = OpenSSL::X509::Certificate.new(public_key)
    end

    def dump(str)
      return str if str =~ EJSON::ENCRYPTED
      "EJ[1,#{encrypt_string(str)}]"
    end

    private

    def encrypt_string(str)
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      bin = OpenSSL::PKCS7.encrypt([@public_key], str, cipher, OpenSSL::PKCS7::BINARY).to_der
      Base64.encode64(bin).tr("\n",'')
    end

  end

  class Decrypter

    # raises MissingPrivateKey
    def initialize(public_key, keydir)
      @public_key = OpenSSL::X509::Certificate.new(public_key)
      @private_key = find_priv_for_pub(@public_key, keydir)
    end

    def load(str)
      str =~ EJSON::ENCRYPTED or raise EJSON::ExpectedEncryptedString
      decrypt_string($1)
    end

    private

    def decrypt_string(ciphertext)
      bin = Base64.decode64(ciphertext)
      pkcs7 = OpenSSL::PKCS7.new(bin)
      pkcs7.decrypt(@private_key, @public_key)
    end

    def load_private_key(private_key)
      OpenSSL::PKey::RSA.new(get_pem(private_key))
    end

    # An RSA public key is mostly a very large integer N and an exponent E.
    # Comparing N is sufficient to find a matching cert.
    #
    # raises MissingPrivateKey
    def find_priv_for_pub(pubkey, keydir)
      public_n = pubkey.public_key.n
      fpaths = Dir.glob(File.join(keydir,"*.pem"))
      fpaths.each do |fpath|
        pkey = load_pem(File.read(fpath))
        next if is_public_key?(pkey)

        private_n = pkey.public_key.n
        if public_n == private_n
          return pkey
        end
      end
      raise MissingPrivateKey
    end

    def load_pem(pem)
      OpenSSL::PKey::RSA.new(pem)
    rescue OpenSSL::PKey::RSAError
      OpenSSL::X509::Certificate.new(pem)
    end

    def is_public_key?(obj)
      OpenSSL::X509::Certificate === obj
    end

  end

end
