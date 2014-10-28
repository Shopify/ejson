require 'json'

require 'ejson'
require 'ejson/encryption'

module EJSON

  class Data
    def initialize(data, pubkey)
      @data, @pubkey = data, pubkey
    end

    def encrypt
      encrypter = EJSON::Encrypter.new(@pubkey)
      encrypt_subtree(encrypter, @data)
    end

    def decrypt(keydir)
      decrypter = EJSON::Decrypter.new(@pubkey, keydir)
      decrypt_subtree(decrypter, @data)
    end

    private

    def encrypt_subtree(encrypter, data, name="")
      case data
      when Hash
        Hash[ data.map { |k,v| [k, encrypt_subtree(encrypter, v, k)] } ]
      when Array
        data.map { |d| encrypt_subtree(encrypter, d, name) }
      when String
        name =~ EJSON::COMMENT ? data : encrypter.dump(data)
      else
        data
      end
    end

    def decrypt_subtree(decrypter, data, name="")
      case data
      when Hash
        Hash[ data.map { |k,v| [k, decrypt_subtree(decrypter, v, k)] } ]
      when Array
        data.map { |d| decrypt_subtree(decrypter, d, name) }
      when String
        name =~ EJSON::COMMENT ? data : decrypter.load(data)
      else
        data
      end
    end

  end

end
