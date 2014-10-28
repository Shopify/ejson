require 'json'

require 'ejson/serializer'
require 'ejson/data'

module EJSON

  COMMENT   = /\A_/
  ENCRYPTED = /\AEJ\[1,(.*)\]\n*\z/m

  MissingPublicKey        = Class.new(StandardError)
  MissingPrivateKey       = Class.new(StandardError)
  ExpectedEncryptedString = Class.new(StandardError)

  # raises EJSON::MissingPublicKey
  # raises JSON::ParserError
  # raises OpenSSL::X509::CertificateError
  def self.encrypt(json_text)
    unmarshaled, pubkey = EJSON::Serializer.load_json(json_text)
    data = EJSON::Data.new(unmarshaled, pubkey)
    encrypted = data.encrypt
    EJSON::Serializer.dump_json(encrypted)
  end

  # raises EJSON::MissingPrivateKey
  # raises EJSON::ExpectedEncryptedString
  def self.decrypt(json_text, keydir)
    unmarshaled, pubkey = EJSON::Serializer.load_json(json_text)
    data = EJSON::Data.new(unmarshaled, pubkey)
    decrypted = data.decrypt(keydir)
    EJSON::Serializer.dump_json(decrypted)
  end

end

