require_relative 'helper'

require 'ejson/encryption'

class EncryptionTest < MiniTest::Test

  def test_encrypter
    enc = EJSON::Encrypter.new(pubkey_text)
    output = enc.dump("test")
    output =~ /EJ\[1,(MIIB.*)\]/
    ciphertext = $1

    pkcs7 = OpenSSL::PKCS7.new(Base64.decode64(ciphertext))
    assert_equal "test", pkcs7.decrypt(privkey, pubkey)
  end

  def test_decrypter
    cipher = OpenSSL::Cipher::AES.new(256, :CBC)
    bin = OpenSSL::PKCS7.encrypt([pubkey], "test", cipher, OpenSSL::PKCS7::BINARY).to_der
    ciphertext = Base64.encode64(bin).tr("\n",'')
    input = "EJ[1,#{ciphertext}]"

    dec = EJSON::Decrypter.new(pubkey_text, keydir)
    assert_equal "test", dec.load(input)
  end

  def test_roundtrip
    enc = EJSON::Encrypter.new(pubkey_text)
    dec = EJSON::Decrypter.new(pubkey_text, keydir)

    ciphertext = enc.dump("test")
    assert_equal "test", dec.load(ciphertext)
  end

  def test_decrypt_with_missing_key
    assert_raises EJSON::MissingPrivateKey do
      EJSON::Decrypter.new(pubkey_text(:b), keydir)
    end
  end

end
