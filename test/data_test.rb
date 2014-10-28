require_relative 'helper'

require 'ejson/data'

class DataTest < MiniTest::Test

  def test_roundtrip1
    input = {
      "_public_key" => pubkey_text,
      "_name1"      => "value1",
      "name2"       => "value2"
    }
    output = {
      "_public_key" => pubkey_text,
      "_name1"      => "value1",
      "name2"       => ENCRYPTED,
    }
    assert_roundtrip input, output
  end

  def test_roundtrip2
    input = {
      "_public_key" => pubkey_text,
      "secret1" => {
        "_description" => "desc",
        "rotation" => "rotation instructions",
        "_urls" => ["http://google.com"],
        "_severity" => "HIGH",
        "something" => ["test"],
        "secret" => "some api key"
      },
    }
    output = {
      "_public_key" => pubkey_text,
      "secret1" => {
        "_description" => "desc",
        "rotation" => ENCRYPTED,
        "_urls" => ["http://google.com"],
        "_severity" => "HIGH",
        "something" => [ENCRYPTED],
        "secret" => ENCRYPTED,
      },
    }
    assert_roundtrip input, output
  end

  def test_decrypt_raises_if_string_should_have_been_encrypted
    input = {
      "_public_key" => pubkey_text,
      "secret" => "plaintext"
    }
    data = EJSON::Data.new(input, pubkey_text)
    assert_raises EJSON::ExpectedEncryptedString do
      data.decrypt(keydir)
    end
  end

  def test_encrypt_does_not_modify_encrypted_values
    input = {
      "_public_key" => pubkey_text,
      "secret" => "plaintext"
    }
    data = EJSON::Data.new(input, pubkey_text)
    encrypted = data.encrypt
    encrypted["secret2"] = "more plaintext"
    data2 = EJSON::Data.new(encrypted, pubkey_text)
    encrypted2 = data2.encrypt

    assert_encrypted encrypted["secret"]
    assert_equal encrypted["secret"], encrypted2["secret"]

    assert_encrypted encrypted2["secret2"]
    refute_equal encrypted2["secret2"], encrypted2["secret"]
  end

  private

  # behaviour undefined if objects don't have the same shape.
  def assert_roundtrip(input, expected)
    data = EJSON::Data.new(input, pubkey_text)
    encrypted = data.encrypt
    assert_match_hash_with_regex(expected, encrypted)

    data2 = EJSON::Data.new(encrypted, pubkey_text)
    decrypted = data2.decrypt(keydir)
    assert_equal input, decrypted
  end

end
