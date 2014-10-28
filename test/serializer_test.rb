require_relative 'helper'

require 'ejson/serializer'

class SerializerTest < MiniTest::Test

  def test_load_fails_when_key_is_not_present
    json = '{"key":"value"}'
    assert_raises EJSON::MissingPublicKey do
      EJSON::Serializer.load_json(json)
    end
  end

  def test_load_fails_when_key_is_too_short
    json = '{"_public_key":"too_short"}'
    assert_raises EJSON::MissingPublicKey do
      EJSON::Serializer.load_json(json)
    end
  end

  def test_returns_key_when_key_is_acceptable
    key = "a"*1024
    json = %Q|{"_public_key":"#{key}","a":"b"}|
    obj, pk = EJSON::Serializer.load_json(json)
    assert_equal pk, key
    assert_equal({"_public_key" => key, "a" => "b"}, obj)
  end

  def test_dump
    assert_equal '{"a":"b"}', EJSON::Serializer.dump_json(a: :b)
  end

end
