require 'minitest/autorun'
require 'tempfile'

require 'ejson/cli'

class CLITest < Minitest::Unit::TestCase

  def test_ejson
    f = Tempfile.new("encrypt")


    f.puts JSON.dump(secret_schema)
    f.close

    runcli "encrypt", "-p", pubkey, f.path
    encrypted = JSON.load(File.read(f.path))

    assert_equal secret_schema["a"]["severity"], encrypted["a"]["severity"]
    assert_equal secret_schema["a"]["description"], encrypted["a"]["description"]
    assert_equal secret_schema["a"]["type"], encrypted["a"]["type"]
    assert_equal secret_schema["a"]["rotation"], encrypted["a"]["rotation"]
    assert_equal secret_schema["a"]["urls"], encrypted["a"]["urls"]
    assert_match(/\AENC\[MIIB.*\]\z/, encrypted["a"]["secret"])

    runcli "decrypt", "-o", f.path, "-p", pubkey, "-k", privkey, f.path
    decrypted = JSON.load(File.read(f.path))
    assert_equal secret_schema["a"]["severity"], decrypted["a"]["severity"]
    assert_equal secret_schema["a"]["description"], decrypted["a"]["description"]
    assert_equal secret_schema["a"]["type"], decrypted["a"]["type"]
    assert_equal secret_schema["a"]["rotation"], decrypted["a"]["rotation"]
    assert_equal secret_schema["a"]["urls"], decrypted["a"]["urls"]
    assert_equal secret_schema["a"]["secret"], decrypted["a"]["secret"]
  ensure
    File.unlink(f.path)
  end


  def test_inplace
    f = Tempfile.new("encrypt")

    f.puts JSON.dump(secret_schema)
    f.close

    runcli "encrypt", "-p", pubkey, f.path
    encrypted = JSON.load(File.read(f.path))
    assert_match(/\AENC\[MIIB.*\]\z/, encrypted["a"]["secret"])

    runcli "decrypt", "-o", f.path, "-p", pubkey, "-k", privkey, f.path
    decrypted = JSON.load(File.read(f.path))
    refute_match(/\AENC\[MIIB.*\]\z/, decrypted["a"]["secret"])
  ensure
    File.unlink(f.path)
  end

  def test_default_key_exists
    f = Tempfile.new("encrypt")

    f.puts JSON.dump(secret_schema)
    f.close

    runcli "encrypt", f.path # no pubkey specified

    first_run = JSON.load(File.read(f.path))
    # We don't have the decryption key to this, and it may change over time,
    # so just make sure it was encrypted.
    assert_match(/\AENC\[MIIB.*\]\z/, first_run["a"]["secret"])
  ensure
    File.unlink(f.path)
  end

  def test_library_is_picky
    f = Tempfile.new("decrypt")
    f.puts JSON.dump(secret_schema)
    f.close
    assert_raises(EJSON::Encryption::ExpectedEncryptedString) {
      decrypt(f.path)
    }
  ensure
    File.unlink(f.path)
  end

  def test_key_strings
    public_key = File.read(pubkey)
    private_key = File.read(privkey)

    @enc = EJSON::Encryption.new(public_key, private_key)

    assert_equal public_key, @enc.instance_variable_get(:@public_key_x509).to_s
    assert_equal private_key, @enc.instance_variable_get(:@private_key_rsa).to_s
  end

  def test_serializer_api
    serializer = EJSON.new(pubkey, privkey).serializer
    assert_equal secret_schema, serializer.load(serializer.dump(secret_schema))
  end

  def test_serializer_safety
    serializer = EJSON.new(pubkey, privkey).serializer
    refute serializer.dump(secret_schema).include?('bar')
  end

  private

  def encrypt(path)
    runcli "encrypt", "-p", pubkey, path
  end

  def decrypt(path)
    runcli "decrypt", "-p", pubkey, "-k", privkey, path
  end

  def secret_schema
    {
      "a" => {
        "severity" => "LOW",
        "description" => "omg",
        "type" => "PASSWORD",
        "rotation" => "Dont know lol",
        "urls" => ["http://omg.com"],
        "secret" => "omg"
      }
    }
  end

  def runcli(*args)
    sio = StringIO.new
    _stdout, $stdout = $stdout, sio
    EJSON::CLI.start(args)
    sio.string.chomp
  ensure
    $stdout = _stdout
  end

  def pubkey  ; File.expand_path("../publickey.pem", __FILE__); end
  def privkey ; File.expand_path("../privatekey.pem", __FILE__); end

end
