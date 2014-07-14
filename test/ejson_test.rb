require 'minitest/autorun'
require 'tempfile'

require 'ejson/cli'

class CLITest < Minitest::Unit::TestCase

  def test_ejson
    f = Tempfile.new("encrypt")

    f.puts JSON.dump({a: "b"})
    f.close

    encrypt f.path

    first_run = JSON.load(File.read(f.path))
    assert_match(/\AENC\[MIIB.*\]\z/, first_run["a"])

    File.open(f.path, "w") { |f2|
      f2.puts JSON.dump(first_run.merge({new_key: "new_value"}))
    }

    encrypt f.path

    second_run = JSON.load(File.read(f.path))

    assert_equal first_run["a"], second_run["a"]
    assert_match(/\AENC\[MIIB.*\]\z/, second_run["new_key"])

    val = JSON.parse(decrypt(f.path))
    assert_equal({"a" => "b", "new_key" => "new_value"}, val)
  ensure
    File.unlink(f.path)
  end

  def test_inplace
    f = Tempfile.new("encrypt")

    f.puts JSON.dump({a: "b"})
    f.close

    runcli "encrypt", "-p", pubkey, f.path
    encrypted = JSON.load(File.read(f.path))
    assert_match(/\AENC\[MIIB.*\]\z/, encrypted["a"])

    runcli "decrypt", "-i", "-p", pubkey, "-k", privkey, f.path
    decrypted = JSON.load(File.read(f.path))
    refute_match(/\AENC\[MIIB.*\]\z/, decrypted["a"])
  ensure
    File.unlink(f.path)
  end

  def test_default_key_exists
    f = Tempfile.new("encrypt")

    f.puts JSON.dump({a: "b"})
    f.close

    runcli "encrypt", f.path # no pubkey specified

    first_run = JSON.load(File.read(f.path))
    # We don't have the decryption key to this, and it may change over time,
    # so just make sure it was encrypted.
    assert_match(/\AENC\[MIIB.*\]\z/, first_run["a"])
  ensure
    File.unlink(f.path)
  end

  def test_library_is_picky
    f = Tempfile.new("decrypt")
    f.puts JSON.dump({a: "b"})
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

  private

  def encrypt(path)
    runcli "encrypt", "-p", pubkey, path
  end

  def decrypt(path)
    runcli "decrypt", "-p", pubkey, "-k", privkey, path
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
