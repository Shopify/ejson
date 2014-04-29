require 'minitest/autorun'
require 'tempfile'

require 'ejson/cli'

class CLITest < Minitest::Unit::TestCase

  def test_ejson
    f = Tempfile.create("encrypt")

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

  def test_default_key_exists
    f = Tempfile.create("encrypt")

    f.puts JSON.dump({a: "b"})
    f.close

    File.stub(:exists?, false) do
      assert_raises(EJSON::Encryption::PublicKeyMissing) {
        runcli "encrypt", f.path # no pubkey specified
      }
    end
  ensure
    File.unlink(f.path)
  end

  def test_default_key_not_exists
    f = Tempfile.create("encrypt")
    f.puts JSON.dump({a: "b"})
    f.close

    assert_raises(EJSON::Encryption::PublicKeyMissing) {
      runcli "encrypt", "-p", File.join('', 'tmp', 'something','doesnt_exist2353'), f.path
    }
  ensure
    File.unlink(f.path)
  end

  def test_library_is_picky
    f = Tempfile.create("decrypt")
    f.puts JSON.dump({a: "b"})
    f.close
    assert_raises(EJSON::Encryption::ExpectedEncryptedString) {
      decrypt(f.path)
    }
  ensure
    File.unlink(f.path)
  end

  def test_library_expects_private_key
    f = Tempfile.create("decrypt")
    f.puts JSON.dump({a: "b"})
    f.close
    encrypt f.path
    assert_raises(EJSON::Encryption::PrivateKeyMissing) {
      runcli "decrypt", "-p", pubkey, f.path
    }
  ensure
    File.unlink(f.path)
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
