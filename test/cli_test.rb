require_relative 'helper'
require 'tempfile'

require 'ejson/cli'

class CLITest < MiniTest::Test

  def test_encrypt_decrypt
    tf = Tempfile.new('ejson')
    tf2 = Tempfile.new('ejson')
    tf2.close
    input = {
      "_public_key" => pubkey_text,
      "secret" => "plaintext",
    }
    expected = {
      "_public_key" => pubkey_text,
      "secret" => ENCRYPTED,
    }
    tf.write(JSON.dump(input))
    tf.close

    stdout = runcli "encrypt", tf.path
    output = JSON.load(File.read(tf.path))
    assert_match_hash_with_regex(expected, output)
    assert_match(%r{\AWrote \d+ bytes to #{tf.path}\z}, stdout)

    dec_text = runcli "decrypt", "--keydir", keydir, tf.path
    decrypted = JSON.load(dec_text)

    assert_equal(input, decrypted)

    msg = runcli "decrypt", "--keydir", keydir, "--out", tf2.path, tf.path
    assert_match(%r{\AWrote \d+ bytes to #{tf2.path}\z}, msg)

    assert_equal dec_text.strip, File.read(tf2.path).strip
  ensure
    tf.unlink
    tf2.unlink
  end

  def test_version
    assert_match(/\Aejson version \S{5,12}\z/, runcli("version"))
  end

  private

  def runcli(*args)
    sio = StringIO.new
    _stdout, $stdout = $stdout, sio
    EJSON::CLI.start(args)
    sio.string.chomp
  ensure
    $stdout = _stdout
  end

end
