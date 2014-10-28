require 'minitest/autorun'

class MiniTest::Test

  ENCRYPTED = /EJ\[1,MII.{100,}\]/

  protected

  def assert_match_hash_with_regex(a, b)
    case a
    when Hash
      a.each{|k,v|assert_match_hash_with_regex(v, b[k])}
    when Array
      a.zip(b).each{|x,y|assert_match_hash_with_regex(x,y)}
    when Regexp
      assert_match a, b
    when String
      assert_equal a, b
    end
  end

  def assert_encrypted(x)
    assert_match(ENCRYPTED, x)
  end

  def pubkey(k=:c)       ; OpenSSL::X509::Certificate.new(pubkey_text k); end
  def privkey(k=:c)      ; OpenSSL::PKey::RSA.new(privkey_text k); end

  def pubkey_text(k=:c)  ; File.read(pubkey_path k); end
  def privkey_text(k=:c) ; File.read(privkey_path k); end

  def pubkey_path(k=:c)  ; File.join(keydir, "#{k}-public.pem"); end
  def privkey_path(k=:c) ; File.join(keydir, "#{k}-private.pem"); end

  def keydir             ; File.expand_path("../keys/", __FILE__); end

end

