require 'thor'
require 'json'
require 'ejson'
require 'ejson/version'
require 'net/http'

class EJSON

  class CLI < Thor
    class_option "privkey", type: :string, aliases: "-k", desc: "Path to PKCS7 private key in PEM format", default: File.join(Dir.home, '.ejson', 'privatekey.pem')
    class_option "pubkey",  type: :string, aliases: "-p", desc: "Path or URL to PKCS7 public key in PEM format", default: File.join(Dir.home, '.ejson', 'publickey.pem')

    default_task :encrypt

    desc "decrypt [file]", "decrypt some data from file to stdout"
    def decrypt(file)
      ciphertext = File.read(file)
      pubkey_data = File.read(options[:pubkey]) if File.exists?(options[:pubkey])
      privkey_data = File.read(options[:privkey]) if File.exists?(options[:privkey])
      ej = EJSON.new(pubkey_data, privkey_data)
      puts JSON.pretty_generate(ej.load(ciphertext).decrypt_all)
    rescue EJSON::Encryption::PrivateKeyMissing => e
      fatal("can't decrypt data without private key (specify path with -k)", e)
    rescue EJSON::Encryption::ExpectedEncryptedString => e
      fatal("can't decrypt data with cleartext strings (use ejson recrypt first)", e)
    end

    desc "encrypt [file=**/*.ejson]", "encrypt an ejson file in place (encrypt any unencrypted values)"
    def encrypt(file="**/*.ejson")
      pubkey_data = File.read(options[:pubkey]) if File.exists?(options[:pubkey])
      ej = EJSON.new(pubkey_data)
      fpaths = Dir.glob(file)
      if fpaths.empty?
        fatal("no ejson files found!", nil)
      end
      fpaths.each do |fpath|
        data = ej.load(File.read(fpath))
        dump = data.dump
        File.open(fpath, "w") { |f| f.puts dump }
        puts "Wrote #{dump.size+1} bytes to #{fpath}"
      end
    rescue OpenSSL::X509::CertificateError => e
      fatal("invalid certificate", e)
    end

    desc "version", "show version information"
    def version
      puts "ejson version #{EJSON::VERSION}"
    end

    private

    def fatal(str, err=str)
      raise err if defined?(Minitest)
      msg = $stderr.tty? ? "\x1b[31m#{str}\x1b[0m" : str
      $stderr.puts msg
      exit 1
    end

    def get_input(file)
      return File.read(file) if file
      $stdin.read
    end

    def pubkey
      @pubkey ||= _pubkey
    end

    def _pubkey
      if options[:pubkey] =~ %r{https://}
        uri = URI.parse(options[:pubkey])
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        req = Net::HTTP::Get.new(URI.parse(options[:pubkey]).request_uri)
        resp = http.request(req)
        resp.value # raises on code >399
        f = Tempfile.new("pubkey")
        f.write resp.body
        f.close
        at_exit { f.unlink }
        f.path
      else
        options[:pubkey]
      end
    end

  end
end

