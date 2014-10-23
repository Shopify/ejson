require 'thor'
require 'json'
require 'ejson'
require 'net/http'

class EJSON

  class CLI < Thor
    SEARCH_PATHS = [File.join(Dir.home, '.ejson'), File.join('', 'etc', 'ejson')]
    DEFAULT_PUBLIC_KEY = "https://s3.amazonaws.com/shopify-ops/ejson-publickey.pem"
    class_option "privkey", type: :string, aliases: "-k", desc: "Path to PKCS7 private key in PEM format", default: ENV['EJSON_PRIVATE_KEY_PATH']
    class_option "pubkey",  type: :string, aliases: "-p", desc: "Path or URL to PKCS7 public key in PEM format",  default: ENV['EJSON_PUBLIC_KEY_PATH']

    default_task :encrypt

    desc "decrypt [file]", "decrypt some data from file to stdout"
    method_option :out, type: :string, default: false, aliases: "-o", desc: "Write to a file rather than stdout"
    def decrypt(file)
      ciphertext = File.read(file)
      ej = EJSON.new(pubkey, privkey)
      output = JSON.pretty_generate(ej.load(ciphertext).decrypt_all)
      if options[:out]
        File.open(options[:out], "w") { |f| f.puts output }
        puts "Wrote #{output.size} bytes to #{options[:out]}"
      else
        puts output
      end
    rescue EJSON::Encryption::PrivateKeyMissing => e
      fatal("can't decrypt data without private key (specify path with -k)", e)
    rescue EJSON::Encryption::ExpectedEncryptedString => e
      fatal("can't decrypt data with cleartext strings (use ejson recrypt first)", e)
    end

    desc "encrypt [file=**/*.ejson]", "encrypt an ejson file in place (encrypt any unencrypted values)"
    def encrypt(file="**/*.ejson")
      ej = EJSON.new(pubkey)
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
      require 'ejson/version'
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
      if options[:pubkey] =~ %r{https://}
        download_public_key(options[:pubkey])
      else
        return options[:pubkey] if options[:pubkey]
        SEARCH_PATHS.each do |path|
          full_path = File.join(path, "publickey.pem")
          return full_path if File.exist?(full_path)
        end
        download_public_key(DEFAULT_PUBLIC_KEY)
      end
    end

    def privkey
      return options[:privkey] if options[:privkey]
      SEARCH_PATHS.each do |path|
        full_path = File.join(path, "privatekey.pem")
        return full_path if File.exist?(full_path)
      end
    end

    def download_public_key(url)
      puts "EJSON is going to download the public key from: #{url}"
      print "Do you want to continue? (Y/n):"
      response = gets.chomp
      unless response == "" || response.downcase == "y"
        puts "Operation cancelled"
        exit 0
      end

      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      req = Net::HTTP::Get.new(uri.request_uri)
      resp = http.request(req)
      resp.value # raises on code >399
      FileUtils.mkpath(SEARCH_PATHS.first)
      f = File.new(File.join(SEARCH_PATHS.first, "publickey.pem"), "w")
      f.write resp.body
      f.close
      f.path
    end

  end
end

