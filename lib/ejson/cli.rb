require 'thor'
require 'json'
require 'openssl'

require 'ejson'
require 'ejson/version'

module EJSON

  class CLI < Thor
    default_task :encrypt

    desc "decrypt [file]", "decrypt an encrypted ejson file"
    method_option :out, type: :string, default: "", aliases: "-o", desc: "File to write output to. Defaults to stdout"
    method_option :keydir, type: :string, default: "/opt/ejson", desc: "Directory to search for private keys"
    def decrypt(file)
      ciphertext = File.read(file)
      output = EJSON.decrypt(ciphertext, options[:keydir])

      if options[:out] == ""
        puts output
      else
        File.open(options[:out], "w") { |f| f.puts output }
        if options[:out] != "/dev/stdout"
          puts "Wrote #{output.size} bytes to #{options[:out]}"
        end
      end
    rescue EJSON::MissingPrivateKey => e
      fatal("no private key was found in #{keydir} matching the file's public key. Speciy a different directory with --keydir", e)
    rescue EJSON::ExpectedEncryptedString => e
      fatal("can't decrypt data with cleartext strings (were plaintext secrets committed to the repository?)", e)
    end

    desc "encrypt [file=**/*.ejson]", "encrypt an ejson file in place (encrypt any unencrypted values)"
    def encrypt(file="**/*.ejson")
      fpaths = Dir.glob(file)
      if fpaths.empty?
        fatal("no ejson files found!", nil)
      end
      fpaths.each do |fpath|
        plaintext = File.read(fpath)
        output = nil
        begin
          output = EJSON.encrypt(plaintext)
        rescue EJSON::MissingPublicKey => e
          fatal("file '#{fpath}' must have a '_public_key' key at the toplevel", e)
        rescue OpenSSL::X509::CertificateError => e
          fatal("invalid certificate", e)
        end
        File.open(fpath, "w") { |f| f.puts output }
        puts "Wrote #{output.size+1} bytes to #{fpath}"
      end
    end

    desc "version", "show version information"
    def version
      puts "ejson version #{EJSON::VERSION}"
    end

    desc "keygen [subject]", "generate a new keypair (subject should be of the form '/O=Shopify/CN=myproject')"
    def keygen(subject)
      system(<<-SH)
        openssl req -x509 -nodes \
          -days 100000 \
          -newkey rsa:2048 \
          -keyout /dev/stderr \
          -subj '#{subject}' \
        | tr "\\\\n" "|" | sed 's/|/\\\\n/g'
        echo
      SH
    end

    private

    def fatal(str, err=str)
      raise err if defined?(MiniTest)
      msg = $stderr.tty? ? "\x1b[31m#{str}\x1b[0m" : str
      $stderr.puts msg
      exit 1
    end

  end
end

