require 'json'
require 'forwardable'
require 'ejson/encryption'

class EJSON
  extend Forwardable
  def_delegators :@encryption, :load_string, :dump_string

  def initialize(public_key, private_key = nil)
    @encryption = Encryption.new(public_key, private_key)
  end

  def load(json_text)
    Data.new(JSON.load(json_text), @encryption)
  end

  class Data
    extend Forwardable
    def_delegators :@data, :[]=

    attr_reader :encryption
    def initialize(data, encryption)
      @data, @encryption = data, encryption
    end

    def dump
      JSON.pretty_generate(encrypt_all(@data))
    end

    def encrypt_all(name=nil, data=@data)
      case data
      when Hash
        Hash[ data.map { |k,v| [k, encrypt_all(k, v)] } ]
      when Array
        data.map { |d| encrypt_all(name, d) }
      when String
        encrypt_string(name, data)
      else
        data
      end
    end

    def decrypt_all(name=nil, data=@data)
      case data
      when Hash
        Hash[ data.map { |k,v| [k, decrypt_all(k, v)] } ]
      when Array
        data.map { |d| decrypt_all(nil, d) }
      when String
        decrypt_string(name, data)
      else
        data
      end
    end

    private

    def encrypt_string(name, data)
      return data if is_comment?(name)
      encryption.dump(data)
    end

    def decrypt_string(name, data)
      return data if is_comment?(name)
      encryption.load(data)
    end

    def is_comment?(name)
      name === String && name =~ /^_/
    end

  end

end


