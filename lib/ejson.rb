require 'json'
require 'forwardable'
require 'ejson/encryption'

class EJSON
  extend Forwardable
  def_delegators :@encryption, :load_string, :dump_string

  def initialize(public_key_pem, private_key_pem = nil)
    @encryption = Encryption.new(public_key_pem, private_key_pem)
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

    def encrypt_all(data=@data)
      case data
      when Hash
        Hash[ data.map { |k,v| [k, encrypt_all(v)] } ]
      when Array
        data.map { |d| encrypt_all(d) }
      when String
        encryption.dump(data)
      else
        data
      end
    end

    def decrypt_all(data=@data)
      case data
      when Hash
        Hash[ data.map { |k,v| [k, decrypt_all(v)] } ]
      when Array
        data.map { |d| decrypt_all(d) }
      when String
        encryption.load(data)
      else
        data
      end
    end

  end

end


