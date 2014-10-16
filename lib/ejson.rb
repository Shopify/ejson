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

  def serializer
    @serializer ||= Serializer.new(@encryption)
  end

  class Serializer

    def initialize(encryption)
      @encryption = encryption
    end

    def dump(data)
      data = Data.new(data, @encryption) unless data.is_a?(Data)
      data.dump
    end

    def load(data)
      Data.new(JSON.parse(data), @encryption).decrypt_all
    end

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
        if data["secret"]
          data["secret"] = encryption.dump(data["secret"])
          data
        else
          Hash[ data.map { |k,v| [k, encrypt_all(v)] } ]
        end
      when Array
        data.map { |d| encrypt_all(d) }
      else
        data
      end
    end

    def decrypt_all(data=@data)
      case data
      when Hash
        if data["secret"]
          data["secret"] = encryption.load(data["secret"])
          data
        else
          Hash[ data.map { |k,v| [k, decrypt_all(v)] } ]
        end
      when Array
        data.map { |d| decrypt_all(d) }
      else
        data
      end
    end

  end

end


