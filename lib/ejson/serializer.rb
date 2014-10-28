require 'json'

require 'ejson'

module EJSON

  class Serializer
    # raises JSON::ParserError
    # raises EJSON::MissingPublicKey
    def self.load_json(text)
      obj = JSON.load(text)
      pk = obj["_public_key"]
      if !pk || pk.size < 1000
        raise EJSON::MissingPublicKey
      end
      return obj, pk
    end

    def self.dump_json(obj)
      JSON.dump(obj)
    end

  end

end
