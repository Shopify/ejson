# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ejson/version'

Gem::Specification.new do |spec|
  spec.name          = "ejson"
  spec.version       = Ejson::VERSION
  spec.authors       = ["Burke Libbey"]
  spec.email         = ["burke.libbey@shopify.com"]
  spec.summary       = %q{Asymmetric keywise encryption for JSON}
  spec.description   = %q{Secret management by encrypting values in a JSON hash with a public/private keypair}
  spec.homepage      = "https://github.com/Shopify/ejson"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "thor", "~> 0.18"
  spec.add_development_dependency "rake", "~> 10.3.2"
end
