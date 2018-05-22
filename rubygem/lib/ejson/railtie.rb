module EJSON
  class Railtie < Rails::Railtie

    initializer "ejson.merge_secrets" do
      json_files.each do |file|
        next unless file.exist?
        secrets = JSON.parse(file.read, symbolize_names: true)
        break Rails.application.secrets.deep_merge!(secrets)
      end
    end

    private

    def json_files
      [
        Rails.root.join("config", "secrets.json"),
        Rails.root.join("config", "secrets.#{Rails.env}.json"),
      ]
    end
  end
end
