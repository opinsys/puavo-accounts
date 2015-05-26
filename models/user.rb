require 'json'
require 'http'

module PuavoAccounts
  class User
    attr_accessor :data, :uuid, :errors

    EXPIRE = 60*60

    UUID_CHARS = ["a".."z", "A".."Z", "0".."9"].reduce([]) do |memo, range|
      memo + range.to_a
    end

    def initialize(user_data = {})
      @data = user_data
      @errors = {}
      @uuid = nil
    end

    def save
      self.data.delete("password_confirmation")
      rest_response = HTTP.basic_auth(:user => CONFIG["puavo-rest"]["username"],
                                      :pass => CONFIG["puavo-rest"]["password"])
        .with_headers("Host" => CONFIG["puavo-rest"]["organisation_domain"])
        .post(CONFIG["puavo-rest"]["server"] + "/v3/users",
              :json => self.data )

      case rest_response.status
      when 200
        return true
      when 400
        rest_response.parse["error"]["meta"]["invalid_attributes"].each do |attribute, errors|
          errors.each do |error|
            self.add_error(attribute, R18n.t.errors.by_code[error["code"]])
          end
        end
      else
        raise "Unknow status code"
      end
    end

    def add_error(attribute, message)
      unless @errors[attribute]
        @errors[attribute] = []
      end
      @errors[attribute].push message
    end

    def html_attribute(attribute)
      "user[#{ attribute }]"
    end

    def css_id(attribute)
      "user_#{ attribute }"
    end

    private

    def uuid_key
      if @uuid.nil?
        generate_uuid
      end
      return "puavo-accounts:user:#{ @uuid }"
    end

    def generate_uuid
      @uuid = (0...50).map{ UUID_CHARS[rand(UUID_CHARS.size)] }.join
    end
  end
end
