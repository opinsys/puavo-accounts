require 'json'
require 'http'

module PuavoAccounts
  class User
    attr_accessor :data, :uuid, :errors

    EXPIRE = 60*60

    UUID_CHARS = ["a".."z", "A".."Z", "0".."9"].reduce([]) do |memo, range|
      memo + range.to_a
    end

    DATA_ATTRIBUTES = [ "first_name",
                        "last_name",
                        "username",
                        "telephone_number",
                        "locale",
                        "password",
                        "password_confirmation" ]

    def initialize(user_data = {})
      @data = user_data.select { |attr| DATA_ATTRIBUTES.include?(attr) }
      @errors = {}
      @uuid = nil
    end

    def save
      self.data.delete("password_confirmation")
      rest_response = rest_request
        .post(CONFIG["puavo-rest"]["server"] + "/v3/users",
              :json => user_data_with_school(self.data) )

      case rest_response.status
      when 200
        unless self.set_legacy_role
          raise "Couldn't set legacy role to user!"
        end

        return true
      when 400
        res_errors = rest_response.parse["error"]

        if res_errors["code"] == "ValidationError"
          attribute_errors = {}
          res_errors["meta"]["invalid_attributes"].each do |attribute, errors|
            if (DATA_ATTRIBUTES + ["email"]).include?(attribute)
              errors.each do |error|
                self.add_error(attribute, R18n.t.errors.by_code[error["code"]])
              end
            else
              attribute_errors[attribute] = errors
            end
          end

          if @errors.empty? and not attribute_errors.empty?
            raise "Unknown attribute validation errors: #{ attribute_errors }"
          end
        else
          raise "Unknown server error: #{ res_errors.inspect }"
        end

      else
        raise "Unknown status code: #{ rest_response.status }"
      end
    end

    def email_error?
      return true if @errors["email"].nil? || @errors["email"].empty?

      return false
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

    def set_legacy_role
      school_id = CONFIG["legacy_role_school_id"]
      legacy_role_id = CONFIG["legacy_role_id"]

      url = CONFIG["puavo-rest"]["server"] + "/v3/schools/#{ school_id }/legacy_roles/#{ legacy_role_id }/members"

      rest_response = rest_request
        .post(url,
              :form => { "username" => self.data["username"] } )

      case rest_response.status
      when 200
        return true
      else
        return false
      end
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

    def user_data_with_school(user_data)
      user_data["school_dns"] = CONFIG["school_dns_for_users"]
      user_data["roles"] = CONFIG["role_for_users"]

      return user_data
    end

    def rest_request
      HTTP.basic_auth(:user => CONFIG["puavo-rest"]["username"],
                      :pass => CONFIG["puavo-rest"]["password"])
        .headers("Host" => CONFIG["puavo-rest"]["organisation_domain"])
    end
  end
end
