require_relative "helpers"

describe PuavoAccounts::Root do

  describe "email register form" do

    it "will be respond 200" do
      assert_equal 200, 200

      get "/register/email"

      assert_equal 200, last_response.status
    end
  end

  describe "when register new email" do

    before do
      stub_mailer
    end

    it "will be sen an email to user" do
      post "/register/email", {
        "email" => "jane.doe@example.com"
      }
      assert_equal 302, last_response.status
      assert_equal "jane.doe@example.com", $mailer.options[:to]

      jwt = $mailer.options[:body].match("https://www.example.net/authenticate/(.+)$")[1]
      jwt_data = JWT.decode(jwt, "secret")

      assert_equal "jane.doe@example.com", jwt_data[0]["email"]
    end

  end

  describe "authentication by jwt token" do

    before do
      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i.to_s,

        "email" => "jane.doe@example.com"
      }

      @jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      @rest_user = {
        "email"=>"jane.doe@example.com",
        "first_name"=>"Jane",
        "last_name"=>"Doe",
        "locale"=>"en_US",
        "password"=>"secret",
        "telephone_number"=>"1234567",
        "username"=>"jane.doe"
      }

      stub_mailer

      @user_form = {
        "user[first_name]" => "Jane",
        "user[last_name]" => "Doe",
        "user[email]" => "jane.doe@example.com",
        "user[username" => "jane.doe",
        "user[telephone_number]" => "1234567",
        "user[locale]" => "en_US",
        "user[password]" => "secret",
        "user[password_confirmation]" => "secret"
      }
    end

    it "show error message if jwt is invalid" do
      get "/authenticate/asdfsdfsdfsdfsdf0934023sdfs0df9w0"

      last_response.body.must_include "The link is invalid or has expired!"
    end

    it "show error message if jwt is too old" do
      jwt_data = {
        "iat" =>  (Time.now-60*60*25).to_i.to_s,

        "email" => "jane.doe@example.com"
      }

      @jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      get "/register/user/#{ @jwt }"

      last_response.body.must_include "The link is invalid or has expired!"
    end

    it "render error if password doesn't match confirmation" do
      @user_form.delete("user[password_confirmation]")
      post "/", @user_form

      last_response.body.must_include "Password doesn't match confirmation"
    end
  end

  describe "when the user registration to confirm" do

    before do
      @stub_create_user = stub_request(:post, "http://127.0.0.1/v3/users").
        with(:headers => {'Host'=>'www.example.net'},
             :body => {
               "first_name" => "Jane",
               "last_name" => "Doe",
               "email" => "jane.doe@example.com",
               "username" => "jane.doe",
               "telephone_number" => "1234567",
               "locale" => "en_US",
               "password" => "secret" }).
        to_return( :status => 200,
                   :body => {
                     "dn" => "puavoId=55,ou=People,dc=edu,dc=example,dc=fi",
                     "id" => "55",
                     "username" => "jane.doe",
                     "uid_number" => 11111,
                     "gid_number" => 22222,
                     "last_name" => "Doe",
                     "first_name" => "Jane",
                     "email" => "jane.doe@example.com",
                     "secondary_emails" => [],
                     "school_dns" => [
                                    "puavoId=1122,ou=Groups,dc=edu,dc=exaple,dc=fi"
                                   ],
                     "preferred_language" => "en",
                     "locale" => "en_US.UTF-8",
                     "locked" => false,
                     "ssh_public_key" => nil,
                     "admin_of_school_dns" => [],
                     "object_model" => "PuavoRest::User",
                     "user_type" => "student",
                     "puavo_id" => "55",
                     "unique_id" => "puavoid=55,ou=people,dc=edu,dc=example,dc=fi",
                     "organisation_domain" => "www.example.net",
                     "school_dn" => "puavoId=1122,ou=Groups,dc=edu,dc=example,dc=fi",
                     "primary_school_id" => "1122",
                     "homepage" => "",
                     "external_service_path_prefix" => "/"
                   }.to_json, :headers => {})

      @user = PuavoAccounts::User.new({
        "first_name" => "Jane",
        "last_name" => "Doe",
        "email" => "jane.doe@example.com",
        "username" => "jane.doe",
        "telephone_number" => "1234567",
        "locale" => "en_US",
        "password" => "secret",
        "password_confirmation" => "secret"
      })
      @user.redis_save

      @uuid = @user.uuid

      get "/confirm/#{ @uuid }"

    end

    it "send create request to the puavo-rest" do
      assert_requested(@stub_create_user)
    end

  end

  def stub_mailer
    $mailer = Class.new do
      def self.options
        return @options
      end

      def self.send(args)
        @options = args
      end
    end
  end
end
