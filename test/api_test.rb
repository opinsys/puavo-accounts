require_relative "helpers"

describe PuavoAccounts::Root do

  describe "email register form" do

    it "will be respond 200" do
      assert_equal 200, 200

      get "/accounts"

      assert_equal 200, last_response.status
    end
  end

  describe "when register new email" do

    before do
      stub_mailer
    end

    it "will be send an email to user" do
      post "/accounts", {
        "user[email]" => "jane.doe@example.com"
      }
      assert_equal 302, last_response.status
      assert_equal "jane.doe@example.com", $mailer.options[:to]

      jwt = $mailer.options[:body].match("https://www.example.net/accounts/authenticate/(.+)$")[1]
      jwt_data = JWT.decode(jwt, "secret")

      assert_equal "jane.doe@example.com", jwt_data[0]["email"]
    end

  end

  describe "authentication by jwt token" do

    before do
      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i,

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
      get "/accounts/authenticate/asdfsdfsdfsdfsdf0934023sdfs0df9w0"

      last_response.body.must_include "The link has been expired or it is malformed!"
    end

    it "show error message if jwt is too old" do
      jwt_data = {
        "iat" =>  (Time.now-60*60*25).to_i,

        "email" => "jane.doe@example.com"
      }

      @jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      get "/accounts/authenticate/#{ @jwt }"

      last_response.body.must_include "The link has been expired or it is malformed!"
    end

    it "redirect to use form jwt is valid" do
      get "/accounts/authenticate/#{ @jwt }"

      assert last_response.redirect?
    end
  end

  describe "when register new user" do
    before do
      @user_form = {
        "user[first_name]" => "Jane",
        "user[last_name]" => "Doe",
        "user[username" => "jane.doe",
        "user[telephone_number]" => "1234567",
        "user[locale]" => "en_US.UTF-8",
        "user[password]" => "secret",
        "user[password_confirmation]" => "secret"
      }

      @stub_add_legacy_role = stub_request(:post, "http://127.0.0.1/v3/schools/1/legacy_roles/2/members").
        with(:headers => {'Host'=>'www.example.net'},
             :body => { "username" => "jane.doe" }).
        to_return( :status => 200 )

      @stub_create_user = stub_request(:post, "http://127.0.0.1/v3/users").
        with(:headers => {'Host'=>'www.example.net'},
             :body => "{\"first_name\":\"Jane\",\"last_name\":\"Doe\",\"username\":\"jane.doe\",\"telephone_number\":\"1234567\",\"locale\":\"en_US.UTF-8\",\"password\":\"secret\",\"email\":\"jane.doe@example.com\",\"school_dns\":[\"puavoId=1,ou=Groups,dc=edu,dc=hogwarts,dc=fi\"],\"roles\":[\"student\"]}").
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

      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i,

        "email" => "jane.doe@example.com"
      }
      @jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])
      get "/accounts/authenticate/#{ @jwt }"
    end

    it "will be see user form" do
      get "/accounts/user"

      last_response.body.must_include "Opinsys Account registration"
    end

    it "will be create new user" do
      post "/accounts/user", @user_form
      
      assert_requested(@stub_create_user)
      assert_requested(@stub_add_legacy_role)

      assert last_response.redirect?
    end

    it "render error if password doesn't match confirmation" do
      @user_form.delete("user[password_confirmation]")
      post "/accounts/user", @user_form

      last_response.body.must_include "Passwords do not match!"
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
