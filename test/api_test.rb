require_relative "helpers"

describe PuavoAccounts::Root do

  describe "user form" do

    it "test" do
      assert_equal 200, 200

      get "/new"

      assert_equal 200, last_response.status
    end
  end

  describe "when register new user" do

    before do
      @stub_validate = puavo_rest_stub_validate

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

    it "will be sent an email to user" do
      post "/", @user_form

      assert_equal 200, last_response.status

      assert_equal "jane.doe@example.com", $mailer.options[:to]
    end

    it "user information has been stored in the database" do
      post "/", @user_form

      assert_equal 200, last_response.status

      uuid = $mailer.options[:body].match("https://www.example.net/confirm/(.+)$")[1]
      user = PuavoAccounts::User.new
      user.redis_fetch(uuid)

      assert_equal user.data["first_name"], "Jane"
      assert_equal user.data["last_name"], "Doe"
      assert_equal user.data["email"], "jane.doe@example.com"
    end

    it "validate user information by puavo-rest" do
      post "/", @user_form

      assert_equal 200, last_response.status

      assert_requested(@stub_validate)
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
               "password" => "secret",
               "password_confirmation]" => "secret" }).
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
        "password_confirmation]" => "secret"
      })
      @user.redis_save

      @uuid = @user.uuid

      get "/confirm/#{ @uuid }"

    end

    it "send create request to the puavo-rest" do
      assert_requested(@stub_create_user)
    end

    it "remove user information from the database" do
      assert_equal @user.redis_fetch(@uuid), false
    end
  end

  def puavo_rest_stub_validate
    stub_request(:post, "http://127.0.0.1/v3/users_validate").
      with(:headers => {'Host'=>'www.example.net', 'Authorization'=>'Basic dGVzdC11c2VyOnNlY3JldA=='}).
      to_return( :status => 200,
                 :body => { :status => 'successfully' }.to_json, :headers => {})
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
