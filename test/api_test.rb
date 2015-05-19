require_relative "helpers"

describe PuavoAccounts::Root do

  describe "user form" do

    it "test" do
      assert_equal 200, 200

      get "/new"

      assert_equal 200, last_response.status
    end
  end

  describe "when create new user" do

    before do
      stub_request(:post, "http://127.0.0.1/v3/users_validate").
        with(:headers => {'Host'=>'www.example.net'}).
        to_return( :status => 200,
                   :body => { :status => 'successfully' }.to_json, :headers => {})

      $mailer = Class.new do
        def self.options
          return @options
        end

        def self.send(args)
          @options = args
        end
      end

      post "/", {
        "user[first_name]" => "Jane",
        "user[last_name]" => "Doe",
        "user[email]" => "jane.doe@example.com"
      }
    end

    it "will be sent an email to user" do
      assert_equal 200, last_response.status

      assert_equal "jane.doe@example.com", $mailer.options[:to]
    end

    it "user information has been stored in the database" do
      assert_equal 200, last_response.status

      uuid = $mailer.options[:body]
      user = PuavoAccounts::User.new
      user.redis_fetch(uuid)

      assert_equal user.data["first_name"], "Jane"
      assert_equal user.data["last_name"], "Doe"
      assert_equal user.data["email"], "jane.doe@example.com"
    end

    it "validate user information by puavo-rest" do
      assert_equal 200, last_response.status

      
    end
  end

end
