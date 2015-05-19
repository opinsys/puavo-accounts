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

    it "will be sent an email to user" do
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

      assert_equal 200, last_response.status

      assert_equal "jane.doe@example.com", $mailer.options[:to]
    end
  end

end
