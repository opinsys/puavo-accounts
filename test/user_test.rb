require_relative "helpers"

describe PuavoAccounts::User do

  user_data = {
    "first_name" => "Jane",
    "last_name" => "Doe",
    "username" => "jane.doe",
    "foobar" => "barfoo"
  }


  describe "when create new user object" do

    describe "without initial data" do
      it "user object must be" do
        user = PuavoAccounts::User.new

        assert_equal user.data, {}
        assert_equal user.errors, {}
        assert_nil   user.uuid
      end
    end

    describe "with initial data" do

      it "user object must be" do
        user = PuavoAccounts::User.new(user_data)

        assert_equal user.data["first_name"], "Jane"
        assert_equal user.data["last_name"], "Doe"
        assert_equal user.data["username"], "jane.doe"
        assert_nil user.data["foobar"]
      end
    end

  end

  # FIXME test expire time

end
