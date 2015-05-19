require_relative "helpers"

describe PuavoAccounts::User do

  user_data = {
    "first_name" => "Jane",
    "last_name" => "Doe",
    "email" => "jane.doe@example.com"
  }


  describe "when create new user object" do

    describe "without initial data" do
      it "user object must be" do
        user = PuavoAccounts::User.new

        assert_equal user.data, {}
        assert_equal user.errors, {}
        assert_equal user.uuid, nil
      end
    end

    describe "with initial data" do

      it "user object must be" do
        user = PuavoAccounts::User.new(user_data)

        assert_equal user.data["first_name"], "Jane"
        assert_equal user.data["last_name"], "Doe"
        assert_equal user.data["email"], "jane.doe@example.com"
      end
    end

    describe "and save user to redis" do

      it "user data must remain the same" do
        user = PuavoAccounts::User.new(user_data)
        user.redis_save

        assert user.uuid != nil

        redis_user = PuavoAccounts::User.new
        redis_user.redis_fetch(user.uuid)

        assert_equal redis_user.data["first_name"], "Jane"
        assert_equal redis_user.data["last_name"], "Doe"
        assert_equal redis_user.data["email"], "jane.doe@example.com"
      end
    end
  end

  # FIXME test expire time

end
