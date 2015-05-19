require_relative "helpers"

describe PuavoAccounts::Root do

  describe "user form" do

    it "test" do
      assert_equal 200, 200

      get "/new"

      assert_equal 200, last_response.status
    end
  end

end
