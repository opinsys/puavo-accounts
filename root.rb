require "sinatra/base"
require "sinatra/json"

require_relative "resources/users"

module PuavoAccounts
  class Root < Sinatra::Base

    get "/" do
      "puavo accounts"
    end

    use PuavoAccounts::Users

  end
end
