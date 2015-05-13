require "sinatra/base"
require "sinatra/json"

module PuavoAccounts
  class Root < Sinatra::Base

    get "/" do
      "puavo accounts"
    end

    get "/new" do
      erb :new
    end

  end
end
