require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"

module PuavoAccounts
  class Root < Sinatra::Base

    register Sinatra::R18n

    get "/" do
      "puavo accounts"
    end

    get "/new" do
      erb :new
    end

  end
end
