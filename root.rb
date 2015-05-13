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
      @locales = [ "fi_FI",
                   "en_US",
                   "sv_FI",
                   "de_CH",
                   "fr_CH" ]
      erb :new
    end

    post "/" do
      params["user"].inspect
    end

  end
end
