require "sinatra/base"
require "sinatra/json"

module PuavoAccounts
  class Root < Sinatra::Base

    get "/" do
      "puavo accounts"
    end

  end
end
