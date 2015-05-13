module PuavoAccounts
  class Users < Sinatra::Base

    set :views, Proc.new { File.join(File.dirname(__FILE__), "../", "views/users") }


    get "/new" do
      erb :new
    end

    post "/" do

    end

  end
end
