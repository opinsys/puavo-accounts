require "json"
require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"

require_relative "models/user"

module PuavoAccounts
  class Root < Sinatra::Base



    register Sinatra::R18n

    get "/" do
      "puavo accounts"
    end

    get "/new" do
      @user = User.new()

      @locales = [ "fi_FI",
                   "en_US",
                   "sv_FI",
                   "de_CH",
                   "fr_CH" ]
      erb :new
    end

    post "/" do

      @user = User.new(params["user"])

      unless @user.valid?
        # render form
      end

      # Save user to redis
      @user.redis_save

      @user.uuid

      # Send email
    end

    get "/confirm/:uuid" do

      # Get user from redis
      @user = User.new
      @user.redis_fetch(params[:uuid])

      if @user.save
        # render OK
        @user.data.inspect
      else
        # render fail
      end

    end
  end
end
