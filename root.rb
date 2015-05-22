require "json"
require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"

require_relative "models/user"
require_relative "lib/mailer"

module PuavoAccounts
  $mailer = PuavoAccounts::Mailer.new

  class Root < Sinatra::Base


    register Sinatra::R18n

    get "/" do
      "puavo accounts"
    end

    get "/new" do
      @user = User.new()

      erb :new
    end

    post "/" do
      @user = User.new(params["user"])

      if params["user"]["password"] != params["user"]["password_confirmation"]
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
        return erb :new
      end

      unless @user.valid?
        # render form
      end

      # Save user to redis
      @user.redis_save

      confirm_url = "https://www.example.net/confirm/#{ @user.uuid }"
      body = t.api.confirm.message(@user.data["first_name"], confirm_url )

      # Send email
      $mailer.send( :to => @user.data["email"],
                    :subject => t.api.confirm.subject,
                    :body => body )
    end

    get "/confirm/:uuid" do

      # Get user from redis
      @user = User.new
      @user.redis_fetch(params[:uuid])

      if @user.save
        # render OK
        @user.data.inspect
        @user.redis_destroy
      else
        # render fail
      end

    end

    helpers do

      def show_error_message(user, attribute)
        return unless user.errors[attribute]

        @errors = user.errors[attribute]

        erb :error_message

      end

      def text_field(model, attribute, options = {})
        @name = model.html_attribute(attribute)
        @css_id = model.css_id(attribute)
        @value = model.data[attribute]

        erb :text_field
      end

    end

  end
end
