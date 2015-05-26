require "json"
require "jwt"
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

    get "/register/email" do
      erb :register_email
    end

    post "/register/email" do
      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i.to_s,

        "email" => params["email"]
      }

      jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      @register_url = "https://#{ CONFIG["puavo-rest"]["organisation_domain"] }/register/user/#{ jwt }"

      body = erb(:register_email_message, :layout => false)

      $mailer.send( :to => params["email"],
                    :subject => t.register.email.subject,
                    :body => body )

      redirect "register/email/complete"
    end
    get "/register/email/complete" do
      erb :register_email_complete
    end

    get "/register/user/:jwt" do
      @user = User.new()

      erb :new
    end

    post "/" do
      @user = User.new(params["user"])

      if params["user"]["password"] != params["user"]["password_confirmation"]
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
      end

      if not @user.valid? or not @user.errors.empty?
        return erb :new
      end

      # FIXME redirect to the complete page
      redirect "/successfylly"
    end

    get "/successfully" do
      erb :successfully
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

      def form_field(model, attribute, type)
        @user = model
        @attr = attribute
        @errors = []
        @type = type
        @name = model.html_attribute(attribute)
        @css_id = model.css_id(attribute)
        @value = model.data[attribute]

        @form_group_class = "form-group"

        if @user.errors[attribute]
          @errors = @user.errors[attribute]
          @form_group_class += " has-error"
        end

        erb :form_field

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
