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

    enable :sessions
    set :session_secret, CONFIG["session_secret"]

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

      @register_url = "https://#{ CONFIG["puavo-rest"]["organisation_domain"] }/authenticate/#{ jwt }"

      body = erb(:register_email_message, :layout => false)

      $mailer.send( :to => params["email"],
                    :subject => t.api.register_email.subject,
                    :body => body )

      redirect "register/email/complete"
    end

    get "/register/email/complete" do
      erb :register_email_complete
    end

    get "/authenticate/:jwt" do
      begin
        jwt_data = JWT.decode(params[:jwt], CONFIG["jwt"]["secret"])
      rescue JWT::DecodeError
        return erb :invalid_jwt
      end

      if (Time.now-60*60*24).to_i > jwt_data.first["iat"].to_i
        return erb :invalid_jwt
      end

      session[:email] = jwt_data.first["email"]


      redirect "/register/user"
    end

    get "/register/user" do
      @user = User.new()

      unless session[:email]
        return "ERROR"
      end

      erb :new
    end

    post "/register/user" do
      unless session[:email]
        return "ERROR"
      end

      @user = User.new(params["user"])

      @user.data["email"] = session["email"]

      if params["user"]["password"] != params["user"]["password_confirmation"]
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
      end

      if not @user.save or not @user.errors.empty?
        return erb :new
      end

      session.delete(:email)

      # FIXME redirect to the complete page
      redirect "/successfully"
    end

    get "/successfully" do
      erb :successfully
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
