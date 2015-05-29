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

    enable :logging

    use( Rack::Session::Cookie,
         :key => 'puavo-accounts',
         :domain => CONFIG["puavo-rest"]["organisation_domain"],
         :path => '/accounts',
         :expire_after => 86400,
         :secret => CONFIG["session_secret"] )

    register Sinatra::R18n

    before do
      logger.info request.path
    end

    get "/accounts" do
      erb :register_email
    end

    post "/accounts" do
      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i.to_s,

        "email" => params["email"]
      }

      jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      @register_url = "https://#{ CONFIG["puavo-rest"]["organisation_domain"] }/accounts/authenticate/#{ jwt }"

      body = erb(:register_email_message, :layout => false)

      begin
        $mailer.send( :to => params["email"],
                      :subject => t.api.register_email.subject,
                      :body => body )
      rescue Net::SMTPSyntaxError
        return erb :error, :locals => { :error => t.errors.invalid_email_address }
      end
      logger.info "Send email to following address: #{ params["email"] }, IP-address: #{ request.ip }"
      redirect to("/accounts/complete?email=#{params["email"]}")
    end

    get "/accounts/complete" do
      erb :register_email_complete
    end

    get "/accounts/authenticate/:jwt" do
      begin
        jwt_data = JWT.decode(params[:jwt], CONFIG["jwt"]["secret"])
      rescue JWT::DecodeError
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      if (Time.now-60*60*24).to_i > jwt_data.first["iat"].to_i
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      session[:email] = jwt_data.first["email"]


      redirect "/accounts/user"
    end

    get "/accounts/user" do
      @user = User.new()

      unless session[:email]
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      erb :new

    end

    post "/accounts/user" do
      unless session[:email]
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      @user = User.new(params["user"])

      @user.data["email"] = session["email"]

      if params["user"]["password"] != params["user"]["password_confirmation"]
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
      end

      save_status = @user.save

      if not @user.email_error?
        return erb :error, :locals => { :error => t.views.new.email_unique_error(session[:email]) }
      end

      if not save_status or not @user.errors.empty?
        return erb :new
      end

      session.delete(:email)

      redirect "/accounts/successfully"
    end

    get "/accounts/successfully" do
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
