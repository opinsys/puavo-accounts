require "json"
require "jwt"
require "socket"
require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"

require_relative "models/user"
require_relative "lib/mailer"
require_relative "lib/fluent"

module PuavoAccounts
  HOSTNAME = Socket.gethostname
  FQDN = Socket.gethostbyname(Socket.gethostname).first

  FLUENT_LOGGER = FluentWrap.new(
    "puavo-accounts",
    :hostname => HOSTNAME,
    :fqdn => FQDN
  )

  FLUENT_LOGGER.info "starting"

  $mailer = PuavoAccounts::Mailer.new

  class Root < Sinatra::Base

    enable :logging

    use( Rack::Session::Cookie,
         :key => 'puavo-accounts',
         :path => '/accounts',
         :expire_after => 86400,
         :secret => CONFIG["session_secret"] )

    register Sinatra::R18n

    def fluent_logger
      Thread.current[:fluent]
    end

    def fluent_logger=(logger)
      Thread.current[:fluent] = logger
    end


    before do
      request_headers = request.env.select{|k,v| k.start_with?("HTTP_")}
      if request_headers["HTTP_AUTHORIZATION"]
        request_headers["HTTP_AUTHORIZATION"] = "[FILTERED]"
      end

      self.fluent_logger = FLUENT_LOGGER.merge({
        "request" => {
          "uuid" => (0...25).map{ ('a'..'z').to_a[rand(26)] }.join,
          "ip" => env["HTTP_X_REAL_IP"] || request.ip,
          "host" => request.host,
          "url" => request.url,
          "method" => env["REQUEST_METHOD"],
          "headers" => request_headers
        }
      })

      fluent_logger.info "request start"
      logger.info request.path
    end

    after do
      log_error
    end

    def log_error
      err = env["sinatra.error"]
      return if err.nil?
      fluent_logger.error "unhandled exception", {
        "code" => err.class.name,
        "message" => err.message,
        "backtrace" => err.backtrace
      }
    end

    get "/accounts" do
      @user = User.new

      erb :register_email
    end

    post "/accounts" do
      @user = User.new(params["user"])

      email = params["user"]["email"]

      if email.nil? or email.empty?
        @user.add_error("email", t.errors.invalid_email_address)
        fluent_logger.warn "post without email"
        return erb :register_email
      end

      jwt_data = {
        # Issued At
        "iat" => Time.now.to_i.to_s,

        "email" => email
      }

      jwt = JWT.encode(jwt_data, CONFIG["jwt"]["secret"])

      @register_url = "https://#{ CONFIG["puavo-rest"]["organisation_domain"] }/accounts/authenticate/#{ jwt }"
      logger.info "Registration URL: #{ @register_url }"
      puts "#"*80
      puts "Registration URL: #{ @register_url }"
      puts "#"*80

      body = erb(:register_email_message, :layout => false)

      begin
        $mailer.send( :to => email,
                      :subject => t.api.register_email.subject,
                      :body => body )
      rescue Net::SMTPSyntaxError, Net::SMTPFatalError, ArgumentError => error
        fluent_logger.error "email sending failed", {
          "email" => email,
          "error" => error
        }
        @user.add_error("email", t.errors.invalid_email_address)
        return erb :register_email
      end

      fluent_logger.info "registration email sent ok", {
        "email" => email
      }
      logger.info "Send email to following address: #{ email }, IP-address: #{ request.ip }"
      redirect to("/accounts/complete?email=#{ email }")
    end

    get "/accounts/complete" do
      erb :register_email_complete
    end

    get "/accounts/authenticate/:jwt" do
      begin
        jwt_data = JWT.decode(params[:jwt], CONFIG["jwt"]["secret"])
      rescue JWT::DecodeError
        fluent_logger.warn "invalid jwt data", "jwt_token" => params[:jwt]
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      if (Time.now-60*60*24).to_i > jwt_data.first["iat"].to_i
        fluent_logger.warn "jwt token expired", {
          "jwt_token" => params[:jwt],
          "jwt_data" => jwt_data
        }
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
        fluent_logger.warn "Cannot create user", "reason" => "No email in session"
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      @user = User.new(params["user"])

      @user.data["email"] = session["email"]

      if params["user"]["password"] != params["user"]["password_confirmation"]
        fluent_logger.warn "Cannot create user", {
          "reason" => "bad password confirmation",
          "params" => params
        }
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
      end

      save_status = @user.save

      if not @user.email_error?
        fluent_logger.warn "Cannot create user", {
          "reason" => "email not unique",
          "params" => params
        }
        return erb :error, :locals => { :error => t.views.new.email_unique_error(session[:email]) }
      end

      if not save_status or not @user.errors.empty?
        return erb :new
      end

      session.delete(:email)

      fluent_logger.warn "User created ok"
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

        @error = nil
        if @user.errors[attribute]
          @error = @user.errors[attribute].first
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

      def h(text)
        Rack::Utils.escape_html(text)
      end

    end

  end
end
