require "json"
require "jwt"
require "socket"
require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"
require "http"

require_relative "models/user"
require_relative "lib/mailer"
require_relative "lib/fluent"

class PuavoRestWrapper
  def initialize(host, domain)
    @host = host
    @domain = domain
  end

  def auth_request(username, password)
    HTTP.basic_auth({
      :user => username,
      :pass => password
    }).headers({
      'host' => @domain,
    })
  end

  def get(username, password, url, params={})
    auth_request(username, password).get("#{@host}#{url}", :params => params)
  end

  def put(username, password, url, params)
    auth_request(username, password).put("#{@host}#{url}", :params => params)
  end

  def post(username, password, url, params, json)
    auth_request(username, password).post("#{@host}#{url}", :params => params, :json => json)
  end
end

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


    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------

    def get_nested(from, *key)
      now = from

      key.each_with_index do |k, i|
        is_last = (i == key.size - 1)
        raise KeyError unless now.include?(k)
        return now[k] if is_last
        now = now[k]
      end
    end

    def empty_field(name)
      { 'name' => name, 'reason' => 'empty' }
    end

    def invalid_field(name)
      { 'name' => name, 'reason' => 'failed_validation' }
    end

    post '/register_user' do
      # Generate a unique ID for this request, to distinguish multiple requests
      # from each other. Some letters removed to prevent profanities, as the
      # code is displayed to users in case there are errors.
      id = 'ABCDEGIJKLMOQRTUVXYZ1234678'.split('').sample(10).join

      logger.info "(#{id}) received a new user registration request from #{request.env['REMOTE_ADDR']}"

      body = request.body.read

      begin
        data = JSON.parse(body)
      rescue StandardError => e
        logger.error "(#{id}) client sent malformed JSON: |#{body}|"
        return 400
      end

      begin
        user_first_name = get_nested(data, 'user', 'first_name').strip()
        user_last_name = get_nested(data, 'user', 'last_name').strip()
        user_username = get_nested(data, 'user', 'username').strip()
        user_email = get_nested(data, 'user', 'email').strip()
        user_password = get_nested(data, 'user', 'password')
        user_password_confirm = get_nested(data, 'user', 'password_confirm')
        user_language = get_nested(data, 'user', 'language').strip()
        user_phone = get_nested(data, 'user', 'phone').strip()
        machine_dn = get_nested(data, 'machine', 'dn').strip()
        machine_password = get_nested(data, 'machine', 'password').strip()
        machine_hostname = get_nested(data, 'machine', 'hostname').strip()
      rescue
        logger.error "(#{id}) client sent incomplete user/machine data: |#{body}|"
        return 400
      end

      # puavo-rest parameters
      rest_host = CONFIG['puavo-rest']['server']
      rest_domain = CONFIG['puavo-rest']['organisation_domain']
      rest_user = CONFIG['puavo-rest']['username']
      rest_password = CONFIG['puavo-rest']['password']
      target_school_dn = CONFIG['school_dns_for_users'][0]

      rest = PuavoRestWrapper.new(rest_host, rest_domain)

      ret = {}
      ret[:log_id] = id
      ret[:status] = :ok
      ret[:failed_fields] = []

      # ------------------------------------------------------------------------
      # Verify device registration

      logger.info "(#{id}) verifying client device (hostname=\"#{machine_hostname}\", " \
                  "dn=\"#{machine_dn}\", password=\"#{machine_password[0..9]}...\")"

      begin
        res = rest.get(machine_dn, machine_password, "/v3/devices/#{machine_hostname}")

        if res.code == 200
          # the dn/password combo works and the device exists
          logger.info "(#{id}) found the device"
        elsif res.code == 401
          # the dn/password combo is not valid, so the machine is unlikely to exist
          logger.info "(#{id}) received error 401, client dn/password are not OK, " \
                      "assuming the device does not exist"
          ret[:status] = :unknown_machine
          return 401, ret.to_json
        else
          # something else failed
          logger.error "(#{id}) received error code #{res.code} from puavo-rest, " \
                       "unable to determine device status"
          logger.error "(#{id}) full server response: |#{res}|"
          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception \"#{e}\" while determining " \
                     "if the client machine exists"
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Is this device already registered for some user?

      begin
        device = rest.get(rest_user, rest_password, "/v3/devices/#{machine_hostname}")
        device_data = JSON.parse(device)

        unless device_data['primary_user_dn'].nil?
          logger.error "(#{id}) this device already has a primary user " \
                       "(\"#{device_data['primary_user_dn']}\")"
          ret[:status] = :device_already_in_use
          return 401, ret.to_json
        else
          logger.info "(#{id}) this device does not have a primary user"
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception \"#{e}\" while determining if "\
                     "the machine has already been registered to some user"
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Validate user data

      # Part 1: Reject empty fields (these should NOT happen)
      if user_first_name.empty?
        logger.error "(#{id}) user first name is empty"
        ret[:failed_fields] << empty_field('first_name')
        ret[:status] = :missing_data
      end

      if user_last_name.empty?
        logger.error "(#{id}) user last name is empty"
        ret[:failed_fields] << empty_field('last_name')
        ret[:status] = :missing_data
      end

      if user_username.empty?
        logger.error "(#{id}) user username is empty"
        ret[:failed_fields] << empty_field('username')
        ret[:status] = :missing_data
      end

      if user_email.empty?
        logger.error "(#{id}) user email is empty"
        ret[:failed_fields] << empty_field('email')
        ret[:status] = :missing_data
      end

      if ret[:status] != :ok
        return 400, ret.to_json
      end

      # Part 2: Check email, username and passwords

      # The regex that works in Python does nothing in Ruby
      user_username.split('').each do |c|
        unless 'abcdefghijklmnopqrstuvwxyz0123456789.-_'.include?(c)
          logger.error "(#{id}) the username (\"#{user_username}\") contains invalid characters"
          ret[:status] = :invalid_username
          return 400, ret.to_json
        end
      end

      # TODO: Validate the address better?
      if !user_email.include?('@') || user_email.count('.') == 0
        logger.error "(#{id}) the email address (\"#{user_email}\") contains invalid characters"
        ret[:status] = :invalid_email
        return 400, ret.to_json
      end

      if user_password != user_password_confirm
        logger.error "(#{id}) password mismatch"
        ret[:status] = :password_mismatch
        return 400, ret.to_json
      end

      unless CONFIG['locales'].include?(user_language)
        logger.error "(#{id}) language \"#{user_language}\" is not valid"
        ret[:status] = :invalid_language
        return 400, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Is the username available?

      logger.info "(#{id}) checking if the username (#{user_username}) is available"

      begin
        res = rest.get(rest_user, rest_password, "/v3/users/#{user_username}")

        if res.code == 404
          # not found, so the username is available
          logger.info "(#{id}) the username is available"
        elsif res.code == 200
          # found, username is already used
          logger.error "(#{id}) the username is NOT available"
          ret[:status] = :username_unavailable
          return 409, ret.to_json
        else
          # something else failed
          logger.error "(#{id}) received error code #{res.code} from puavo-rest, " \
                       "unable to determine if the username is available"
          logger.error "(#{id}) full server response: |#{res}|"
          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception \"#{e}\" while checking if " \
                     "the username is available"
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Create the user!

      logger.info "(#{id}) trying to create a new account"

      user_data = {
        'first_name' => user_first_name,
        'last_name' => user_last_name,
        'username' => user_username,
        'email' => user_email,
        'password' => user_password,
        'telephone_number' => user_phone,
        'locale' => user_language,    # this has been validated already
        'roles' => ['student'],
        'school_dns' => target_school_dn,
      }

      begin
        res = rest.post(rest_user, rest_password, '/v3/users', [], user_data)

        if res.code == 200
          # The account was created
          logger.info "(#{id}) new user account \"#{user_username}\" created!"

          # Try to set the newly-created account as the primary user
          # for the device. If this fails, do nothing, because the
          # first login will do it too.
          begin
            # Get the user DN
            result = rest.get(rest_user, rest_password, "/v3/users/#{user_username}")
            user_dn = JSON.parse(result)['dn']

            logger.info "(#{id}) setting the primary user of the device \"#{machine_hostname} " \
                        "to \"#{user_username}\" (\"#{user_dn}\")"

            # Update device info
            device_data = {
              'primary_user_dn' => user_dn
            }

            result = rest.post(rest_user, rest_password,
                               "/v3/devices/#{machine_hostname}",
                               { :hostname => machine_hostname },
                               device_data)

            logger.info "(#{id}) successfully set \"#{user_username}\" as the " \
                        "primary user of the device \"#{machine_hostname}\""
          rescue StandardError => e
            logger.error "(#{id}) could not set \"#{user_username}\" as the " \
                         "primary user for the device \"#{machine_hostname}\""
            logger.error "(#{id}) #{e}"
          end
        elsif res.code == 400
          # The account was NOT created
          logger.error "(#{id}) account creation failed, got a 400 error"
          logger.error "(#{id}) full response: |#{res}|"

          # Is it a duplicate email address?
          res_json = JSON.parse(res)

          if res_json.dig('error', 'code') == 'ValidationError'
            invalid = res_json.dig('error', 'meta', 'invalid_attributes')

            if invalid.include?('email')
              email = invalid['email'][0]

              case email['code']
                when 'email_not_unique'
                  # Yes, this email address is already in use
                  logger.error "(#{id}) email address \"#{user_email}\" is already in use"
                  ret[:status] = :duplicate_email
                  return 409, ret.to_json
                else
                  # Don't know then
                  ret[:status] = :server_error
                  return 500, ret.to_json
              end
            end
          end
        else
          # Something else failed
          logger.error "(#{id}) account creation failed, got error #{res.code}"
          logger.error "(#{id}) full response: |#{res}|"
          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception \"#{e}\" while creating a new account"
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # All good?

      # If we get here, the account was created and nothing failed.
      # ret['status'] should still be :ok

      return 200, ret.to_json
    end

    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------


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

      body = erb(:successfully_email_message, :layout => false, :locals => { :user => @user.data })

      $mailer.send( :to =>  @user.data["email"],
                    :subject => t.api.register_email.subject,
                    :body => body )

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
