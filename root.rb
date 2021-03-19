require "json"
require "jwt"
require "socket"
require "sinatra/base"
require "sinatra/json"
require "sinatra/r18n"
require "http"

require_relative "models/user"
require_relative "lib/mailer"
require_relative "lib/mattermost"

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

  # The maximum number of characters in first/last/username, password,
  # email and phone fields
  MAXIMUM_FIELD_LENGTH = 32

  $mailer = PuavoAccounts::Mailer.new

  class Root < Sinatra::Base

    enable :logging

    use( Rack::Session::Cookie,
         :key => 'puavo-accounts',
         :path => '/accounts',
         :expire_after => 86400,
         :secret => CONFIG["session_secret"] )

    register Sinatra::R18n

    before do
      request_headers = request.env.select{|k,v| k.start_with?("HTTP_")}
      if request_headers["HTTP_AUTHORIZATION"]
        request_headers["HTTP_AUTHORIZATION"] = "[FILTERED]"
      end
    end

    after do
      log_error
    end

    def log_error
      err = env["sinatra.error"]
      return if err.nil?

      logger.error "unhandled exception:"
      logger.error "    code: #{err.class.name}"
      logger.error "    message: #{err.message}"
      logger.error "    backtrace: #{err.backtrace}"
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

    def too_long(name)
      { 'name' => name, 'reason' => 'too_long' }
    end

    def invalid_field(name)
      { 'name' => name, 'reason' => 'failed_validation' }
    end

    post '/register_user' do
      # Setup Mattermost logging
      mattermost = Mattermost::Bot.new(
        CONFIG['mattermost']['server'] || '',
        CONFIG['mattermost']['webhook'] || '',
        'user-registration')

      mattermost.enable() if CONFIG['mattermost']['enabled']

      # Generate a unique ID for this request, to distinguish multiple requests
      # from each other. Some letters removed to prevent profanities, as the
      # code is displayed to users in case there are errors.
      id = 'ABCDEGIJKLMOQRTUVXYZ1234678'.split('').sample(10).join

      remote_addr = request.env['REMOTE_ADDR'] || '?'
      x_real_ip = request.env['HTTP_X_REAL_IP'] || '?'
      x_forwarded_for = request.env['HTTP_X_FORWARDED_FOR'] || '?'
      logger.info "(#{id}) received a new user registration request from IP=#{remote_addr} (x_real_ip=#{x_real_ip}, x_forwarded_for=#{x_forwarded_for})"

      body = request.body.read

      ret = {}
      ret[:log_id] = id
      ret[:status] = :ok
      ret[:email_sent] = false
      ret[:failed_fields] = []

      begin
        data = JSON.parse(body)
      rescue StandardError => e
        logger.error "(#{id}) client sent malformed JSON: |#{body}|"
        mattermost.send(logger, "(#{id}) client sent malformed JSON")

        ret[:status] = :malformed_json
        return 400, ret.to_json
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

        raise KeyError if machine_dn.empty? || machine_password.empty? || machine_hostname.empty?
      rescue StandardError => e
        logger.error "(#{id}) client sent incomplete user/machine data: |#{body}|"
        mattermost.send(logger, "(#{id}) client sent incomplete user/machine data")

        ret[:status] = :incomplete_data
        return 400, ret.to_json
      end

      # puavo-rest parameters
      rest_host = CONFIG['puavo-rest']['server']
      rest_domain = CONFIG['puavo-rest']['organisation_domain']
      rest_user = CONFIG['puavo-rest']['username']
      rest_password = CONFIG['puavo-rest']['password']
      target_school_dn = CONFIG['school_dns_for_users'][0]

      rest = PuavoRestWrapper.new(rest_host, rest_domain)

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
          mattermost.send(logger, "(#{id}) a registration was attempted from an " \
                          "unknown/unregistered device \"#{machine_hostname}\"!")

          ret[:status] = :unknown_machine
          return 401, ret.to_json
        else
          # something else failed
          logger.error "(#{id}) received error #{res.code} from puavo-rest, " \
                       "unable to determine device status"
          logger.error "(#{id}) full server response: |#{res}|"
          mattermost.send(logger, "(#{id}) received error #{res.code} from puavo-rest " \
                          "while determining if the client device \"#{machine_hostname}\" exists!")

          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception while determining " \
                     "if the client device exists: #{e}"
        mattermost.send(logger, "(#{id}) caught an exception while determining " \
                        "if the client device \"#{machine_hostname}\" exists: #{e}")

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
          mattermost.send(logger, "(#{id}) device \"#{machine_hostname}\" already " \
                          "has a primary user!")

          ret[:status] = :device_already_in_use
          return 401, ret.to_json
        else
          logger.info "(#{id}) this device does not have a primary user"
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception while determining "\
                     "if the device already has a primary user: #{e}"
        mattermost.send(logger, "(#{id}) caught an exception while determining " \
                        "if the device \"#{machine_hostname}\" already has a " \
                        "primary user: #{e}")

        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Validate user data

      # Part 1: Reject empty and too long fields (these should NOT happen as
      # the client does these same validations and will not let the form to be
      # submitted if the fields are not correct, but check anyway)
      if user_first_name.nil? || user_first_name.empty?
        logger.error "(#{id}) the user first name is empty"
        ret[:failed_fields] << empty_field('first_name')
        ret[:status] = :missing_data
      else
        if user_first_name.length > MAXIMUM_FIELD_LENGTH
          logger.error "(#{id}) the user first name is too long"
          ret[:failed_fields] << too_long('first_name')
          ret[:status] = :missing_data
        end
      end

      if user_last_name.nil? || user_last_name.empty?
        logger.error "(#{id}) the user last name is empty"
        ret[:failed_fields] << empty_field('last_name')
        ret[:status] = :missing_data
      else
        if user_last_name.length > MAXIMUM_FIELD_LENGTH
          logger.error "(#{id}) the user last name is too long"
          ret[:failed_fields] << too_long('last_name')
          ret[:status] = :missing_data
        end
      end

      if user_username.nil? || user_username.empty?
        logger.error "(#{id}) the username is empty"
        ret[:failed_fields] << empty_field('username')
        ret[:status] = :missing_data
      else
        if user_username.length < 3
          logger.error "(#{id}) the username is too short"
          ret[:failed_fields] << empty_field('username')    # argh (should never happen tho)
          ret[:status] = :missing_data
        end

        if user_username.length > MAXIMUM_FIELD_LENGTH
          logger.error "(#{id}) the username is too long"
          ret[:failed_fields] << too_long('username')
          ret[:status] = :missing_data
        end
      end

      if user_email.empty?
        logger.error "(#{id}) user email is empty"
        ret[:failed_fields] << empty_field('email')
        ret[:status] = :missing_data
      elsif user_email.length > 100     # permit very long addresses on purpose
        logger.error "(#{id}) user email is too long"
        ret[:failed_fields] << too_long('email')
        ret[:status] = :missing_data
      end

      if !user_phone.nil?
        if user_phone.strip.length > MAXIMUM_FIELD_LENGTH
          logger.error "(#{id}) user phone number is too long"
          ret[:failed_fields] << too_long('phone')
          ret[:status] = :missing_data
        else
          user_phone.split('').each do |c|
            unless '0123456789-+'.include?(c)
              logger.error "(#{id}) the phone number (\"#{user_username}\") contains invalid characters"
              ret[:failed_fields] << invalid_field('phone')
              break
            end
          end
        end
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

        unless 'abcdefghijklmnopqrstuvwxyz0123456789'.include?(user_username[0])
          logger.error "(#{id}) the username (\"#{user_username}\") does not start with a letter or number"
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
          mattermost.send(logger, "(#{id}) received error #{res.code} from puavo-rest " \
                          "while checking for username availability")

          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception while checking if " \
                     "the username is available: #{e}"
        mattermost.send(logger, "(#{id}) caught an exception while checking " \
                        "if the username \"#{user_username}\" is available: #{e}")

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
        'locale' => user_language,    # this has been validated already
        'roles' => ['student'],
        'school_dns' => target_school_dn,
      }

      # puavo-rest really does not like empty telephone numbers
      if !user_phone.nil? && !user_phone.strip.empty?
        user_data['telephone_number'] = user_phone
      end

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
                         "primary user for the device \"#{machine_hostname}\": #{e}"
            mattermost.send(logger, "(#{id}) new user successfully registered " \
                            "on device \"#{machine_hostname}\", but the user could " \
                            "not be set as the primary user: #{e}")
          end

          # Send a confirmation email
          send_retried = false

          begin
            subject = t.api.register_email.subject

            body = erb(:successfully_email_message,
                       :layout => false,
                       :locals => {
                         :user => {
                           'first_name' => user_first_name,
                           'username' => user_username,
                          }
                       })

            $mailer.send(:to => user_email, :subject => subject, :body => body)

            logger.info "(#{id}) sent a confirmation email to \"#{user_email}\""
            ret[:email_sent] = true
          rescue StandardError => error
            logger.error "(#{id}) email sending failed:"
            logger.error "(#{id})    address: #{user_email}"
            logger.error "(#{id})    error: #{error}"

            # Try again if there was a network problem, but only once
            if !send_retried && error.to_s.include?('Connection reset by peer')
              logger.error "(#{id})    --> Retrying once"
              send_retried = true
              sleep(1)
              retry
            end

            mattermost.send(logger, "(#{id}) new user \"#{user_username}\" successfully " \
                            "registered, but the confirmation email could not be sent: #{error}")

            ret[:email_sent] = false
          end

        elsif res.code == 400
          # The account was NOT created
          logger.error "(#{id}) account creation failed, got a 400 error"
          logger.error "(#{id}) full response: |#{res}|"

          # Try to dig up more information from the puavo-rest's response
          res_json = JSON.parse(res)

          if res_json.dig('error', 'code') == 'ValidationError'
            invalid = res_json.dig('error', 'meta', 'invalid_attributes')

            if invalid.include?('email')
              email = invalid['email'][0]

              case email['code']
                when 'email_not_unique'
                  # A duplicate email address
                  logger.error "(#{id}) email address \"#{user_email}\" is already in use"

                  ret[:status] = :duplicate_email
                  return 409, ret.to_json
                else
                  # Something's wrong with the email address, but we don't know what
                  mattermost.send(logger, "(#{id}) got a 400 error from puavo-rest, " \
                                  "new account NOT created! #{res}")

                  ret[:status] = :server_error
                  return 500, ret.to_json
              end

            elsif invalid.include?('username')
              case invalid['username'][0]['code']
                when 'username_too_short'
                  # The username is too short
                  logger.error "(#{id}) username \"#{user_username}\" is too short"

                  ret[:status] = :username_too_short
                  return 409, ret.to_json
              end
            end
          end

          # We don't know why the account could not be created. This is ugly,
          # because we can only return a "generic" error to the user, who
          # then has to contact us.
          ret[:status] = :server_error
          return 500, ret.to_json
        else
          # Something else failed
          logger.error "(#{id}) account creation failed, got error #{res.code}"
          logger.error "(#{id}) full response: |#{res}|"
          mattermost.send(logger, "(#{id}) received error #{res.code} from puavo-rest, " \
                          "new account NOT created! #{res}")

          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception \"#{e}\" while creating a new account"
        mattermost.send(logger, "(#{id}) caught an exception while creating the account: #{e}")

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
        logger.warn "post without email"
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
        logger.error "email sending failed:"
        logger.error "    address: #{email}"
        logger.error "    error: #{error}"
        @user.add_error("email", t.errors.invalid_email_address)
        return erb :register_email
      end

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
        logger.warn "invalid jwt data: #{params[:jwt]}"
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      if (Time.now-60*60*24).to_i > jwt_data.first["iat"].to_i
        logger.warn "jwt token has expired:"
        logger.warn "    token: #{params[:jwt]}"
        logger.warn "    data: #{jwt_data}"
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
        logger.warn "Cannot create user: no email in session"
        return erb :error, :locals => { :error => t.errors.invalid_jwt }
      end

      @user = User.new(params["user"])

      @user.data["email"] = session["email"]

      if params["user"]["password"] != params["user"]["password_confirmation"]
        logger.warn "Cannot create user: bad password confirmation"
        @user.add_error("password_confirmation", t.errors.password_confirmation.does_not_match)
      end

      save_status = @user.save

      if not @user.email_error?
        logger.warn "Cannot create user: email not unique"
        return erb :error, :locals => { :error => t.views.new.email_unique_error(session[:email]) }
      end

      if not save_status or not @user.errors.empty?
        return erb :new
      end

      session.delete(:email)

      logger.warn "User created ok"

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
