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

def get_nested(from, *key)
  now = from

  key.each_with_index do |k, i|
    is_last = (i == key.size - 1)
    raise KeyError, k unless now.include?(k)
    return now[k] if is_last
    now = now[k]
  end
end

class Machine
  attr_reader :dn, :domain, :hostname, :password

  def initialize(machinedata)
    # XXX our input validation could be stricter
    @dn       = get_nested(machinedata, 'dn')
    @domain   = get_nested(machinedata, 'organisation_domain')
    @hostname = get_nested(machinedata, 'hostname')
    @password = get_nested(machinedata, 'password')

    # XXX machine.hostname should not be trusted to construct urls?

    raise KeyError, "machine_dn"                  if @dn.empty?
    raise KeyError, "machine_organisation_domain" if @domain.empty?
    raise KeyError, "machine_hostname"            if @hostname.empty?
    raise KeyError, "machine_password"            if @password.empty?
  end
end

class User
  attr_reader :email, :first_name, :language, :last_name,
              :password, :password_confirm, :phone, :username

  def initialize(userdata)
    # XXX our input validation could be stricter
    @email      = get_nested(userdata, 'email'     ).strip()
    @first_name = get_nested(userdata, 'first_name').strip()
    @language   = get_nested(userdata, 'language'  ).strip()
    @last_name  = get_nested(userdata, 'last_name' ).strip()
    @phone      = get_nested(userdata, 'phone'     ).strip()
    @username   = get_nested(userdata, 'username'  ).strip()

    @password_confirm = get_nested(userdata, 'password_confirm')
    @password         = get_nested(userdata, 'password')
  end
end

module PuavoAccounts
  # The maximum number of characters in first/last/username, password,
  # email and phone fields
  MAX_FIRST_NAME_LENGTH = 32
  MAX_LAST_NAME_LENGTH = 32
  MAX_USERNAME_LENGTH = 65
  MAX_EMAIL_LENGTH = 100
  MAX_PHONE_LENGTH = 32

  $mailer = PuavoAccounts::Mailer.new

  class Root < Sinatra::Base
    enable :logging

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

      ret = {
        :email_sent    => false,
        :failed_fields => [],
        :log_id        => id,
        :status        => :ok,
      }

      begin
        data = JSON.parse(body)
      rescue StandardError => e
        logger.error "(#{id}) client sent malformed JSON: |#{body}|"
        mattermost.send(logger, "(#{id}) client sent malformed JSON")

        ret[:status] = :malformed_json
        return 400, ret.to_json
      end

      begin
        # XXX our input validation could be stricter
        user = User.new(data['user'])
        machine = Machine.new(data['machine'])
      rescue StandardError => e
        logger.error "(#{id}) client sent incomplete user/machine data: |#{body}|"
        mattermost.send(logger, "(#{id}) client sent incomplete user/machine data")

        ret[:status] = :incomplete_data
        return 400, ret.to_json
      end

      logger.info "(#{id}) domain: #{ machine.domain }"

      # Is the domain configured in the config file?
      unless CONFIG['organisations'].include?(machine.domain)
        logger.error "(#{id}) unknown or invalid organisation \"#{machine.domain}\""
        mattermost.send(logger, "(#{id}) unknown or invalid organisation")

        ret[:status] = :invalid_organisation_domain
        return 400, ret.to_json
      end

      rest_host = CONFIG['puavo-rest']
      rest_domain = machine.domain    # can use this directly, we've validated it

      org = CONFIG['organisations'][machine.domain]
      rest_user = org['username']
      rest_password = org['password']
      target_school_dn = nil

      rest = PuavoRestWrapper.new(rest_host, rest_domain)

      # ------------------------------------------------------------------------
      # Verify device registration

      logger.info "(#{id}) verifying client device (hostname=\"#{machine.hostname}\", " \
                  "dn=\"#{machine.dn}\", password=\"#{machine.password[0..9]}...\")"

      begin
        res = rest.get(machine.dn, machine.password, "/v3/devices/#{machine.hostname}")

        if res.code == 200 then
          # the dn/password combo works and the device exists
          logger.info "(#{id}) found the device"

          # Put the user in the same school where the machine has been registered to
          data = JSON.parse(res.body)
          target_school_dn = data['school_dn']

          logger.info "(#{id}) target school DN: \"#{target_school_dn}\""

        elsif res.code == 401 then
          # the dn/password combo is not valid, so the machine is unlikely to exist
          logger.info "(#{id}) received error 401, client dn/password are not OK, " \
                      "assuming the device does not exist"
          mattermost.send(logger, "(#{id}) a registration was attempted from an " \
                          "unknown/unregistered device \"#{machine.hostname}\"!")

          ret[:status] = :unknown_machine
          return 401, ret.to_json
        else
          # something else failed
          logger.error "(#{id}) received error #{res.code} from puavo-rest, " \
                       "unable to determine device status"
          logger.error "(#{id}) full server response: |#{res}|"
          mattermost.send(logger, "(#{id}) received error #{res.code} from puavo-rest " \
                          "while determining if the client device \"#{machine.hostname}\" exists!")

          ret[:status] = :server_error
          return 500, ret.to_json
        end
      rescue StandardError => e
        logger.error "(#{id}) caught an exception while determining " \
                     "if the client device exists: #{e}"
        mattermost.send(logger, "(#{id}) caught an exception while determining " \
                        "if the client device \"#{machine.hostname}\" exists: #{e}")

        ret[:status] = :server_error
        return 500, ret.to_json
      end

      if target_school_dn.nil? then
        logger.error "(#{id}) target_school_dn is nil after the device information has been retrieved!"
        mattermost.send(logger, "(#{id}) target_school_dn is nil!")

        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Is this device already registered for some user?

      begin
        device = rest.get(rest_user, rest_password, "/v3/devices/#{machine.hostname}")
        device_data = JSON.parse(device)

        unless device_data['primary_user_dn'].nil? then
          logger.error "(#{id}) this device already has a primary user " \
                       "(\"#{device_data['primary_user_dn']}\")"
          mattermost.send(logger, "(#{id}) device \"#{machine.hostname}\" already " \
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
                        "if the device \"#{machine.hostname}\" already has a " \
                        "primary user: #{e}")

        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Validate user data

      # Part 1: Reject empty and too long fields (these should NOT happen as
      # the client does these same validations and will not let the form to be
      # submitted if the fields are not correct, but check anyway)
      if user.first_name.nil? || user.first_name.empty? then
        logger.error "(#{id}) the user first name is empty"
        ret[:failed_fields] << empty_field('first_name')
        ret[:status] = :missing_data
      else
        if user.first_name.length > MAX_FIRST_NAME_LENGTH then
          logger.error "(#{id}) the user first name is too long"
          ret[:failed_fields] << too_long('first_name')
          ret[:status] = :missing_data
        end
      end

      if user.last_name.nil? || user.last_name.empty? then
        logger.error "(#{id}) the user last name is empty"
        ret[:failed_fields] << empty_field('last_name')
        ret[:status] = :missing_data
      else
        if user.last_name.length > MAX_LAST_NAME_LENGTH
          logger.error "(#{id}) the user last name is too long"
          ret[:failed_fields] << too_long('last_name')
          ret[:status] = :missing_data
        end
      end

      if user.username.nil? || user.username.empty? then
        logger.error "(#{id}) the username is empty"
        ret[:failed_fields] << empty_field('username')
        ret[:status] = :missing_data
      else
        if user.username.length < 3 then
          logger.error "(#{id}) the username is too short"
          ret[:failed_fields] << empty_field('username')    # argh (should never happen tho)
          ret[:status] = :missing_data
        end

        if user.username.length > MAX_USERNAME_LENGTH then
          logger.error "(#{id}) the username is too long"
          ret[:failed_fields] << too_long('username')
          ret[:status] = :missing_data
        end
      end

      if user.email.empty? then
        logger.error "(#{id}) user email is empty"
        ret[:failed_fields] << empty_field('email')
        ret[:status] = :missing_data
      elsif user.email.length > MAX_EMAIL_LENGTH then
        logger.error "(#{id}) user email is too long"
        ret[:failed_fields] << too_long('email')
        ret[:status] = :missing_data
      end

      if user.phone.length > MAX_PHONE_LENGTH then
        logger.error "(#{id}) user phone number is too long"
        ret[:failed_fields] << too_long('phone')
        ret[:status] = :missing_data
      else
        # The LDAP schema is *very* picky about phone numbers
        user.phone.split('').each do |c|
          unless '0123456789-+'.include?(c)
            logger.error "(#{id}) the phone number (\"#{user.username}\") contains invalid characters"
            ret[:failed_fields] << invalid_field('phone')
            break
          end
        end
      end

      if ret[:status] != :ok
        return 400, ret.to_json
      end

      # Part 2: Check email, username and passwords

      # The regex that works in Python does nothing in Ruby
      user.username.split('').each do |c|
        unless 'abcdefghijklmnopqrstuvwxyz0123456789.-_'.include?(c)
          logger.error "(#{id}) the username (\"#{user.username}\") contains invalid characters"
          ret[:status] = :invalid_username
          return 400, ret.to_json
        end
      end

      unless 'abcdefghijklmnopqrstuvwxyz'.include?(user.username[0])
        logger.error "(#{id}) the username (\"#{user.username}\") does not start with a letter"
        ret[:status] = :invalid_username
        return 400, ret.to_json
      end

      # TODO: Validate the address better?
      if !user.email.include?('@') || user.email.count('.') == 0 then
        logger.error "(#{id}) the email address (\"#{user.email}\") contains invalid characters"
        ret[:status] = :invalid_email
        return 400, ret.to_json
      end

      if user.password != user.password_confirm then
        logger.error "(#{id}) password mismatch"
        ret[:status] = :password_mismatch
        return 400, ret.to_json
      end

      unless CONFIG['locales'].include?(user.language) then
        logger.error "(#{id}) language \"#{user.language}\" is not valid"
        ret[:status] = :invalid_language
        return 400, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Is the username available?

      logger.info "(#{id}) checking if the username (#{user.username}) is available"

      begin
        res = rest.get(rest_user, rest_password, "/v3/users/#{user.username}")

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
                        "if the username \"#{user.username}\" is available: #{e}")

        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Create the user!

      logger.info "(#{id}) trying to create a new account"

      user_data = {
        'first_name' => user.first_name,
        'last_name' => user.last_name,
        'username' => user.username,
        'email' => user.email,
        'password' => user.password,
        'locale' => user.language,    # this has been validated already
        'roles' => ['student'],
        'school_dns' => target_school_dn,
      }

      # puavo-rest does not like empty telephone numbers,
      # set this only if non-empty
      if !user.phone.empty? then
        user_data['telephone_number'] = user.phone
      end

      begin
        res = rest.post(rest_user, rest_password, '/v3/users', [], user_data)

        if res.code == 200
          # The account was created
          logger.info "(#{id}) new user account \"#{user.username}\" created!"

          # Try to set the newly-created account as the primary user
          # for the device. If this fails, do nothing, because the
          # first login will do it too.
          begin
            # Get the user DN
            result = rest.get(rest_user, rest_password, "/v3/users/#{user.username}")
            user_dn = JSON.parse(result)['dn']

            logger.info "(#{id}) setting the primary user of the device \"#{machine.hostname} " \
                        "to \"#{user.username}\" (\"#{user_dn}\")"

            # Update device info
            device_data = {
              'primary_user_dn' => user_dn
            }

            result = rest.post(rest_user, rest_password,
                               "/v3/devices/#{machine.hostname}",
                               { :hostname => machine.hostname },
                               device_data)

            logger.info "(#{id}) successfully set \"#{user.username}\" as the " \
                        "primary user of the device \"#{machine.hostname}\""
          rescue StandardError => e
            logger.error "(#{id}) could not set \"#{user.username}\" as the " \
                         "primary user for the device \"#{machine.hostname}\": #{e}"
            mattermost.send(logger, "(#{id}) new user successfully registered " \
                            "on device \"#{machine.hostname}\", but the user could " \
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
                           'first_name' => user.first_name,
                           'username' => user.username,
                          }
                       })

            $mailer.send(:to => user.email, :subject => subject, :body => body)

            logger.info "(#{id}) sent a confirmation email to \"#{user.email}\""
            ret[:email_sent] = true
          rescue StandardError => error
            logger.error "(#{id}) email sending failed:"
            logger.error "(#{id})    address: #{user.email}"
            logger.error "(#{id})    error: #{error}"

            # Try again if there was a network problem, but only once
            if !send_retried && error.to_s.include?('Connection reset by peer')
              logger.error "(#{id})    --> Retrying once"
              send_retried = true
              sleep(1)
              retry
            end

            mattermost.send(logger, "(#{id}) new user \"#{user.username}\" successfully " \
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
                  logger.error "(#{id}) email address \"#{user.email}\" is already in use"

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
                  logger.error "(#{id}) username \"#{user.username}\" is too short"

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

    # Everything else goes here
    get "*" do
      erb :layout
    end
  end
end
