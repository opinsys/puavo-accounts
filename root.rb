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
  def initialize(host, domain, username, password)
    # XXX check that these are all set?
    @domain   = domain
    @host     = host
    @password = password
    @username = username
  end

  def auth_request(username, password)
    HTTP.basic_auth({
      :user => username,
      :pass => password
    }).headers({
      'host' => @domain,
    })
  end

  def get(url, params={}, username=nil, password=nil)
    username ||= @username
    password ||= @password
    auth_request(username, password).get("#{@host}#{url}", :params => params)
  end

  def post(url, params, json)
    auth_request(@username, @password).post("#{@host}#{url}", :params => params,
                                                              :json   => json)
  end
end

def louderrormsg(message)
  logger.error(message)
  begin
    $mattermost.send(logger, message)
  rescue StandardError => e
    logger.error('error in sending a message to Mattermost')
  end
end

def get_nested(from, *key)
  # XXX this should ensure that we do not get nil as value...
  # XXX if that is possible, those could be replaced by empty strings?

  now = from

  key.each_with_index do |k, i|
    is_last = (i == key.size - 1)
    raise KeyError, k unless now.include?(k)
    return now[k] if is_last
    now = now[k]
  end
end

def empty_field(name)  ; { 'name' => name, 'reason' => 'empty'             }; end
def invalid_field(name); { 'name' => name, 'reason' => 'failed_validation' }; end
def too_long(name)     ; { 'name' => name, 'reason' => 'too_long'          }; end

class MachineAlreadyInUse < StandardError; end
class MachineNotFound     < StandardError; end
class RestServerError     < StandardError; end
class SetPrimaryUserError < StandardError; end

class Machine
  attr_reader :dn, :domain, :hostname, :password

  def initialize(machinedata)
    # XXX our input validation could be stricter
    @dn       = get_nested(machinedata, 'dn')
    @domain   = get_nested(machinedata, 'organisation_domain')
    @hostname = get_nested(machinedata, 'hostname')
    @password = get_nested(machinedata, 'password')

    @target_school_dn = nil

    # XXX machine.hostname should not be trusted to construct urls?

    raise KeyError, "machine_dn"                  if @dn.empty?
    raise KeyError, "machine_organisation_domain" if @domain.empty?
    raise KeyError, "machine_hostname"            if @hostname.empty?
    raise KeyError, "machine_password"            if @password.empty?
  end

  def lookup_host(puavo_rest, id)
    # XXX should the hostname be validated first so that this url might not
    # XXX contain crazy stuff?
    res = puavo_rest.get("/v3/devices/#{@hostname}", {}, @dn, @password)

    if res.code == 401 then
      # the dn/password combo is not valid, so the machine is unlikely to exist
      louderrormsg("(#{id}) a registration was attempted from an " \
                   "unknown/unregistered device \"#{machine.hostname}\"!")
      raise MachineNotFound
    end

    if res.code != 200 then
      louderrormsg("(#{id}) received error #{res.code} from puavo-rest " \
                   "while determining if the client device \"#{machine.hostname}\" exists!")
      louderrormsg("(#{id}) full server response: |#{res}|")
      raise RestServerError
    end

    # the dn/password combo works and the device exists
    logger.info "(#{id}) found the device"

    device_data = JSON.parse(res.body)

    unless device_data['primary_user_dn'].nil? then
      louderrormsg("(#{id}) this device already has a primary user " \
                   "(\"#{device_data['primary_user_dn']}\")")
      raise MachineAlreadyInUse
    end

    logger.info "(#{id}) this device does not have a primary user"

    # Lookup target school so we can put the user in the same school
    # where the machine has been registered to.
    @target_school_dn = device_data['school_dn']
    if @target_school_dn.nil? then
      louderrormsg("(#{id}) target_school_dn is nil after the device information has been retrieved!")
      raise RestServerError
    end

    logger.info "(#{id}) target school DN: \"#{@target_school_dn}\""
  end

  def set_primary_user(puavo_rest, username)
    # Get the user DN
    res = puavo_rest.get("/v3/users/#{username}")
    if res.code != 200 then
      # XXX we could show the errors provided by puavo rest
      raise SetPrimaryUserError
    end

    user_dn = JSON.parse(res)['dn']

    logger.info "(#{id}) setting the primary user of the device \"#{@hostname} " \
                "to \"#{username}\" (\"#{user_dn}\")"

    # Update device info
    device_data = { 'primary_user_dn' => user_dn }

    res = puavo_rest.post("/v3/devices/#{@hostname}",
                         { :hostname => @hostname },
                         device_data)

    if res.code != 200 then
      # XXX we could show the errors provided by puavo rest
      raise SetPrimaryUserError
    end

    logger.info "(#{id}) successfully set \"#{username}\" as the " \
                "primary user of the device \"#{@hostname}\""
  end
end

class User
  # The maximum number of characters in first/last/username, password,
  # email and phone fields
  MAX_EMAIL_LENGTH      = 100
  MAX_FIRST_NAME_LENGTH = 32
  MAX_LAST_NAME_LENGTH  = 32
  MAX_PHONE_LENGTH      = 32
  MAX_USERNAME_LENGTH   = 65

  attr_reader :email, :first_name, :language, :last_name,
              :password, :password_confirm, :phone, :username

  def initialize(userdata)
    # XXX get_nested() should ensure that values can not be nil

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

  def validate_user(ret, id)
    # Part 1: Reject empty and too long fields (these should NOT happen as
    # the client does these same validations and will not let the form to be
    # submitted if the fields are not correct, but check anyway)
    if @first_name.empty? then
      logger.error "(#{id}) the user first name is empty"
      ret[:failed_fields] << empty_field('first_name')
      ret[:status] = :missing_data
    elsif @first_name.length > MAX_FIRST_NAME_LENGTH then
      logger.error "(#{id}) the user first name is too long"
      ret[:failed_fields] << too_long('first_name')
      ret[:status] = :missing_data
    end

    if @last_name.empty? then
      logger.error "(#{id}) the user last name is empty"
      ret[:failed_fields] << empty_field('last_name')
      ret[:status] = :missing_data
    elsif @last_name.length > MAX_LAST_NAME_LENGTH then
      logger.error "(#{id}) the user last name is too long"
      ret[:failed_fields] << too_long('last_name')
      ret[:status] = :missing_data
    end

    if @username.empty? then
      logger.error "(#{id}) the username is empty"
      ret[:failed_fields] << empty_field('username')
      ret[:status] = :missing_data
    elsif @username.length < 3 then
      logger.error "(#{id}) the username is too short"
      # argh (should never happen tho)
      ret[:failed_fields] << empty_field('username')
      ret[:status] = :missing_data
    elsif @username.length > MAX_USERNAME_LENGTH then
      logger.error "(#{id}) the username is too long"
      ret[:failed_fields] << too_long('username')
      ret[:status] = :missing_data
    end

    if @email.empty? then
      logger.error "(#{id}) user email is empty"
      ret[:failed_fields] << empty_field('email')
      ret[:status] = :missing_data
    elsif @email.length > MAX_EMAIL_LENGTH then
      logger.error "(#{id}) user email is too long"
      ret[:failed_fields] << too_long('email')
      ret[:status] = :missing_data
    end

    if @phone.length > MAX_PHONE_LENGTH then
      logger.error "(#{id}) user phone number is too long"
      ret[:failed_fields] << too_long('phone')
      ret[:status] = :missing_data
    else
      # The LDAP schema is *very* picky about phone numbers
      @phone.split('').each do |c|
        unless '0123456789-+'.include?(c) then
          logger.error "(#{id}) the phone number (\"#{@username}\") contains invalid characters"
          ret[:failed_fields] << invalid_field('phone')
          break
        end
      end
    end

    if ret[:status] != :ok then
      return 400, ret.to_json
    end

    # Part 2: Check email, username and passwords

    @username.split('').each do |c|
      unless 'abcdefghijklmnopqrstuvwxyz0123456789.-_'.include?(c) then
        logger.error "(#{id}) the username (\"#{@username}\") contains invalid characters"
        ret[:status] = :invalid_username
        return ret
      end
    end

    unless 'abcdefghijklmnopqrstuvwxyz'.include?(@username[0]) then
      logger.error "(#{id}) the username (\"#{@username}\") does not start with a letter"
      ret[:status] = :invalid_username
      return ret
    end

    # TODO: Validate the address better?
    if !@email.include?('@') || @email.count('.') == 0 then
      logger.error "(#{id}) the email address (\"#{@email}\") contains invalid characters"
      ret[:status] = :invalid_email
      return ret
    end

    if @password != @password_confirm then
      logger.error "(#{id}) password mismatch"
      ret[:status] = :password_mismatch
      return ret
    end

    unless CONFIG['locales'].include?(@language) then
      logger.error "(#{id}) language \"#{@language}\" is not valid"
      ret[:status] = :invalid_language
      return ret
    end

    return ret
  end

  def user_is_available(puavo_rest, ret)
    res = puavo_rest.get("/v3/users/#{@username}")
    if res.code == 200 then
      # found, username is already used
      logger.error "(#{id}) the username is NOT available"
      ret[:status] = :username_unavailable
      return ret
    end

    if res.code != 404 then
      # something failed
      louderrormsg("(#{id}) received error #{res.code} from puavo-rest " \
                   "while checking for username availability")
      louderrormsg("(#{id}) full server response: |#{res}|")
      ret[:status] = :server_error
      return ret
    end

    # 404 == not found, so the username is available
    logger.info "(#{id}) the username is available"

    return ret
  end

  def create_user(puavo_rest, ret)
    logger.info "(#{id}) trying to create a new account"

    user_data = {
      'email'      => @email,
      'first_name' => @first_name,
      'last_name'  => @last_name,
      'locale'     => @language,    # this has been validated already
      'password'   => @password,
      'roles'      => [ 'student' ],
      'school_dns' => @target_school_dn,
      'username'   => @username,
    }

    # puavo-rest does not like empty telephone numbers,
    # set this only if non-empty
    if !@phone.empty? then
      user_data['telephone_number'] = @phone
    end

    res = puavo_rest.post('/v3/users', {}, user_data)

    if res.code == 400 then
      # The account was NOT created
      logger.error "(#{id}) account creation failed, got a 400 error"
      logger.error "(#{id}) full response: |#{res}|"

      # Try to dig up more information from the puavo-rest's response
      res_json = JSON.parse(res)

      if res_json.dig('error', 'code') == 'ValidationError' then
        invalid = res_json.dig('error', 'meta', 'invalid_attributes')

        if invalid.include?('email') then
          email = invalid['email'][0]

          case email['code']
            when 'email_not_unique'
              # A duplicate email address
              logger.error "(#{id}) email address \"#{user.email}\" is already in use"

              ret[:status] = :duplicate_email
              return ret
            else
              # Something's wrong with the email address, but we don't know what
              louderrormsg("(#{id}) got a 400 error from puavo-rest, " \
                           "new account NOT created! #{res}")
              ret[:status] = :server_error
              return ret
          end

        elsif invalid.include?('username')
          case invalid['username'][0]['code']
            # XXX when 'do we get not unique error here?'
            when 'username_too_short'
              # The username is too short
              logger.error "(#{id}) username \"#{user.username}\" is too short"

              ret[:status] = :username_too_short
              return ret
          end
        end
      end

      # We don't know why the account could not be created. This is ugly,
      # because we can only return a "generic" error to the user, who
      # then has to contact us.
      ret[:status] = :server_error
      return ret
    end

    if res.code != 200 then
      # Something else failed
      louderrormsg("(#{id}) received error #{res.code} from puavo-rest, " \
                   "new account NOT created! #{res}")
      ret[:status] = :server_error
      return ret
    end

    return ret
  end
end

module PuavoAccounts
  # Setup Mattermost logging
  $mattermost = Mattermost::Bot.new(
    CONFIG['mattermost']['server']  || '',
    CONFIG['mattermost']['webhook'] || '',
    'user-registration')
  $mattermost.enable() if CONFIG['mattermost']['enabled']

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

    def send_confirmation_email(user, ret)
      # Send a confirmation email
      send_retried = false

      begin
        subject = t.api.register_email.subject

        body = erb(:successfully_email_message,
                   :layout => false,
                   :locals => {
                     :user => {
                       'first_name' => user.first_name,
                       'username'   => user.username,
                      }
                   })

        $mailer.send(:to => user.email, :subject => subject, :body => body)

        logger.info "(#{id}) sent a confirmation email to \"#{user.email}\""
        ret[:email_sent] = true
      rescue StandardError => error
        logger.error "(#{id}) email sending failed:"
        logger.error "(#{id})    address: #{user.email}"
        logger.error "(#{id})    error: #{error}"

        # XXX Try again if there was a network problem, but only once.
        # XXX (A dirty hack that can be removed once we have a properly
        # XXX functioning network).
        if !send_retried && error.to_s.include?('Connection reset by peer') then
          logger.error "(#{id})    --> Retrying once"
          send_retried = true
          sleep(1)
          retry
        end

        louderrormsg("(#{id}) new user \"#{user.username}\" successfully " \
                     "registered, but the confirmation email could not be sent: #{error}")

        ret[:email_sent] = false
      end

      return ret
    end

    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------

    post '/register_user' do
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
        loudaerrormsg("(#{id}) client sent malformed JSON: |#{body}|")

        ret[:status] = :malformed_json
        return 400, ret.to_json
      end

      begin
        # XXX our input validation could be stricter
        user = User.new(data['user'])
        machine = Machine.new(data['machine'])
      rescue StandardError => e
        louderrormsg("(#{id}) client sent incomplete user/machine data: |#{body}|")
        ret[:status] = :incomplete_data
        return 400, ret.to_json
      end

      logger.info "(#{id}) domain: #{ machine.domain }"

      # Is the domain configured in the config file?
      unless CONFIG['organisations'].include?(machine.domain)
        louderrormsg("(#{id}) unknown or invalid organisation \"#{machine.domain}\"")
        ret[:status] = :invalid_organisation_domain
        return 400, ret.to_json
      end

      rest_host = CONFIG['puavo-rest']
      rest_domain = machine.domain    # can use this directly, we've validated it

      org = CONFIG['organisations'][machine.domain]
      rest_user = org['username']
      rest_password = org['password']
      target_school_dn = nil

      puavo_rest = PuavoRestWrapper.new(rest_host, rest_domain, rest_user,
                                        rest_password)

      # ------------------------------------------------------------------------
      # Verify device registration

      logger.info "(#{id}) verifying client device (hostname=\"#{machine.hostname}\", " \
                  "dn=\"#{machine.dn}\", password=\"#{machine.password[0..9]}...\")"

      begin
        machine.lookup_host(puavo_rest, id)
      rescue MachineNotFound => e
        ret[:status] = :unknown_machine
        return 401, ret.to_json
      rescue MachineAlreadyInUse => e
        ret[:status] = :device_already_in_use
        return 401, ret.to_json
      rescue RestServerError => e
        ret[:status] = :server_error
        return 500, ret.to_json
      rescue StandardError => e
        louderrormsg("(#{id}) caught an exception while determining " \
                     "if the client device \"#{machine.hostname}\" exists: #{e}")
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Validate user data

      ret = user.validate_user(ret, id)
      if ret[:status] != :ok then
        return 400, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Is the username available?
      #
      # XXX this should be pointless if user creation could tell us that
      # XXX the reason for failure is that username is already reserved

      begin
        ret = user.user_is_available(puavo_rest, ret)
        case ret[:status]
          when :ok
            true
          when :username_unavailable
            return 409, ret.to_json
          else
            return 500, ret.to_json
        end
      rescue StandardError => e
        louderrormsg("(#{id}) caught an exception while checking " \
                     "if the username \"#{user.username}\" is available: #{e}")
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      logger.info "(#{id}) checking if the username (#{user.username}) is available"


      # ------------------------------------------------------------------------
      # Create the user!

      begin
        ret = user.create_user(puavo_rest)
        case ret[:status]
          when :ok
            true
          when :duplicate_email, :username_too_short
            return 409, ret.to_json
          else
            return 500, ret.to_json
        end
      rescue StandardError => e
        louderrormsg("(#{id}) caught an exception while creating the account: #{e}")
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # The account was created
      logger.info "(#{id}) new user account \"#{user.username}\" created!"

      begin
        # Try to set the newly-created account as the primary user
        # for the device. If this fails, do nothing, because the
        # first login will do it too.
        user.set_primary_user(puavo_rest, machine)
      rescue StandardError => e
        louderrormsg("(#{id}) could not set \"#{user.username}\" as the " \
                     "primary user for the device \"#{machine.hostname}\": #{e}")
      end

      ret = send_confirmation_email(user, ret)

      # ------------------------------------------------------------------------
      # All good?

      # If we get here, the account was created and nothing failed.

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
