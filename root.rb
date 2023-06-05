require 'http'
require 'json'
require 'sinatra/base'
require 'sinatra/json'
require 'sinatra/r18n'
require 'uri'

require_relative 'lib/mailer'
require_relative 'lib/mattermost'

class OrgNotConfigured < StandardError; end

class PuavoRestWrapper
  def initialize(domain, log)
    unless CONFIG['organisations'].include?(domain) then
      log.louderror("unknown or invalid organisation \"#{ domain }\"")
      raise OrgNotConfigured
    end

    host = CONFIG['puavo-rest']
    org = CONFIG['organisations'][domain]

    @domain   = domain
    @host     = host
    @password = org['password']
    @username = org['username']
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
    username ||= @username
    password ||= @password
    auth_request(username, password).get("#{@host}#{url}", :params => params)
  end

  def post(url, params, json)
    auth_request(@username, @password).post("#{@host}#{url}", :params => params,
                                                              :json   => json)
  end
end

class LogWithId
  attr_reader :id

  def initialize(logger)
    # Generate a unique ID for this request, to distinguish multiple requests
    # from each other. Some letters removed to prevent profanities, as the
    # code is displayed to users in case there are errors.
    @id = 'ABCDEGIJKLMOQRTUVXYZ1234678'.split('').sample(10).join
    @logger = logger
  end

  def error(msg)
    @logger.error("(#{@id}) #{msg}")
  end

  def info(msg)
    @logger.info("(#{@id}) #{msg}")
  end

  def loudinfo(msg)
    info(msg)
    send_to_mattermost(msg)
  end

  def louderror(msg)
    error(msg)
    send_to_mattermost("ERROR: #{msg}")
  end

  def request_info(msg, request)
    remote_addr     = request.env['REMOTE_ADDR']          || '?'
    x_real_ip       = request.env['HTTP_X_REAL_IP']       || '?'
    x_forwarded_for = request.env['HTTP_X_FORWARDED_FOR'] || '?'

    info "#{ msg } from IP=#{ remote_addr } (x_real_ip=#{ x_real_ip }, x_forwarded_for=#{ x_forwarded_for })"
  end

  def send_to_mattermost(msg)
    Thread.new do
      begin
        $mattermost.send(@logger, msg)
      rescue StandardError => e
        @logger.error("error in sending a message to Mattermost: #{e}")
      end
    end
  end
end

def empty_field(name)  ; { 'name' => name, 'reason' => 'empty'             }; end
def invalid_field(name); { 'name' => name, 'reason' => 'failed_validation' }; end
def too_long(name)     ; { 'name' => name, 'reason' => 'too_long'          }; end

class Machine
  attr_reader :dn, :domain, :hostname, :password, :primary_user,
              :primary_user_dn, :target_school_dn

  def initialize(machinedata, log)
    @log = log

    raise 'machine data is not a hash' unless machinedata.kind_of?(Hash)

    attrlist = %w(dn hostname organisation_domain password)
    attrlist.each do |attr|
      raise "machine attribute #{ attr } is missing or empty" \
        unless machinedata[attr].kind_of?(String) && !machinedata[attr].empty?
    end

    # check hostname more carefully, it is used to construct urls
    raise 'machine hostname contains /' \
      if machinedata['hostname'].include?('/')

    @dn       = machinedata['dn']
    @domain   = machinedata['organisation_domain']
    @hostname = machinedata['hostname']
    @password = machinedata['password']

    @primary_user     = nil
    @primary_user_dn  = nil
    @target_school_dn = nil
  end

  def lookup_host(puavo_rest, ret)
    res = puavo_rest.get("/v3/devices/#{@hostname}", {}, @dn, @password)

    if res.code == 401 then
      # the dn/password combo is not valid, so the machine is unlikely to exist
      @log.louderror("a registration was attempted from an " \
                     "unknown/unregistered device \"#{@hostname}\"!")
      ret[:status] = :unknown_machine
      return ret
    end

    if res.code != 200 then
      @log.louderror("received error #{res.code} from puavo-rest " \
                     "while determining if the client device \"#{@hostname}\" exists!")
      @log.louderror("full server response: |#{res}|")
      ret[:status] = :server_error
      return ret
    end

    # the dn/password combo works and the device exists
    @log.info "found the device #{@hostname} from Puavo"

    device_data = JSON.parse(res.body)

    if device_data['primary_user_dn'] then
      @primary_user    = device_data['primary_user']
      @primary_user_dn = device_data['primary_user_dn']
      ret[:status] = :device_already_in_use
      return ret
    end

    @log.info "this device does not have a primary user"

    # Lookup target school so we can put the user in the same school
    # where the machine has been registered to.
    @target_school_dn = device_data['school_dn']
    if @target_school_dn.nil? then
      @log.louderror("target_school_dn is nil after the device information " \
                     "has been retrieved!")
      ret[:status] = :server_error
      return ret
    end

    @log.info "target school DN: \"#{@target_school_dn}\""

    return ret
  end

  def set_primary_user(puavo_rest, username)
    # Get the user DN
    res = puavo_rest.get("/v3/users/#{username}")
    if res.code != 200 then
      raise "could not retrieve information for #{username}: " \
            "puavo-rest returned #{res.code}"
    end

    user_dn = JSON.parse(res)['dn']

    @log.info "setting the primary user of the device \"#{@hostname} " \
              "to \"#{username}\" (\"#{user_dn}\")"

    # Update device info
    device_data = { 'primary_user_dn' => user_dn }

    res = puavo_rest.post("/v3/devices/#{@hostname}",
                         { :hostname => @hostname },
                         device_data)

    if res.code != 200 then
      raise "could not update primary user #{username} to #{@hostname}: " \
            "puavo-rest returned #{res.code}"
    end

    @log.info "successfully set \"#{username}\" as the " \
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

  def initialize(userdata, log)
    @log = log

    raise 'user data is not a hash' unless userdata.kind_of?(Hash)

    # these can be empty
    raise 'user email is not a string' unless userdata['email'].kind_of?(String)
    raise 'user phone is not a string' unless userdata['phone'].kind_of?(String)

    # these can not be empty
    attrlist = %w(first_name language last_name password password_confirm
                  username)
    attrlist.each do |attr|
      raise "user attribute #{ attr } is missing" \
        unless userdata[attr].kind_of?(String)
    end

    # check username more carefully, it is used to construct urls
    raise 'user username contains /' if userdata['username'].include?('/')

    @email      = userdata['email'     ].strip()
    @first_name = userdata['first_name'].strip()
    @language   = userdata['language'  ].strip()
    @last_name  = userdata['last_name' ].strip()
    @phone      = userdata['phone'     ].strip()
    @username   = userdata['username'  ].strip()

    # no strip for these
    @password         = userdata['password']
    @password_confirm = userdata['password_confirm']
  end

  def validate_user(ret)
    # Part 1: Reject empty and too long fields (these should NOT happen as
    # the client does these same validations and will not let the form to be
    # submitted if the fields are not correct, but check anyway)
    if @first_name.empty? then
      @log.error 'the user first name is empty'
      ret[:failed_fields] << empty_field('first_name')
      ret[:status] = :missing_data
    elsif @first_name.length > MAX_FIRST_NAME_LENGTH then
      @log.error "the user first name is too long"
      ret[:failed_fields] << too_long('first_name')
      ret[:status] = :missing_data
    end

    if @last_name.empty? then
      @log.error 'the user last name is empty'
      ret[:failed_fields] << empty_field('last_name')
      ret[:status] = :missing_data
    elsif @last_name.length > MAX_LAST_NAME_LENGTH then
      @log.error "the user last name is too long"
      ret[:failed_fields] << too_long('last_name')
      ret[:status] = :missing_data
    end

    if @username.empty? then
      @log.error 'the username is empty'
      ret[:failed_fields] << empty_field('username')
      ret[:status] = :missing_data
    elsif @username.length < 3 then
      @log.error 'the username is too short'
      # argh (should never happen tho)
      ret[:failed_fields] << empty_field('username')
      ret[:status] = :missing_data
    elsif @username.length > MAX_USERNAME_LENGTH then
      @log.error 'the username is too long'
      ret[:failed_fields] << too_long('username')
      ret[:status] = :missing_data
    end

    if @email.length > MAX_EMAIL_LENGTH then
      @log.error 'user email is too long'
      ret[:failed_fields] << too_long('email')
      ret[:status] = :invalid_email
    end

    if @phone.length > MAX_PHONE_LENGTH then
      @log.error 'user phone number is too long'
      ret[:failed_fields] << too_long('phone')
      ret[:status] = :missing_data
    else
      # The LDAP schema is *very* picky about phone numbers
      @phone.split('').each do |c|
        unless '0123456789-+'.include?(c) then
          @log.error "the phone number (\"#{@username}\") contains invalid characters"
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
        @log.error "the username (\"#{@username}\") contains invalid characters"
        ret[:status] = :invalid_username
        return ret
      end
    end

    unless 'abcdefghijklmnopqrstuvwxyz'.include?(@username[0]) then
      @log.error "the username (\"#{@username}\") does not start with a letter"
      ret[:status] = :invalid_username
      return ret
    end

    if !@email.empty? && @email !~ URI::MailTo::EMAIL_REGEXP then
      @log.error "the email address (\"#{@email}\") is not valid"
      ret[:status] = :invalid_email
      return ret
    end

    if @password != @password_confirm then
      @log.error 'password mismatch'
      ret[:status] = :password_mismatch
      return ret
    end

    unless CONFIG['locales'].include?(@language) then
      @log.error "language \"#{@language}\" is not valid"
      ret[:status] = :invalid_language
      return ret
    end

    return ret
  end

  def create_user(puavo_rest, machine, ret)
    @log.info 'trying to create a new account'

    # these are required attributes
    user_data = {
      'first_name' => @first_name,
      'last_name'  => @last_name,
      'locale'     => @language,    # this has been validated already
      'password'   => @password,
      'roles'      => [ 'student' ],
      'school_dns' => machine.target_school_dn,
      'username'   => @username,
    }

    # email is not required
    if !@email.empty? then
      user_data['email'] = @email
    end

    # puavo-rest does not like empty telephone numbers,
    # set this only if non-empty
    if !@phone.empty? then
      user_data['telephone_number'] = @phone
    end

    res = puavo_rest.post('/v3/users', {}, user_data)

    if res.code == 400 then
      # The account was NOT created
      @log.error "account creation failed, got a 400 error"
      @log.error "full response: |#{res}|"

      # Try to dig up more information from the puavo-rest's response
      res_json = JSON.parse(res)

      if res_json.dig('error', 'code') == 'ValidationError' then
        invalid = res_json.dig('error', 'meta', 'invalid_attributes')

        if invalid.include?('email') then
          invalid['email'].each do |attr_error|
            case attr_error['code']
              when 'email_not_unique'
                # A duplicate email address
                @log.error "email address \"#{@email}\" is already in use"

                ret[:status] = :duplicate_email
                return ret
              else
                # Something's wrong with the email address, but we don't know what
                @log.louderror("got a 400 error from puavo-rest, " \
                               "new account NOT created! #{res}")
                ret[:status] = :server_error
                return ret
            end
          end

        elsif invalid.include?('username')
          invalid['username'].each do |attr_error|
            case attr_error['code']
              when 'username_not_unique'
                @log.error "username \"#{@username}\" is not unique"
                ret[:status] = :username_unavailable
                return ret
              when 'username_too_short'
                @log.error "username \"#{@username}\" is too short"
                ret[:status] = :username_too_short
                return ret
            end
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
      @log.louderror("received error #{res.code} from puavo-rest, " \
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
      err = env['sinatra.error']
      return if err.nil?
      return if err.instance_of?(Sinatra::NotFound)

      logger.error "unhandled exception:"
      logger.error "    code: #{err.class.name}"
      logger.error "    message: #{err.message}"
      logger.error "    backtrace: #{err.backtrace}"
    end

    not_found do
      status 404
    end

    def check_if_resent(puavo_rest, user, machine)
      # If this user is the same as the primary user of this machine
      # and user password matches (user can fetch his/her own data), we decide
      # that the same form has been resent and should not continue with
      # normal user registration.
      res = puavo_rest.get("/v3/users/#{user.username}", {}, user.username,
                           user.password)
      if res.code == 200 then
        user_data = JSON.parse(res.body)
        return true if user_data['dn'] == machine.primary_user_dn
      end

      return false
    end

    def send_confirmation_email(user, machine, log)
      if user.email.empty? then
        log.info 'user did not provide an email address, not sending email'
        return
      end

      begin
        subject = t.api.register_email.subject

        body = erb(:successfully_email_message,
                   :layout => false,
                   :locals => {
                     :machine => {
                       'domain' => machine.domain,
                     },
                     :user => {
                       'first_name' => user.first_name,
                       'username'   => user.username,
                      }
                   })

        Thread.new do
          send_retried = false

          begin
            $mailer.send(:to => user.email, :subject => subject, :body => body)
            log.info "sent a confirmation email to \"#{user.email}\""
          rescue StandardError => error
            log.error "email sending failed:"
            log.error "   address: #{user.email}"
            log.error "   error: #{error}"

            # XXX Try again if there was a network problem, but only once.
            # XXX (A dirty hack that can be removed once we have a properly
            # XXX functioning network).
            if !send_retried && error.to_s.include?('Connection reset by peer') then
              log.error "    --> Retrying once"
              send_retried = true
              sleep(1)
              retry
            end

            log.louderror("new user \"#{user.username}\" successfully " \
                          "registered, but the confirmation email could not be sent: #{error}")
          end
        end
      rescue StandardError => error
        log.louderror("could not construct an email to send: #{ error }")
      end
    end

    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------

    post '/register_user/check_host' do
      log = LogWithId.new(logger)

      log.request_info('received a check host request', request)

      ret = {
        :primary_user => nil,
        :status       => :ok,
      }

      begin
        data = JSON.parse(request.body.read)
        machine = Machine.new(data, log)
        puavo_rest = PuavoRestWrapper.new(machine.domain, log)
        ret = machine.lookup_host(puavo_rest, ret)
        ret[:primary_user] = machine.primary_user
      rescue OrgNotConfigured => e
        ret[:status] = :invalid_organisation_domain
        return 400, ret.to_json
      rescue StandardError => e
        log.error("could not lookup host information from puavo:" \
                     + " #{ e.message }")
        ret[:status] = :error
        return 400, ret.to_json
      end

      log.info("returning primary user for host #{ machine.hostname }:" \
                 + " (#{ ret[:primary_user] })")

      return 200, ret.to_json
    end

    post '/register_user' do
      log = LogWithId.new(logger)

      log.request_info('received a new user registration request', request)

      body = request.body.read

      ret = {
        :failed_fields => [],
        :log_id        => log.id,
        :status        => :ok,
      }

      begin
        data = JSON.parse(body)
      rescue StandardError => e
        log.louderror('client sent malformed JSON')
        ret[:status] = :malformed_json
        return 400, ret.to_json
      end

      begin
        raise 'data sent by client is not a hash' unless data.kind_of?(Hash)

        user = User.new(data['user'], log)
        machine = Machine.new(data['machine'], log)

      rescue StandardError => e
        log.louderror("client sent incomplete user/machine data: #{ e.message }")
        ret[:status] = :incomplete_data
        return 400, ret.to_json
      end

      log.info "domain: #{ machine.domain }"

      # We can use machine.domain but only if we use lookup_host() soon
      # so ensure that machine really belongs to this domain.
      begin
        puavo_rest = PuavoRestWrapper.new(machine.domain, log)
      rescue OrgNotConfigured => e
        ret[:status] = :invalid_organisation_domain
        return 400, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Verify device registration

      log.info "verifying client device (hostname=\"#{machine.hostname}\", " \
               "dn=\"#{machine.dn}\", password=\"#{machine.password[0..9]}...\")"

      begin
        ret = machine.lookup_host(puavo_rest, ret)
        if machine.primary_user_dn then
          if check_if_resent(puavo_rest, user, machine) then
            log.loudinfo("a resent register_user submission for " \
                         "#{ user.username } on #{ machine.hostname }")
            ret[:status] = :resent
            return 200, ret.to_json
          end
          log.louderror("this device already has a primary user " \
                        "(\"#{machine.primary_user_dn}\")")
        end

        case ret[:status]
          when :ok
            true
          when :device_already_in_use, :unknown_machine
            return 401, ret.to_json
          else
            return 500, ret.to_json
        end
      rescue StandardError => e
        log.louderror("caught an exception while determining " \
                      "if the client device \"#{machine.hostname}\" exists: #{e}")
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Validate user data

      ret = user.validate_user(ret)
      if ret[:status] != :ok then
        return 400, ret.to_json
      end

      # ------------------------------------------------------------------------
      # Create the user!

      begin
        ret = user.create_user(puavo_rest, machine, ret)
        case ret[:status]
          when :ok
            true
          when :duplicate_email, :username_too_short, :username_unavailable
            return 409, ret.to_json
          else
            return 500, ret.to_json
        end
      rescue StandardError => e
        log.louderror("caught an exception while creating the account: #{e}")
        ret[:status] = :server_error
        return 500, ret.to_json
      end

      # The account was created
      log.loudinfo "new user account \"#{user.username}\" was created " \
                   "for host #{machine.hostname}"

      begin
        # Try to set the newly-created account as the primary user
        # for the device. If this fails, do nothing, because the
        # first login will do it too.
        machine.set_primary_user(puavo_rest, user.username)
      rescue StandardError => e
        log.louderror("could not set \"#{user.username}\" as the " \
                      "primary user for the device \"#{machine.hostname}\": #{e}")
      end

      send_confirmation_email(user, machine, log)

      # ------------------------------------------------------------------------
      # All good?

      # If we get here, the account was created and nothing failed.

      return 200, ret.to_json
    end
  end
end
