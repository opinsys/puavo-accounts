# frozen_string_literal: true

require 'http'
require 'jwt'
require 'openssl'

class PuavoRestWrapper
  def initialize(domain, log)
    unless CONFIG['enabled_in_organisations'].include?(domain) then
      log.louderror("unknown or invalid organisation \"#{ domain }\"")
      raise OrgNotConfigured
    end

    @domain = domain
    @host   = CONFIG['puavo-rest']['server']
    @log    = log
  end

  def get(url, auth: :basic, username: nil, password: nil, params: {})
    auth_request(auth, username, password).get("#{@host}#{url}", params: params)
  end

  def post(url, auth: :basic, username: nil, password: nil, params: nil, json: nil)
    auth_request(auth, username, password).post("#{@host}#{url}", params: params, json: json)
  end

  private

  def auth_request(auth, username, password)
    case auth
      # Basic auth cannot be removed because it is used, for example, when the machine is authenticated
      when :basic
        HTTP.basic_auth({
          user: username,
          pass: password
        }).headers({
          'host' => @domain,
        })

      when :oauth2
        token = acquire_access_token
        raise 'no access token' if token.nil?
        HTTP.auth("Bearer #{token}").headers({ 'host' => @domain })

      else
        raise "unknown authentication method #{auth.inspect}"
    end
  end

  # Returns an access token, or nil if there was an error
  def acquire_access_token
    token_file = CONFIG['oauth2']['token_cache_file']

    # Cached already?
    begin
      token_data = File.read(token_file)

      # Is the token still valid?
      JWT.decode(token_data, OpenSSL::PKey.read(File.read(CONFIG['oauth2']['public_key_file'])), true, {
        algorithm: 'ES256',
        verify_iat: true,
        iss: 'https://api.opinsys.fi',
        verify_iss: true,
        aud: 'puavo-rest-v4',
        verify_aud: true,
        sub: CONFIG['oauth2']['client_id'],
        verify_sub: true,
      })

      # It's valid
      #@log.info("acquire_access_token(): using cached token #{token_file.inspect}")
      return token_data
    rescue StandardError => e
      @log.error("acquire_access_token(): could not use cached token #{token_file.inspect}: #{e}")
    end

    # No, get a new one
    token_data = request_access_token
    return nil if token_data.nil?

    @log.info("acquire_access_token(): Puavo request ID: #{token_data['puavo_request_id']}")
    @log.info("acquire_access_token(): the token expires in #{token_data['expires_in']} seconds")

    # Try to cache the token. Return the token even if this fails.
    begin
      File.write(token_file, token_data['access_token'])
      @log.info("acquire_access_token(): cached the token to #{token_file.inspect}")
    rescue StandardError => e
      @log.error("acquire_access_token(): could not cache the token to #{token_file}: #{e}")
    end

    token_data['access_token']
  rescue StandardError => e
    @log.error("acquire_access_token(): unhandled exception: #{e}")
    nil
  end

  # Requests a new access token from puavo-rest
  def request_access_token
    full_url = CONFIG['puavo-rest']['server'] + '/oidc/token'
    @log.info("request_access_token(): requesting a new OAuth2 access token from \"#{full_url}\"")

    max_attempts = 2
    attempt = 1

    begin
      response = HTTP.basic_auth({
        user: CONFIG['oauth2']['client_id'],
        pass: CONFIG['oauth2']['client_password']
      }).post(full_url, form: {
        grant_type: 'client_credentials',
        scope: 'puavo.read.users puavo.write.users puavo.write.devices'
      })
    rescue HTTP::ConnectionError
      @log.error('request_access_token(): connection failed!')

      if attempt < max_attempts
        @log.info('request_access_token(): attempting again in 1 second')
        attempt += 1
        sleep(1)
        retry
      end

      @log.error('request_access_token(): all attempts used, giving up')
      return nil
    end

    if response.status.success?
      JSON.parse(response.body)
    else
      @log.error("request_access_token(): received error status: #{response.status}")
      @log.error("request_access_token(): #{response.body}")
      nil
    end
  rescue StandardError => e
    @log.error("request_access_token(): unhandled exception: #{e}")
    nil
  end
end
