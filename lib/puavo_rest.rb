# frozen_string_literal: true

class PuavoRestWrapper
  def initialize(domain, log)
    unless CONFIG['enabled_in_organisations'].include?(domain) then
      log.louderror("unknown or invalid organisation \"#{ domain }\"")
      raise OrgNotConfigured
    end

    @domain = domain
    @host   = CONFIG['puavo-rest']['server']
  end

  def get(url, username:, password:, params: {})
    auth_request(username, password).get("#{@host}#{url}", params: params)
  end

  def post(url, username:, password:, params: nil, json: nil)
    auth_request(username, password).post("#{@host}#{url}", params: params, json: json)
  end

  private

  def auth_request(username, password)
    HTTP.basic_auth({
      :user => username,
      :pass => password
    }).headers({
      'host' => @domain,
    })
  end
end
