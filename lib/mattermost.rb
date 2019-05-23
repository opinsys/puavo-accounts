# Send messages to Mattermost through incoming webhooks

require 'uri'
require 'net/https'
require 'json'

module Mattermost
  class Bot
    def initialize(server, webhook_key, message_prefix=nil, channel=nil)
      @uri = URI.parse(server + '/hooks/' + webhook_key)
      @channel = channel
      @message_prefix = message_prefix
      @enabled = false
    end

    def enable
      @enabled = true
    end

    def send(logger, body)
      return unless @enabled

      begin
        data = {}
        data['channel'] = @channel if @channel

        body = '<Empty message>' if body.nil?
        prefix = @message_prefix.nil? ? '' : "[#{@message_prefix.to_s}] "
        data['text'] = prefix + body.to_s

        Net::HTTP.start(@uri.host, @uri.port, :use_ssl => true) do |http|
          post = Net::HTTP::Post.new(@uri, { 'Content-Type': 'text/json' })
          post.body = data.to_json
          http.request(post)
        end
      rescue StandardError => e
        # Log the error if we can
        logger.error "Could not send message to Mattermost: #{e}" if logger
      end
    end
  end
end
