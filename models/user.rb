require 'redis'
require 'json'

module PuavoAccounts
  class User
    attr_accessor :data, :uuid, :errors

    EXPIRE = 60*60

    UUID_CHARS = ["a".."z", "A".."Z", "0".."9"].reduce([]) do |memo, range|
      memo + range.to_a
    end

    def initialize(user_data = {})
      @data = user_data
      @errors = {}
      @uuid = nil
    end

    def valid?
      # FIXME validate request to puavo-rest
      return true
    end

    def save
      # FIXME save request to puavo-rest
      return true
    end

    def redis_fetch(uuid)
      @uuid = uuid
      redis = redis_connection
      @data = JSON.parse(redis.get(uuid_key))
    end

    def redis_save
      redis = redis_connection
      redis.set(uuid_key, @data.to_json)
      redis.expire(uuid_key, EXPIRE)
    end


    private

    def uuid_key
      if @uuid.nil?
        generate_uuid
      end
      return "puavo-accounts:user:#{ @uuid }"
    end

    def redis_connection
      Redis.new( :db => 6 )
    end

    def generate_uuid
      @uuid = (0...50).map{ UUID_CHARS[rand(UUID_CHARS.size)] }.join
    end

  end
end
