require "minitest/autorun"
require 'rack/test'

require_relative "../models/user"
require_relative "../root"

include Rack::Test::Methods

def app
  Rack::Builder.parse_file(File.dirname(__FILE__) + '/../config.ru').first
end
