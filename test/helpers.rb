require "minitest/autorun"
require 'rack/test'
require 'webmock/minitest'

ENV["RACK_ENV"] = "test"

require_relative "../config.rb"
require_relative "../root"

include Rack::Test::Methods

def app
  Rack::Builder.parse_file(File.dirname(__FILE__) + '/../config.ru').first
end
