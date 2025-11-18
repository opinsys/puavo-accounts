# frozen_string_literal: true

dir = File.dirname File.expand_path __FILE__

class OrgNotConfigured < StandardError; end

require File.join dir, './config'
require File.join dir, './root'

run PuavoAccounts::Root
