Dir.glob(File.expand_path(File.dirname(__FILE__)) + "/*_test.rb").each do |p|
    require_relative p
end
