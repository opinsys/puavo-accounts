
require 'fluent-logger'

Fluent::Logger::FluentLogger.open(nil, :host=>'localhost', :port=>24224)

class FluentWrap

  def initialize(tag, base_attrs, logger=Fluent::Logger)
    @tag = tag
    @logger = logger
    @base_attrs = clean(base_attrs)
  end

  def log(level, msg, attrs=nil)

    if [:msg, :meta, :level].include?(msg)
      raise "Illegal fluentd message key: #{ msg }"
    end

    record = {
      :msg => msg, # for legacy elasticsearch support
      :meta => clean(@base_attrs),
    }

    record[:meta][:level] = level

    # Write attrs under a key defined by msg to avoid type errors in
    # elasticsearch
    record[msg] = clean(attrs) if attrs

    @logger.post(@tag, record)

    if !ENV["FLUENTD_STDOUT"]
      return if ENV["RACK_ENV"] == "test"
      return if ENV["RAILS_ENV"] == "test"
    end
    begin
      puts "#{ msg }: #{ record.to_json }"
    rescue Exception => e
      puts "Failed to log message: #{ record.inspect }"
      puts e
    end
  end

  def info(msg, attrs=nil)
    log("info", msg, attrs)
  end

  def warn(msg, attrs=nil)
    log("warn", msg, attrs)
  end

  def error(msg, attrs=nil)
    log("error", msg, attrs)
  end

  def merge(more_attrs=nil, new_logger=nil)
    FluentWrap.new(
      @tag,
      @base_attrs.merge(more_attrs || {}),
      new_logger || @logger
    )
  end

  MAX_SIZE = 1024 * 512
  def truncate_large(val)
    return val if !val.kind_of?(String)
    if val.size > MAX_SIZE
      val.slice(0, MAX_SIZE) << "[TRUNCATED #{ val.size - MAX_SIZE } bytes]"
    else
      val
    end
  end

  def filter_passwords(val)
    return val if !val.kind_of?(Hash)
    val = val.dup
    val.each do |k, v|
      # Sensor keys that contain word password
      if k.to_s.include?("password")
        val[k] = "[FILTERED]"
      end
    end
    val
  end

  def clean(val)
    val = truncate_large(val)
    val = filter_passwords(val)

    if val.kind_of?(Array)
      val = val.map do |val|
        clean(val)
      end
    end

    if val.kind_of?(Hash)
      val = val.dup
      val.each do |k, v|
        val[k] = clean(v)
      end
    end

    val
  end

end
