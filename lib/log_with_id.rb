# frozen_string_literal: true

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
  end

  def louderror(msg)
    error(msg)
  end

  def request_info(msg, request)
    remote_addr     = request.env['REMOTE_ADDR']          || '?'
    x_real_ip       = request.env['HTTP_X_REAL_IP']       || '?'
    x_forwarded_for = request.env['HTTP_X_FORWARDED_FOR'] || '?'

    info "#{ msg } from IP=#{ remote_addr } (x_real_ip=#{ x_real_ip }, x_forwarded_for=#{ x_forwarded_for })"
  end
end
