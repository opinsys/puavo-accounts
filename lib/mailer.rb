require "pony"

module PuavoAccounts

  class Mailer

    def initialize
      @options = { :via => :smtp }
      @options.merge!(CONFIG["smtp"])
    end

    def send(args)
      email_options = args.merge(@options)
      Pony.mail(email_options)
    end

    def options
      @options
    end

  end
end

