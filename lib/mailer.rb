require "pony"

module PuavoAccounts

  class Mailer

    def initialize
      @options = { :via => :smtp }
      @options.merge!({
                        :from => CONFIG["smtp"]["from"],
                        :via_options => {
                          :address => CONFIG["smtp"]["via_options"]["address"],
                          :port => CONFIG["smtp"]["via_options"]["port"],
                          :enable_starttls_auto => CONFIG["smtp"]["via_options"]["enable_starttls_auto"]
                        }})
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

