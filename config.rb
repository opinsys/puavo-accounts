require "yaml"

CONFIG = {
  "locales" => [ "fi_FI",
                 "en_US",
                 "sv_FI",
                 "de_CH",
                 "fr_CH" ],
  "puavo-rest" => {
    "server" => "http://127.0.0.1",
    "organisation_domain" => "www.example.net",
    "username" => "test-user",
    "password" => "secret"
  },
  "school_dns_for_users" => ["puavoId=1,ou=Groups,dc=edu,dc=hogwarts,dc=fi"],
  "role_for_users" => ["student"],
  "smtp" => {
    "from" => "Opinsys <no-reply@opinsys.fi>",
    "via_options" => {
      "address" => "localhost",
      "port" => 25,
      "enable_starttls_auto" => false
    }
  },
  "jwt" => "secret",
  "session_secret" => "foobar"
}

if ENV["RACK_ENV"] != "test"
  begin
    CONFIG.merge!(YAML.load_file "/etc/puavo-accounts.yml")
  rescue Errno::ENOENT
    raise "No such configuration file! /etc/puavo-accounts.yml"
  end
end
