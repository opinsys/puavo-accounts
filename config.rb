CONFIG = {
  "puavo-rest" => {
    "server" => "http://127.0.0.1",
    "organisation_domain" => "www.example.net",
    "username" => "test-user",
    "password" => "secret"
  },
  "smtp" => {
    "from" => "Opinsys <no-reply@opinsys.fi>",
    "via_options" => {
      "address" => "localhost",
      "port" => 25,
      "enable_starttls_auto" => false
    }
  }
}

if ENV["RACK_ENV"] != "test"
  begin
    CONFIG.merge!(YAML.load_file "/etc/puavo-accounts.yml")
  rescue Errno::ENOENT
    raise "No such configuration file! /etc/puavo-accounts.yml"
  end
end
