# FIXME: test/production
CONFIG = {
  "puavo-rest" => {
    "server" => "http://127.0.0.1",
    "organisation_domain" => "www.example.net"
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
