# FIXME: test/production
CONFIG = {
  "smtp" => {
    "from" => "Opinsys <no-reply@opinsys.fi>",
    "via_options" => {
      "address" => "localhost",
      "port" => 25,
      "enable_starttls_auto" => false
    }
  }
}
