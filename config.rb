if ENV['RACK_ENV'] == 'test'
  # Development and testing configuration, meant to be used in/for puavo-standalone environments
  CONFIG = {
    'locales' => [
      'fi_FI.UTF-8',
      'en_US.UTF-8',
      'sv_FI.UTF-8',
      'de_CH.UTF-8',
      'fr_CH.UTF-8'
    ],
    'enabled_in_organisations' => [
      'hogwarts.puavo.net',
    ],
    'puavo-rest' => {
      'server' => 'http://127.0.0.1:9292',
    },
    'oauth2' => {
      'client_id' => 'puavo_accounts',
      'client_password' => '...',
      'token_cache_file' => '/tmp/puavo_accounts_oauth2_cached_token.txt',

      # This file exists in puavo-standalone, so we can use it directly. In production, the actual
      # production public key must be copied on the server.
      'public_key_file' => '/etc/puavo-rest.d/oauth2_token_signing_public_key_example.pem'
    },
    'smtp' => {
      'from' => 'Opinsys <no-reply@opinsys.fi>',
      'via_options' => {
        'address' => 'localhost',
        'port' => 25,
        'enable_starttls_auto' => false
      }
    },
  }.freeze
else
  # Production environment
  require 'yaml'

  begin
    CONFIG = YAML.load_file('/etc/puavo-accounts.yml').freeze
  rescue Errno::ENOENT
    raise 'No such configuration file! /etc/puavo-accounts.yml'
  end
end
