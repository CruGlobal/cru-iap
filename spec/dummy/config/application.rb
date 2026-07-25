require "rails"
# Deliberately NOT `require "rails/all"` and deliberately not the `rails`
# meta-gem: this app is railties + actionpack only. No ActiveRecord, no
# ActiveJob, no ActionMailer, no asset pipeline — the gem under test needs none
# of them, and pulling them in would let a Rails-only helper sneak into lib/
# unnoticed.
require "action_controller/railtie"

require "cru_iap"

module Dummy
  # The smallest thing that is still a real Rails app: it boots through
  # Rails::Application#initialize!, builds a real middleware stack, and routes
  # real requests through ActionDispatch. Integration specs drive it with
  # Rack::Test, so everything from Rack env to controller runs for real.
  class Application < Rails::Application
    config.load_defaults 8.0

    config.root = File.expand_path("..", __dir__)
    config.eager_load = false
    config.enable_reloading = false
    config.consider_all_requests_local = true
    config.secret_key_base = "cru-iap-dummy-app-secret-key-base-not-a-real-secret"

    # No cookies, sessions, flash, or ETag middleware. The gem does not touch
    # any of them.
    config.api_only = true

    # Quiet: the suite asserts on CruIap's logger, not Rails'.
    config.logger = ActiveSupport::Logger.new(IO::NULL)
    config.log_level = :fatal

    # Keep HostAuthorization in the stack — the whole point of installing
    # StripForwardedHost at position 0 is that it runs BEFORE it, and a spec
    # asserts that ordering, which needs the middleware to actually exist.
    # (Rails drops HostAuthorization entirely when config.hosts is empty.)
    #
    # These are the hosts the integration specs send as a genuine Host header.
    # A forged X-Forwarded-Host must be defeated by the strip, not by happening
    # to be absent from this list — so admin.example.com, the host the
    # forged-routing example tries to reach, is deliberately allowed here.
    config.hosts = ["example.org", "www.example.com", "admin.example.com", "beacon.cru.org"]

    # THE POINT OF THIS APP. Position 0 — ahead of HostAuthorization and
    # everything else — is the documented install, so that is what gets tested.
    config.middleware.insert_before 0, CruIap::StripForwardedHost
  end
end
