# Boots the dummy Rails app once per process and wires up the offline JWKS.
#
# Required explicitly by each spec/integration file rather than from
# spec/spec_helper.rb, so `rspec spec/cru_iap` stays a pure unit run that never
# loads Rails — which is also what keeps the "no Rails at runtime" property
# honest rather than aspirational.

ENV["RAILS_ENV"] ||= "test"

require "rack/test"
require "webmock/rspec" # disables net connect and resets stubs between examples

require_relative "iap_jwt"
require_relative "../dummy/config/environment"

module IapRequestHelpers
  # Rack::Test needs the app under test. The real one, whole stack included.
  def app
    Rails.application
  end

  # Send a request carrying an IAP assertion, named through the gem's own
  # constant so the wire header name is asserted in passing.
  def get_with_assertion(path, token, headers = {})
    get path, {}, headers.merge(CruIap::TokenVerifier::RACK_ENV_KEY => token)
  end

  def json_body
    JSON.parse(last_response.body)
  end
end

RSpec.configure do |config|
  # Everything under spec/integration gets the Rails app, Rack::Test, and a
  # freshly stubbed JWKS; nothing else in the suite is touched.
  config.define_derived_metadata(file_path: %r{/spec/integration/}) do |metadata|
    metadata[:iap_integration] = true
  end

  config.include Rack::Test::Methods, iap_integration: true
  config.include IapJwt, iap_integration: true
  config.include IapRequestHelpers, iap_integration: true

  config.before(iap_integration: true) do
    # spec_helper's global around hook deletes IAP_AUDIENCE so a developer's
    # ambient value can't satisfy a spec by accident. Put ours back inside that
    # window: the dummy app resolves the audience the way a real app does, off
    # the env var, rather than being handed one by the test.
    ENV["IAP_AUDIENCE"] = IapJwt::AUDIENCE

    # Cold key cache + a JWKS containing only IapJwt.signing_key. googleauth
    # memoizes iap_key_source across examples and then caches its keys for an
    # hour, so without this an example inherits the previous one's keys.
    stub_iap_jwks
  end

  config.after(iap_integration: true) do
    Google::Auth::IDTokens.forget_sources!
  end
end
