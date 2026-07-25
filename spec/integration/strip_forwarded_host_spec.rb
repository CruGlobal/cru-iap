require "support/rails_integration"

# StripForwardedHost end to end. The unit spec proves the middleware deletes a
# Rack env key; this proves the thing that actually matters — that with the
# middleware installed the way the README says to install it, a forged
# X-Forwarded-Host cannot reach ActionDispatch, cannot move request.host, and
# cannot steer host-constrained routing.
RSpec.describe "StripForwardedHost end to end" do
  let(:forged) { "admin.example.com" }

  describe "the threat, demonstrated" do
    it "ActionDispatch really does prefer X-Forwarded-Host over Host" do
      # The negative control. Without this, the specs below could pass simply
      # because Rails ignores the header, and would prove nothing about the
      # middleware. Same env the app would have received, minus the strip.
      env = Rack::MockRequest.env_for(
        "http://www.example.com/host",
        "HTTP_X_FORWARDED_HOST" => forged
      )

      expect(ActionDispatch::Request.new(env).host).to eq(forged)
    end
  end

  describe "with the middleware installed at position 0" do
    it "does not let a forged X-Forwarded-Host move request.host" do
      get "/host", {}, { "HTTP_X_FORWARDED_HOST" => forged }

      expect(last_response.status).to eq(200)
      expect(json_body["host"]).to eq("example.org") # Rack::Test's default Host
      expect(json_body["host"]).not_to eq(forged)
    end

    it "removes the header from the Rack env entirely, not just from request.host" do
      get "/host", {}, { "HTTP_X_FORWARDED_HOST" => forged }

      expect(json_body["forwarded_host_header"]).to be_nil
    end

    it "keeps the forged host out of request.original_url" do
      get "/host", {}, { "HTTP_X_FORWARDED_HOST" => forged }

      expect(json_body["original_url"]).not_to include(forged)
      expect(json_body["original_url"]).to start_with("http://example.org/host")
    end

    it "strips a comma-separated forwarded-host chain too" do
      get "/host", {}, { "HTTP_X_FORWARDED_HOST" => "#{forged}, second.evil.example" }

      expect(json_body["host"]).to eq("example.org")
      expect(json_body["forwarded_host_header"]).to be_nil
    end

    it "strips it with a port attached" do
      get "/host", {}, { "HTTP_X_FORWARDED_HOST" => "#{forged}:8443" }

      expect(json_body["host"]).to eq("example.org")
      expect(json_body["host_with_port"]).to eq("example.org")
    end

    it "leaves the genuine Host header alone" do
      get "/host", {}, { "HTTP_HOST" => "beacon.cru.org" }

      expect(json_body["host"]).to eq("beacon.cru.org")
    end
  end

  describe "host-constrained routing" do
    it "matches the constrained route on a genuine Host header" do
      get "/admin", {}, {
        "HTTP_HOST" => "admin.example.com",
        CruIap::TokenVerifier::RACK_ENV_KEY => iap_token
      }

      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("admin ok")
    end

    it "does not let a forged X-Forwarded-Host reach a host-constrained route" do
      # Journey matches `constraints host:` against request.host — the same
      # value the middleware protects. Without the strip this would be a 200.
      get "/admin", {}, {
        "HTTP_HOST" => "www.example.com",
        "HTTP_X_FORWARDED_HOST" => "admin.example.com",
        CruIap::TokenVerifier::RACK_ENV_KEY => iap_token
      }

      expect(last_response.status).to eq(404)
      expect(last_response.body).not_to include("admin ok")
    end
  end

  describe "interaction with authentication" do
    it "authenticates normally on a request that also carried a forged host" do
      # The two concerns are independent: stripping the header must not
      # disturb the assertion, and a valid assertion must not excuse the host.
      get "/gated", {}, {
        "HTTP_X_FORWARDED_HOST" => forged,
        CruIap::TokenVerifier::RACK_ENV_KEY => iap_token
      }

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
    end
  end
end
