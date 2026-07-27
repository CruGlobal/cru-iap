require "json"
require "time"

# Loader for the shared live-capture artifact.
#
# One browser login, four verifications — see test/support/capture.ts for the
# reasoning and e2e/README.md for the artifact contract. This is the Ruby
# sibling of that loader and applies the same staleness rule.
#
# Deliberately does NOT require webmock. The offline suites pull in
# `webmock/rspec` (via support/rails_integration), which disables real net
# connect — exactly what an e2e spec must not have. Keeping the e2e spec's
# require graph free of it is what lets `Google::Auth::IDTokens.verify_iap`
# reach gstatic.com for real.
#
# Nothing infrastructure-specific is hardcoded: the audience and expected email
# resolve from the environment or the artifact and otherwise cause a skip, so
# moving the e2e stack to another project does not touch spec code.
module LiveCapture
  # Refuse a capture that is within this many seconds of expiry.
  EXPIRY_MARGIN_SECONDS = 30

  Loaded = Struct.new(:assertion, :claims, :audience, :expected_email, :captured_at,
                      keyword_init: true)

  class << self
    # Memoized so a suite of examples reads the file once and every example
    # agrees on the same freshness verdict.
    def result
      return @result if defined?(@result)

      @result = load_capture
    end

    def path
      ENV["CRU_IAP_E2E_CAPTURE"] ||
        File.expand_path("../../e2e/okta/capture.json", __dir__)
    end

    private

    # Returns a Loaded, or a String explaining why the suite must skip. Never
    # raises: an absent stack is a skip, not a failure.
    def load_capture
      return "no capture at #{path} — run: node e2e/okta/capture_assertion.mjs --json" unless File.exist?(path)

      begin
        raw = JSON.parse(File.read(path))
      rescue JSON::ParserError => e
        return "capture at #{path} is not readable JSON: #{e.message}"
      end

      assertion = raw["assertion"]
      claims = raw["claims"]
      unless assertion && claims.is_a?(Hash)
        return "capture at #{path} has no assertion/claims — was it written by an older capture script?"
      end

      # Keyed on `exp` rather than captured_at: exp is what actually decides
      # whether a verify can succeed, and it comes from Google not our clock.
      exp = Integer(claims["exp"], exception: false)
      return "capture at #{path} has no numeric exp claim" if exp.nil?

      now = Time.now.to_i
      if exp <= now + EXPIRY_MARGIN_SECONDS
        return "capture at #{path} expired #{now - exp}s ago — re-run the capture"
      end

      # Audience is configuration, never read off the token: taking it from the
      # `aud` claim would turn the positive verify into "does aud equal aud".
      audience = presence(ENV["CRU_IAP_E2E_AUDIENCE"]) || presence(raw["audience"])
      unless audience
        return 'no audience: set CRU_IAP_E2E_AUDIENCE or capture with ' \
               '--audience "$(terraform output -raw iap_audience)"'
      end

      expected_email = presence(ENV["CRU_IAP_E2E_EMAIL"]) || presence(raw["expected_email"])
      return "no expected email: set CRU_IAP_E2E_EMAIL or re-run the capture script" unless expected_email

      Loaded.new(
        assertion: assertion,
        claims: claims,
        audience: audience,
        expected_email: expected_email,
        captured_at: raw["captured_at"].to_i
      )
    end

    def presence(str)
      str.nil? || str.to_s.strip.empty? ? nil : str.to_s
    end
  end
end
