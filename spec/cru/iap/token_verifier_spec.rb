RSpec.describe Cru::Iap::TokenVerifier do
  let(:audience) { "/projects/178891842216/global/backendServices/12345" }

  let(:payload) do
    {
      "iss"   => "https://cloud.google.com/iap",
      "aud"   => "/projects/178891842216/global/backendServices/12345",
      "email" => "alice@cru.org",
      "name"  => "Alice A"
    }
  end

  # Every example that gets past the config guards stubs the googleauth call —
  # we are testing our wrapper's claim handling and rescue taxonomy, not
  # Google's signature verification.
  def verify(returns: nil, raises: nil, token: "fake.jwt.token", **opts)
    if raises
      allow(Google::Auth::IDTokens).to receive(:verify_iap).and_raise(raises)
    elsif returns
      allow(Google::Auth::IDTokens).to receive(:verify_iap).and_return(returns)
    end
    described_class.call(token, audience: audience, **opts)
  end

  describe "input + config guards" do
    it "rejects a blank token" do
      result = described_class.call(nil, audience: audience)
      expect(result.ok?).to be false
      expect(result.reason).to eq("missing_token")
    end

    it "rejects a whitespace-only token" do
      result = described_class.call("   ", audience: audience)
      expect(result.reason).to eq("missing_token")
    end

    it "rejects when no audience is configured" do
      result = described_class.call("some.jwt.token", audience: nil)
      expect(result.ok?).to be false
      expect(result.reason).to eq("missing_audience_config")
    end

    it "rejects when the audience is blank" do
      result = described_class.call("some.jwt.token", audience: "  ")
      expect(result.reason).to eq("missing_audience_config")
    end
  end

  describe "audience resolution" do
    it "passes the configured audience through to verify_iap" do
      expect(Google::Auth::IDTokens).to receive(:verify_iap)
        .with("fake.jwt.token", aud: audience).and_return(payload)
      described_class.call("fake.jwt.token", audience: audience)
    end

    it "defaults the audience to ENV['IAP_AUDIENCE']" do
      ENV["IAP_AUDIENCE"] = audience
      expect(Google::Auth::IDTokens).to receive(:verify_iap)
        .with("fake.jwt.token", aud: audience).and_return(payload)
      described_class.call("fake.jwt.token")
    end

    it "prefers an explicit audience over the env var" do
      ENV["IAP_AUDIENCE"] = "/projects/999/global/backendServices/env"
      expect(Google::Auth::IDTokens).to receive(:verify_iap)
        .with("fake.jwt.token", aud: audience).and_return(payload)
      described_class.call("fake.jwt.token", audience: audience)
    end
  end

  describe "identity extraction" do
    it "accepts a valid IAP payload and returns email + name" do
      result = verify(returns: payload)
      expect(result.ok?).to be true
      expect(result.reason).to eq("iap_jwt")
      expect(result.email).to eq("alice@cru.org")
      expect(result.name).to eq("Alice A")
    end

    it "downcases the email" do
      result = verify(returns: payload.merge("email" => "ALICE@CRU.ORG"))
      expect(result.email).to eq("alice@cru.org")
    end

    it "strips an accounts.google.com: namespace prefix (WIF)" do
      result = verify(returns: payload.merge("email" => "accounts.google.com:Alice@cru.org"))
      expect(result.email).to eq("alice@cru.org")
    end

    it "unwraps a workforce principal URI to its subject email (the live beacon-stage shape)" do
      result = verify(returns: payload.merge(
        "email" => "principal://iam.googleapis.com/locations/global/workforcePools/beacon-stage/subject/Alice@cru.org"
      ))
      expect(result).to be_ok
      expect(result.email).to eq("alice@cru.org")
    end

    it "percent-decodes the workforce principal subject" do
      result = verify(returns: payload.merge(
        "email" => "principal://iam.googleapis.com/locations/global/workforcePools/beacon-stage/subject/alice%40cru.org"
      ))
      expect(result).to be_ok
      expect(result.email).to eq("alice@cru.org")
    end

    it "falls back to sub when email is absent (the live workforce JWT has no email claim)" do
      result = verify(returns: payload.reject { |k, _| k == "email" }.merge(
        "sub" => "principal://iam.googleapis.com/locations/global/workforcePools/beacon-stage/subject/Alice@cru.org"
      ))
      expect(result).to be_ok
      expect(result.email).to eq("alice@cru.org")
    end

    it "falls back to sub when email is present but blank" do
      result = verify(returns: payload.merge("email" => "", "sub" => "accounts.google.com:bob@cru.org"))
      expect(result).to be_ok
      expect(result.email).to eq("bob@cru.org")
    end

    it "prefers the email claim over sub when both are present" do
      result = verify(returns: payload.merge("sub" => "accounts.google.com:other@cru.org"))
      expect(result.email).to eq("alice@cru.org")
    end

    it "leaves a bare email untouched (no colon → no prefix)" do
      result = verify(returns: payload.merge("email" => "carol@cru.org"))
      expect(result.email).to eq("carol@cru.org")
    end

    it "returns a nil name when the name claim is absent" do
      result = verify(returns: payload.reject { |k, _| k == "name" })
      expect(result.ok?).to be true
      expect(result.name).to be_nil
    end

    it "returns a nil name when the name claim is whitespace" do
      result = verify(returns: payload.merge("name" => "   "))
      expect(result.name).to be_nil
    end
  end

  describe "identity rejection" do
    it "rejects missing_email when both email and sub are absent" do
      result = verify(returns: payload.reject { |k, _| k == "email" })
      expect(result).not_to be_ok
      expect(result.reason).to eq("missing_email")
    end

    it "rejects a workforce principal whose subject is not email-shaped" do
      result = verify(returns: payload.merge(
        "email" => "principal://iam.googleapis.com/locations/global/workforcePools/beacon-stage/subject/opaque-id-123"
      ))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a workforce GROUP principalSet rather than treating it as a user" do
      result = verify(returns: payload.merge(
        "email" => "principalSet://iam.googleapis.com/locations/global/workforcePools/beacon-stage/group/beacon-users"
      ))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a colon-bearing subject that isn't email-shaped after prefix stripping" do
      # Prefix stripping yields "//pool/x" — must not be persisted as a user
      # row. Distinct reason from missing_email: an unanticipated WIF
      # principal shape, not an Okta attribute-mapping gap.
      result = verify(returns: payload.merge("email" => "principal://pool/x"))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a bare non-email subject" do
      result = verify(returns: payload.merge("email" => "not-an-email"))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a multi-address subject (the regex is anchored to a single mailbox)" do
      result = verify(returns: payload.merge("email" => "alice@cru.org,bob@cru.org"))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects when iss is not the IAP issuer (defensive re-check)" do
      result = verify(returns: payload.merge("iss" => "https://accounts.google.com"))
      expect(result.ok?).to be false
      expect(result.reason).to eq("bad_iss:https://accounts.google.com")
    end
  end

  describe "googleauth error taxonomy" do
    {
      Google::Auth::IDTokens::AudienceMismatchError => "audience_mismatch",
      Google::Auth::IDTokens::ExpiredTokenError     => "expired_token",
      Google::Auth::IDTokens::IssuerMismatchError   => "issuer_mismatch"
    }.each do |error_class, reason|
      it "maps #{error_class.name.split('::').last} to #{reason}" do
        result = verify(raises: error_class.new("boom"))
        expect(result.ok?).to be false
        expect(result.reason).to eq(reason)
      end
    end

    it "maps SignatureError to signature_error: plus the message" do
      result = verify(raises: Google::Auth::IDTokens::SignatureError.new("bad sig"))
      expect(result.reason).to eq("signature_error:bad sig")
    end

    it "maps KeySourceError (the likely real-world transient) to verification_error:" do
      result = verify(raises: Google::Auth::IDTokens::KeySourceError.new("JWKS fetch failed"))
      expect(result.reason).to eq("verification_error:KeySourceError")
    end

    it "fails closed on an unexpected error" do
      result = verify(raises: RuntimeError.new("boom"))
      expect(result.ok?).to be false
      expect(result.reason).to eq("unexpected_error")
    end
  end

  describe "logging" do
    let(:logger) { instance_double(Logger, warn: nil) }

    it "dumps the payload on malformed_subject so a rejection is diagnosable" do
      verify(returns: payload.merge("email" => "not-an-email"), logger: logger)
      expect(logger).to have_received(:warn).with(
        a_string_including("malformed subject", "not-an-email", '"iss":"https://cloud.google.com/iap"')
      )
    end

    it "logs the class and message of an unexpected error" do
      verify(raises: RuntimeError.new("boom"), logger: logger)
      expect(logger).to have_received(:warn).with(a_string_including("unexpected RuntimeError", "boom"))
    end

    it "does not log on a successful verification" do
      verify(returns: payload, logger: logger)
      expect(logger).not_to have_received(:warn)
    end

    it "does not log the payload for an expected verification failure" do
      verify(raises: Google::Auth::IDTokens::ExpiredTokenError.new("expired"), logger: logger)
      expect(logger).not_to have_received(:warn)
    end

    it "defaults to Cru::Iap.logger" do
      expect(Cru::Iap.logger).to receive(:warn).with(a_string_including("malformed subject"))
      verify(returns: payload.merge("email" => "not-an-email"))
    end
  end

  describe "REASONS" do
    it "documents every reason the verifier can return" do
      # Guards against a new reason being added without updating the shared
      # Datadog vocabulary. Prefixed entries end in ":".
      produced = [
        described_class.call(nil, audience: audience),
        described_class.call("t", audience: nil),
        verify(returns: payload),
        verify(returns: payload.merge("iss" => "https://evil.example")),
        verify(returns: payload.reject { |k, _| k == "email" }),
        verify(returns: payload.merge("email" => "nope")),
        verify(raises: Google::Auth::IDTokens::SignatureError.new("x")),
        verify(raises: Google::Auth::IDTokens::AudienceMismatchError.new("x")),
        verify(raises: Google::Auth::IDTokens::ExpiredTokenError.new("x")),
        verify(raises: Google::Auth::IDTokens::IssuerMismatchError.new("x")),
        verify(raises: Google::Auth::IDTokens::KeySourceError.new("x")),
        verify(raises: RuntimeError.new("x"))
      ].map(&:reason)

      produced.each do |reason|
        expect(described_class::REASONS).to include(
          satisfy { |known| known.end_with?(":") ? reason.start_with?(known) : reason == known }
        ), "reason #{reason.inspect} is not in REASONS"
      end
    end
  end
end
