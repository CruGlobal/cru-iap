RSpec.describe CruIap::TokenVerifier do
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

  describe ".from_request" do
    # Application code should never name the header; these cover the three
    # request-ish things a caller might hand us.
    let(:env) { { described_class::RACK_ENV_KEY => "fake.jwt.token" } }

    it "pulls the assertion out of a bare Rack env hash" do
      allow(Google::Auth::IDTokens).to receive(:verify_iap)
        .with("fake.jwt.token", aud: audience).and_return(payload)
      expect(described_class.from_request(env, audience: audience)).to be_ok
    end

    it "pulls the assertion off anything responding to get_header (Rack/ActionDispatch)" do
      request = double("Rack::Request")
      allow(request).to receive(:get_header).with(described_class::RACK_ENV_KEY)
        .and_return("fake.jwt.token")
      allow(Google::Auth::IDTokens).to receive(:verify_iap)
        .with("fake.jwt.token", aud: audience).and_return(payload)
      expect(described_class.from_request(request, audience: audience)).to be_ok
    end

    it "rejects missing_token when the header is absent" do
      result = described_class.from_request({}, audience: audience)
      expect(result).not_to be_ok
      expect(result.reason).to eq("missing_token")
    end

    it "forwards audience: and logger: through to the verifier" do
      logger = instance_double(Logger, warn: nil)
      allow(Google::Auth::IDTokens).to receive(:verify_iap)
        .and_return(payload.merge("email" => "not-an-email"))
      described_class.from_request(env, audience: audience, logger: logger)
      expect(logger).to have_received(:warn).with(a_string_including("malformed subject"))
    end

    it "exposes the wire header name for infra config and fixtures" do
      expect(described_class::HEADER).to eq("x-goog-iap-jwt-assertion")
      expect(described_class::RACK_ENV_KEY).to eq("HTTP_X_GOOG_IAP_JWT_ASSERTION")
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

    it "strips a namespace prefix off the email claim" do
      result = verify(returns: payload.merge("email" => "accounts.google.com:Alice@cru.org"))
      expect(result.email).to eq("alice@cru.org")
    end

    # The three payloads below are the shapes IAP actually emits, confirmed
    # 2026-07-24 from a captured live payload (keep-zero POC echoserver) and
    # beacon-stage's Datadog logs on both sides of the cru-terraform
    # google.email attribute-mapping fix. They are the regression protection
    # against anyone reintroducing a `sub` fallback.

    it "accepts a real plain-IAP payload, whose sub is an opaque Google id" do
      result = verify(returns: payload.merge("sub" => "accounts.google.com:104291823410293841029"))
      expect(result).to be_ok
      expect(result.email).to eq("alice@cru.org")
    end

    it "accepts a real WIF payload and ignores the nested workforce_identity claim" do
      # The principal:// URI IS real — but it lives here, in a nested claim
      # that is the string IAM bindings match. It is not an identity claim,
      # and the verifier must not read it.
      result = verify(returns: payload.merge(
        "email" => "matt.drees@cru.org",
        "sub" => "sts.google.com:AAFTZtsl9PtVMy-6qd9Otvue",
        "identity_source" => "WORKFORCE_IDENTITY",
        "workforce_identity" => {
          "iam_principal" => "principal://iam.googleapis.com/locations/global/" \
                             "workforcePools/keepzero-okta-poc/subject/matt.drees@cru.org",
          "workforce_pool_name" => "locations/global/workforcePools/keepzero-okta-poc"
        }
      ))
      expect(result).to be_ok
      expect(result.email).to eq("matt.drees@cru.org")
    end

    it "rejects a real unmapped-pool WIF payload as missing_email, not malformed_subject" do
      # A pool whose provider lacks the google.email attribute mapping. The
      # reason matters: missing_email says "go fix the pool", which is the
      # actual remedy. Falling back to the opaque sub would report
      # malformed_subject and send the next person hunting a principal shape
      # that does not exist. Beacon shipped that mistake in 2026-07.
      result = verify(returns: payload.reject { |k, _| k == "email" }.merge(
        "sub" => "sts.google.com:AAFTZtu0MfYynk2IJw-wF3TK8eiNjDbtCiPAMAdnsNacElMHCsyo5"
      ))
      expect(result).not_to be_ok
      expect(result.reason).to eq("missing_email")
    end

    it "ignores sub entirely when the email claim is blank" do
      result = verify(returns: payload.merge("email" => "", "sub" => "accounts.google.com:bob@cru.org"))
      expect(result).not_to be_ok
      expect(result.reason).to eq("missing_email")
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
    it "rejects missing_email when the email claim is absent" do
      result = verify(returns: payload.reject { |k, _| k == "email" })
      expect(result).not_to be_ok
      expect(result.reason).to eq("missing_email")
    end

    # A principal:// URI is not a shape IAP puts in the email claim — it
    # belongs to workforce_identity.iam_principal. These cover it as junk
    # input, and pin that it REJECTS. An earlier version of this gem unwrapped
    # it and accepted, which would persist a garbage user row.
    it "rejects a principal:// URI in the email claim rather than unwrapping it" do
      result = verify(returns: payload.merge(
        "email" => "principal://iam.googleapis.com/locations/global/workforcePools/beacon-stage/subject/alice@cru.org"
      ))
      expect(result).not_to be_ok
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a principalSet:// group binding in the email claim" do
      result = verify(returns: payload.merge(
        "email" => "principalSet://iam.googleapis.com/locations/global/workforcePools/beacon-stage/group/beacon-users"
      ))
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a slash-bearing value even though EMAIL_REGEXP alone accepts it" do
      # RFC 5322 permits "/" in a local part, so URI::MailTo::EMAIL_REGEXP
      # matches this string in full — the extra NEVER_IN_AN_EMAIL gate is the
      # only thing stopping it becoming a user row.
      value = "//iam.googleapis.com/locations/global/subject/alice@cru.org"
      expect(value).to match(URI::MailTo::EMAIL_REGEXP) # the trap
      result = verify(returns: payload.merge("email" => value))
      expect(result).not_to be_ok
      expect(result.reason).to eq("malformed_subject")
    end

    it "rejects a colon-bearing value that isn't email-shaped after prefix stripping" do
      # Prefix stripping yields "//pool/x" — must not be persisted as a user
      # row. Distinct reason from missing_email: something arrived that isn't
      # an address, vs. nothing arriving at all.
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

    it "defaults to CruIap.logger" do
      expect(CruIap.logger).to receive(:warn).with(a_string_including("malformed subject"))
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
