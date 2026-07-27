require "support/live_capture"
require "support/iap_jwt"

# End-to-end against LIVE Google infrastructure.
#
# Nothing here is stubbed. A real Okta sign-in federates through a real
# workforce identity pool into a real IAP-fronted Cloud Run service, and the
# assertion Google actually injected is fed to the verifier — which fetches
# Google's real JWKS over the real network to check the real signature.
#
# The Ruby sibling of test/e2e/live-iap.test.ts, verifying the SAME captured
# assertion. The capture is not driven from here; see spec/support/live_capture.rb.
#
#   e2e/run_all.sh          # capture once, run all four languages
#   bundle exec rake e2e    # this suite alone, against an existing capture
#
# NOT part of `rake default` or `rake spec`, and NOT reached by webmock's
# net-connect block — this is the one suite that is supposed to talk to Google.
RSpec.describe "live IAP", :e2e do
  # Skipping in a before hook rather than at describe level so the reason is
  # reported against every example, and so a stack that is up produces a real
  # pass/fail rather than a silently empty run.
  before { skip LiveCapture.result if LiveCapture.result.is_a?(String) }

  let(:capture) { LiveCapture.result }
  let(:assertion) { capture.assertion }
  let(:claims) { capture.claims }
  let(:audience) { capture.audience }

  def verify(token, aud: audience)
    CruIap::TokenVerifier.call(token, audience: aud)
  end

  describe "the real assertion" do
    it "was minted by Google minutes ago, not replayed from a fixture" do
      # Guards the whole file: every expectation below is only meaningful if
      # the capture really drove a live sign-in. A stale or hand-copied token
      # fails here rather than silently making the rest of the suite a re-test
      # of the offline fixtures.
      age = Time.now.to_i - claims["iat"].to_i

      expect(age).to be >= 0
      expect(age).to be < 600, "assertion is stale — did the capture actually run?"
      expect(claims["exp"].to_i).to be > Time.now.to_i
    end

    it "verifies against Google's live JWKS and yields the signed-in identity" do
      # No stubbed key source: googleauth's real JwkHttpKeySource fetches
      # https://www.gstatic.com/iap/verify/public_key-jwk and checks the
      # signature Google produced with a key we have never seen.
      result = verify(assertion)

      expect(result).to have_attributes(
        ok?: true,
        reason: "iap_jwt",
        email: capture.expected_email
      )
    end

    it "verifies straight off a request carrying the header, as an app would" do
      env = { CruIap::TokenVerifier::RACK_ENV_KEY => assertion }

      result = CruIap::TokenVerifier.from_request(env, audience: audience)

      expect(result.ok?).to be true
      expect(result.email).to eq(capture.expected_email)
    end

    it "has no name claim, so display names must fall back to the local part" do
      expect(verify(assertion).name).to be_nil
    end
  end

  describe "the pass is not vacuous" do
    # Each of these takes the SAME genuine token and breaks exactly one thing.
    # Without them, "it verified" could mean the verifier accepts anything.

    it "rejects the genuine token once its payload is edited" do
      header, payload, signature = assertion.split(".")
      edited = JSON.parse(Base64.urlsafe_decode64(pad(payload)))
      edited["email"] = "attacker@evil.example"
      forged = [
        header,
        Base64.urlsafe_encode64(edited.to_json, padding: false),
        signature
      ].join(".")

      result = verify(forged)

      expect(result.ok?).to be false
      # googleauth phrases this as "Token not verified as issued by Google"
      # rather than the siblings' `no_matching_key`; the prefix is the part of
      # the vocabulary that is shared.
      expect(result.reason).to start_with("signature_error:")
      expect(result.email).to be_nil
    end

    it "rejects the genuine token against a different backend service" do
      # Same project, different backend-service id: the shape is right and only
      # the value is wrong, which is the realistic misconfiguration.
      other = "#{audience.rpartition('/').first}/1111111111111111111"
      expect(other).not_to eq(audience)

      result = verify(assertion, aud: other)

      expect(result).to have_attributes(ok?: false, reason: "audience_mismatch")
    end

    it "rejects the genuine token when no audience is configured" do
      result = verify(assertion, aud: "")

      expect(result).to have_attributes(ok?: false, reason: "missing_audience_config")
    end

    it "rejects the same claims re-signed by a key of our own" do
      # Proof that the live JWKS fetch is load-bearing: identical payload, valid
      # ES256 signature, key Google never published.
      now = Time.now.to_i
      ours = IapJwt::Keypair.new(kid: "not-googles-key")
      forged = ours.sign(claims.merge("iat" => now - 30, "exp" => now + 600))

      result = verify(forged)

      expect(result.ok?).to be false
      expect(result.reason).to start_with("signature_error:")
    end
  end

  describe "the claim shape production actually emits" do
    it "puts a bare address in email — no namespace prefix" do
      expect(claims["email"]).to eq(capture.expected_email)
      expect(claims["email"]).not_to include(":")
    end

    it "puts an opaque STS token in sub, which is not an identity" do
      expect(claims["sub"]).to start_with("sts.google.com:")
      expect(claims["sub"]).not_to include("@")
    end

    it "puts principal:// in the nested workforce_identity claim, not in sub or email" do
      expect(claims.dig("workforce_identity", "iam_principal"))
        .to start_with("principal://iam.googleapis.com/")
      expect(claims["sub"]).not_to include("principal://")
      expect(claims["email"]).not_to include("principal://")
    end

    it "still matches the pinned capture, claim for claim" do
      # Drift detector against production Google. If this fails, the offline
      # suites in ALL FOUR languages are modelling a shape that no longer
      # exists — re-capture and update spec/fixtures/real_wif_iap_payload.json.
      pinned = JSON.parse(
        File.read(File.expand_path("../fixtures/real_wif_iap_payload.json", __dir__))
      )

      expect(claims.keys.sort).to eq(pinned["claims"].keys.sort)
    end
  end

  # Base64.urlsafe_decode64 is strict about padding; JWT segments carry none.
  def pad(segment)
    segment + ("=" * ((4 - (segment.length % 4)) % 4))
  end
end
