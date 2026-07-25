require "support/rails_integration"

# End-to-end: a real Rails app, a real middleware stack, a real ActionDispatch
# request, and a REAL SIGNED JWT verified against a real JWKS by real
# googleauth code. The only thing faked anywhere in this file is the network
# hop to www.gstatic.com — see spec/support/iap_jwt.rb for the seam.
#
# The unit suite stubs Google::Auth::IDTokens.verify_iap and therefore cannot
# tell you whether the gem's audience is actually passed to a real check,
# whether a forged signature is really rejected, or whether our rescue clauses
# name errors googleauth actually raises. This file is that proof.
RSpec.describe "IAP authentication end to end" do
  describe "happy path" do
    it "authenticates a validly signed IAP JWT and lands email + name" do
      get_with_assertion "/gated", iap_token

      expect(last_response.status).to eq(200)
      expect(json_body).to include(
        "content" => PagesController::GATED_CONTENT,
        "email" => "alice@cru.org",
        "name" => "Alice A",
        "reason" => "iap_jwt"
      )
    end

    it "really did verify the signature — the JWKS was fetched from IAP_JWK_URL" do
      get_with_assertion "/gated", iap_token

      expect(last_response.status).to eq(200)
      expect(WebMock).to have_requested(:get, IapJwt::JWKS_URL)
    end

    it "downcases an upper-cased address from a real token" do
      get_with_assertion "/gated", iap_token(email: "Alice.Anderson@CRU.ORG")

      expect(json_body["email"]).to eq("alice.anderson@cru.org")
    end

    it "returns a nil name when the token carries no name claim" do
      get_with_assertion "/gated", iap_token(name: nil)

      expect(last_response.status).to eq(200)
      expect(json_body["name"]).to be_nil
    end
  end

  describe "signature" do
    it "rejects a JWT signed with a key that is not in the published JWKS" do
      # Same claims, same kid-less trust decision — only the signer differs.
      # This is the case the stubbed unit suite structurally cannot cover.
      get_with_assertion "/gated", iap_token(key: IapJwt.rogue_key)

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to start_with("signature_error:")
      expect(last_response.body).not_to include(PagesController::GATED_CONTENT)
    end

    it "rejects a token whose payload was tampered with after signing" do
      # Splice a different payload onto a genuine header+signature: the
      # classic "alg is fine, I just edited the claims" attack.
      header, _payload, signature = iap_token.split(".")
      forged_payload = Base64.urlsafe_encode64(
        iap_claims(email: "attacker@evil.example").to_json, padding: false
      )

      get_with_assertion "/gated", [header, forged_payload, signature].join(".")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to start_with("signature_error:")
    end

    it "rejects an unsigned alg=none token" do
      unsigned = JWT.encode(iap_claims, nil, "none")

      get_with_assertion "/gated", unsigned

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to start_with("signature_error:")
    end

    it "rejects a syntactically broken assertion without raising" do
      get_with_assertion "/gated", "not-a-jwt"

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to start_with("signature_error:")
    end
  end

  describe "audience" do
    it "rejects a correctly signed token minted for a different backend service" do
      get_with_assertion "/gated", iap_token(aud: "/projects/999/global/backendServices/other")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("audience_mismatch")
    end

    it "rejects a correctly signed token with no aud at all" do
      get_with_assertion "/gated", iap_token(aud: nil)

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("audience_mismatch")
    end

    it "fails closed when IAP_AUDIENCE is unset, even for an otherwise perfect token" do
      # The deploy-misconfig case. A missing audience must never degrade into
      # "skip the audience check".
      token = iap_token
      ENV.delete("IAP_AUDIENCE")

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_audience_config")
    end
  end

  describe "expiry" do
    it "rejects a validly signed but expired token" do
      # Deterministic: exp is computed relative to a `now` we choose, so no
      # sleeping and no dependence on how long the suite takes.
      get_with_assertion "/gated", iap_token(now: Time.now.to_i - 3600)

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("expired_token")
    end

    it "accepts a token that is only just still valid" do
      get_with_assertion "/gated", iap_token(exp: Time.now.to_i + 30)

      expect(last_response.status).to eq(200)
    end
  end

  describe "issuer" do
    it "rejects a token whose iss is not the IAP issuer" do
      # NB the reason is issuer_mismatch, not bad_iss: — with real verification
      # googleauth's own iss check (IAP_ISSUERS) fires first and raises before
      # the verifier's belt-and-braces re-check can look at the payload. The
      # bad_iss: branch is only reachable if a future googleauth loosens that
      # default, which is exactly why it exists; the unit suite covers it.
      get_with_assertion "/gated", iap_token(iss: "https://accounts.google.com")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("issuer_mismatch")
    end

    it "rejects a token from a lookalike issuer" do
      get_with_assertion "/gated", iap_token(iss: "https://cloud.google.com/iap.evil.example")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("issuer_mismatch")
    end
  end

  describe "fail closed" do
    it "serves the public route with no assertion header at all" do
      get "/public"

      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("public ok")
    end

    it "rejects the gated route with no assertion header, and serves no content" do
      get "/gated"

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_token")
      expect(last_response.body).not_to include(PagesController::GATED_CONTENT)
    end

    it "rejects a blank assertion header" do
      get_with_assertion "/gated", "   "

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_token")
    end

    it "does not accept the assertion under any other header name" do
      # If an app or a proxy ever renamed the header, the gem must not pick it
      # up from somewhere else.
      get "/gated", {}, { "HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL" => "accounts.google.com:alice@cru.org" }

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_token")
    end
  end

  describe "identity memoization within a request" do
    it "verifies the JWT once no matter how many times the action reads it" do
      allow(CruIap::TokenVerifier).to receive(:from_request).and_call_original

      get_with_assertion "/repeated", iap_token

      expect(last_response.status).to eq(200)
      expect(json_body["emails"]).to eq(["alice@cru.org"] * 4)
      # One resolution shared by the before_action and all four reads.
      expect(json_body["object_ids"]).to eq(1)
      expect(CruIap::TokenVerifier).to have_received(:from_request).once
    end

    it "re-verifies on a second request rather than leaking identity across requests" do
      allow(CruIap::TokenVerifier).to receive(:from_request).and_call_original

      get_with_assertion "/gated", iap_token
      get_with_assertion "/gated", iap_token(email: "bob@cru.org")

      expect(json_body["email"]).to eq("bob@cru.org")
      expect(CruIap::TokenVerifier).to have_received(:from_request).twice
    end

    it "does not re-verify on the rejection path either" do
      # The failure path is the one that matters: an un-memoized rejection
      # re-logs on every current_user call site.
      allow(CruIap::TokenVerifier).to receive(:from_request).and_call_original

      get_with_assertion "/repeated", iap_token(key: IapJwt.rogue_key)

      expect(last_response.status).to eq(401)
      expect(CruIap::TokenVerifier).to have_received(:from_request).once
    end
  end

  describe "JWKS caching" do
    it "fetches Google's keys once and reuses them across requests" do
      3.times { get_with_assertion "/gated", iap_token }
      get_with_assertion "/gated", iap_token(key: IapJwt.rogue_key)

      expect(last_response.status).to eq(401)
      # A rejected signature must not trigger a re-fetch storm against
      # gstatic — HttpKeySource's retry interval is what prevents that.
      expect(WebMock).to have_requested(:get, IapJwt::JWKS_URL).once
    end

    it "surfaces a JWKS outage as verification_error:KeySourceError, not as success" do
      Google::Auth::IDTokens.forget_sources!
      WebMock.stub_request(:get, IapJwt::JWKS_URL).to_return(status: 503, body: "nope")

      get_with_assertion "/gated", iap_token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("verification_error:KeySourceError")
    end

    it "rejects a token signed by a key Google has rotated out of the JWKS" do
      retired = IapJwt::Keypair.new(kid: "retired-key")
      token = iap_token(key: retired)
      stub_iap_jwks(IapJwt.signing_key) # JWKS no longer lists `retired`

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to start_with("signature_error:")
    end
  end

  describe "claim edge cases only a real verification can reach" do
    # Everything in here was found by minting the token and watching what came
    # back, not by reading the code. The stubbed unit suite cannot see any of
    # it, because it never lets googleauth or the jwt gem run.

    it "accepts a token audienced for our backend service among several" do
      # googleauth intersects the aud lists, so a multi-audience token that
      # includes us is valid. Correct per JWT semantics, but worth pinning:
      # it means "aud contains our backend" not "aud is exactly ours".
      get_with_assertion "/gated", iap_token(
        aud: [IapJwt::AUDIENCE, "/projects/9/global/backendServices/someone-else"]
      )

      expect(last_response.status).to eq(200)
    end

    it "tolerates surrounding whitespace on the email claim" do
      get_with_assertion "/gated", iap_token(email: "  alice@cru.org  ")

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
    end

    it "rejects an RFC 5322 display-name address" do
      get_with_assertion "/gated", iap_token(email: "Alice <alice@cru.org>")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "does not check iat, so a future-dated token is still accepted" do
      # Documenting, not endorsing. Nothing verifies iat anywhere in the
      # stack; freshness rests entirely on exp.
      get_with_assertion "/gated", iap_token(iat: Time.now.to_i + 86_400)

      expect(last_response.status).to eq(200)
    end

    it "reports a not-yet-valid (nbf) token as a signature failure, not a timing one" do
      # A googleauth taxonomy wart, worth knowing before you read it in
      # Datadog at 2am: jwt raises JWT::ImmatureSignature, googleauth's
      # decode_token swallows every JWT::DecodeError as "try the next key",
      # and the loop ends in SignatureError. So an nbf/clock-skew problem is
      # indistinguishable from a forged signature in the reason string.
      # Not cru-iap's bug and not worth working around — IAP does not emit
      # nbf — but pinned so a googleauth bump that changes it is visible.
      get_with_assertion "/gated", iap_token(nbf: Time.now.to_i + 3600)

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("signature_error:Token not verified as issued by Google")
    end

    it "rejects a signed token that carries no exp claim at all" do
      # The jwt gem's verify_expiration is a no-op when the claim is ABSENT
      # and googleauth adds no freshness floor, so without TokenVerifier's own
      # check this token would be accepted forever. Not reachable by an
      # attacker (minting one needs Google's IAP signing key) — this is the
      # verifier refusing to depend on IAP always setting exp.
      get_with_assertion "/gated", iap_token(exp: nil)

      expect(last_response.status).to eq(401)
    end
  end

  describe "middleware stack" do
    it "has StripForwardedHost at position 0, ahead of HostAuthorization" do
      stack = Rails.application.middleware.map { |m| m.klass.to_s }

      expect(stack.first).to eq("CruIap::StripForwardedHost")
      expect(stack.index("CruIap::StripForwardedHost"))
        .to be < stack.index("ActionDispatch::HostAuthorization")
    end
  end
end
