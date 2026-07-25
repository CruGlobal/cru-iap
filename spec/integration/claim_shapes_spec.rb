require "support/rails_integration"

# The claim-shape matrix, every case minted as a REAL SIGNED TOKEN and driven
# through the whole app. These are the regression protection for the 2026-07-24
# correction: `email` is the identity in every IAP mode and `sub` is never one.
#
# Shapes confirmed against a captured live payload plus beacon-stage's Datadog
# logs on both sides of the cru-terraform google.email mapping fix:
#
#   mode                       email           sub
#   -------------------------- --------------- -----------------------------
#   plain IAP (Google id)      bare address    accounts.google.com:<opaque>
#   WIF, google.email mapped   bare address    sts.google.com:<opaque STS>
#   WIF, mapping absent        ABSENT          sts.google.com:<opaque STS>
RSpec.describe "IAP claim shapes, end to end with signed tokens" do
  describe "plain IAP (Google / Cloud Identity account, no federation)" do
    it "authenticates from the bare email claim and ignores the opaque sub" do
      token = iap_token(
        email: "alice@cru.org",
        sub: "accounts.google.com:104291823410293841029"
      )

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
    end

    it "rejects rather than falling back to the numeric Google id when email is absent" do
      # The load-bearing assertion against reintroducing a sub fallback: this
      # sub is a real, well-formed, plain-IAP subject — and it is still not an
      # identity. missing_email, not malformed_subject.
      token = iap_token(email: nil, sub: "accounts.google.com:104291823410293841029")

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_email")
    end
  end

  describe "Workforce Identity Federation with google.email mapped" do
    it "authenticates from email and ignores the nested workforce_identity claim" do
      token = wif_token(email: "alice@cru.org", pool: "cru-okta-stage")

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
      expect(json_body["reason"]).to eq("iap_jwt")
    end

    it "carries the full realistic WIF payload — sts sub, identity_source, nested principal" do
      # Pinning the fixture itself, so this file keeps documenting the real
      # shape even if the verifier changes. If someone re-teaches the verifier
      # to read sub or to unwrap principal://, these two claims are the trap.
      claims = wif_claims(email: "alice@cru.org", pool: "cru-okta-stage")

      expect(claims["sub"]).to start_with("sts.google.com:")
      expect(claims["identity_source"]).to eq("WORKFORCE_IDENTITY")
      expect(claims["workforce_identity"]["iam_principal"]).to eq(
        "principal://iam.googleapis.com/locations/global/workforcePools/" \
        "cru-okta-stage/subject/alice@cru.org"
      )
    end

    it "still authenticates from email even when the nested principal disagrees" do
      # The nested claim is an IAM binding string, not an identity. If the
      # verifier ever started reading it, this would surface as mallory@.
      claims = wif_claims(email: "alice@cru.org")
      token = IapJwt.signing_key.sign(
        claims.merge(
          "workforce_identity" => claims["workforce_identity"].merge(
            "iam_principal" =>
              "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/mallory@evil.example"
          )
        )
      )

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
    end
  end

  describe "Workforce Identity Federation with the google.email mapping absent" do
    it "rejects with missing_email — the pool is broken and no claim can recover an address" do
      # This is the beacon-stage 2026-07 failure. The reason must stay
      # missing_email: it points at the pool's attribute_mapping. A sub
      # fallback would relabel it malformed_subject and send the next person
      # hunting for an unrecognised principal shape instead.
      token = wif_token(email: nil)

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_email")
      expect(last_response.body).not_to include(PagesController::GATED_CONTENT)
    end

    it "rejects even though the nested principal contains a perfectly good subject" do
      claims = wif_claims(email: nil)
      token = IapJwt.signing_key.sign(
        claims.merge(
          "workforce_identity" => claims["workforce_identity"].merge(
            "iam_principal" =>
              "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/alice%40cru.org"
          )
        )
      )

      get_with_assertion "/gated", token

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_email")
    end
  end

  describe "namespaced email claims" do
    it "strips an accounts.google.com: namespace prefix" do
      get_with_assertion "/gated", iap_token(email: "accounts.google.com:Alice@cru.org")

      expect(last_response.status).to eq(200)
      expect(json_body["email"]).to eq("alice@cru.org")
    end

    it "strips an sts.google.com: namespace prefix" do
      get_with_assertion "/gated", iap_token(email: "sts.google.com:alice@cru.org")

      expect(json_body["email"]).to eq("alice@cru.org")
    end

    it "strips an Identity Platform securetoken prefix (only the first colon)" do
      get_with_assertion "/gated",
                         iap_token(email: "securetoken.google.com/my-project/my-tenant:alice@cru.org")

      expect(json_body["email"]).to eq("alice@cru.org")
    end

    it "leaves a bare address untouched" do
      get_with_assertion "/gated", iap_token(email: "carol@cru.org")

      expect(json_body["email"]).to eq("carol@cru.org")
    end
  end

  describe "percent-encoded and otherwise non-address values in email" do
    it "rejects a percent-encoded address rather than silently decoding it" do
      # %40 is not @ to the shape gate, and the verifier no longer unescapes
      # anything. Rejecting is correct: IAP does not percent-encode the email
      # claim, so this arriving means something upstream is not what we think.
      get_with_assertion "/gated", iap_token(email: "alice%40cru.org")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "rejects a principal:// URI placed in the email claim" do
      # Real IAP never puts this in `email`. If it shows up there, accepting
      # it would persist "//iam.googleapis.com/..." as a user row.
      get_with_assertion "/gated", iap_token(
        email: "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org"
      )

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "rejects an opaque non-address subject" do
      get_with_assertion "/gated", iap_token(email: "okta-user-9f31c0")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "rejects a whitespace-only email claim as missing rather than malformed" do
      get_with_assertion "/gated", iap_token(email: "   ")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("missing_email")
    end

    it "rejects junk input defensively (principalSet:// is IAM syntax, not a claim)" do
      # Not a shape IAP emits anywhere — kept only as a junk-input case, so
      # the shape gate is shown to hold on values nobody anticipated.
      get_with_assertion "/gated", iap_token(
        email: "principalSet://iam.googleapis.com/locations/global/workforcePools/p/group/beacon-users"
      )

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "rejects a multi-address value" do
      get_with_assertion "/gated", iap_token(email: "alice@cru.org,bob@cru.org")

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end

    it "rejects a non-string email claim without blowing up" do
      get_with_assertion "/gated", iap_token(email: 12_345)

      expect(last_response.status).to eq(401)
      expect(json_body["reason"]).to eq("malformed_subject")
    end
  end

  describe "the rejection log" do
    it "dumps the full payload on malformed_subject so the shape is diagnosable" do
      logger = instance_double(Logger, warn: nil)
      allow(CruIap).to receive(:logger).and_return(logger)

      get_with_assertion "/gated", iap_token(email: "okta-user-9f31c0")

      expect(logger).to have_received(:warn).with(
        a_string_including("malformed subject", "okta-user-9f31c0", '"iss":"https://cloud.google.com/iap"')
      )
    end

    it "stays silent on a successful verification" do
      logger = instance_double(Logger, warn: nil)
      allow(CruIap).to receive(:logger).and_return(logger)

      get_with_assertion "/gated", iap_token

      expect(last_response.status).to eq(200)
      expect(logger).not_to have_received(:warn)
    end
  end
end
