require "base64"
require "json"
require "openssl"
require "jwt"
require "googleauth/id_tokens"

# Mints REAL, REALLY-SIGNED IAP assertion JWTs and serves the matching JWKS, so
# `Google::Auth::IDTokens.verify_iap` runs its actual signature/aud/exp/iss
# checks. Nothing here is stubbed at the googleauth API boundary — the only
# thing faked is the network hop to Google's public key endpoint.
#
# How the seam works
# ------------------
# googleauth resolves IAP keys through a memoized JwkHttpKeySource:
#
#     Google::Auth::IDTokens.iap_key_source
#       #=> JwkHttpKeySource.new("https://www.gstatic.com/iap/verify/public_key-jwk")
#
# which fetches with `Net::HTTP.get_response` and then caches the parsed keys
# for an hour (HttpKeySource::DEFAULT_RETRY_INTERVAL). Two consequences:
#
#   1. WebMock can intercept the fetch — so we stub IAP_JWK_URL with a JWKS
#      built from a keypair we generated in-process. The real JwkHttpKeySource,
#      the real JWK -> OpenSSL::PKey parsing, and the real JWT verification all
#      still run.
#   2. The memoized source outlives an example and would hand stale keys to the
#      next one. `Google::Auth::IDTokens.forget_sources!` (googleauth's own
#      documented "used for testing" hook) drops it; we call that before every
#      example so each one starts from a cold cache.
#
# The alternative seam — assigning a StaticKeySource over @iap_key_source —
# would skip the HTTP key source entirely, including its caching, which is
# exactly the layer a `verification_error:KeySourceError` in production comes
# from. WebMock keeps that in the test's blast radius.
module IapJwt
  AUDIENCE = "/projects/178891842216/global/backendServices/9876543210".freeze
  IAP_ISSUER = "https://cloud.google.com/iap".freeze
  JWKS_URL = Google::Auth::IDTokens::IAP_JWK_URL

  # Real IAP signs with ES256 / P-256, and its JWKS is a set of EC JWKs — so
  # that is what we mint, rather than the RSA keys a generic JWT fixture would
  # reach for.
  class Keypair
    COORDINATE_BYTES = 32 # P-256

    attr_reader :kid, :pkey

    def initialize(kid:)
      @kid = kid
      @pkey = OpenSSL::PKey::EC.generate("prime256v1")
    end

    # The public half, in the JWK shape googleauth's KeyInfo.from_jwk parses.
    def jwk
      octets = pkey.public_key.to_octet_string(:uncompressed) # 0x04 || X || Y
      {
        "kty" => "EC",
        "crv" => "P-256",
        "alg" => "ES256",
        "use" => "sig",
        "kid" => kid,
        "x" => url_b64(octets.byteslice(1, COORDINATE_BYTES)),
        "y" => url_b64(octets.byteslice(1 + COORDINATE_BYTES, COORDINATE_BYTES))
      }
    end

    def sign(payload)
      JWT.encode(payload, pkey, "ES256", { "kid" => kid })
    end

    private

    def url_b64(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end
  end

  class << self
    # The keypair whose public half we publish as the IAP JWKS.
    def signing_key
      @signing_key ||= Keypair.new(kid: "cru-iap-test-signing")
    end

    # A keypair that is NOT in the published JWKS — for the wrong-signer case.
    def rogue_key
      @rogue_key ||= Keypair.new(kid: "rogue-not-in-jwks")
    end

    def jwks(*keypairs)
      keypairs = [signing_key] if keypairs.empty?
      { "keys" => keypairs.map(&:jwk) }
    end
  end

  # Drop googleauth's memoized key source and publish a JWKS. Called from a
  # before hook; pass explicit keypairs to publish something other than
  # IapJwt.signing_key.
  def stub_iap_jwks(*keypairs)
    Google::Auth::IDTokens.forget_sources!
    WebMock.stub_request(:get, IapJwt::JWKS_URL).to_return(
      status: 200,
      body: IapJwt.jwks(*keypairs).to_json,
      headers: { "Content-Type" => "application/json" }
    )
  end

  # A PLAIN-IAP claim set (Google/Cloud Identity account, no federation).
  # Pass nil for a claim to OMIT it entirely — a broken workforce pool sends a
  # JWT with no "email" key at all, not an empty one, and the two are not the
  # same input to the verifier.
  #
  # Times are computed from a caller-supplied `now` so nothing depends on how
  # long the suite takes to run.
  def iap_claims(now: Time.now.to_i, **overrides)
    {
      "iss" => IapJwt::IAP_ISSUER,
      "aud" => IapJwt::AUDIENCE,
      "iat" => now - 30,
      "exp" => now + 600,
      # Opaque and namespaced. Never an identity in any IAP mode.
      "sub" => "accounts.google.com:104291823410293841029",
      "email" => "alice@cru.org",
      "name" => "Alice A",
      "hd" => "cru.org"
    }.merge(overrides.transform_keys(&:to_s)).compact
  end

  # A WORKFORCE IDENTITY FEDERATION claim set, in the shape confirmed
  # 2026-07-24 against a captured live payload. Two things matter here and are
  # easy to get wrong from memory:
  #
  #   * `sub` is "sts.google.com:<opaque STS token>" — NOT a principal:// URI,
  #     and not recoverable into an address.
  #   * the principal:// URI is real but lives in the nested
  #     `workforce_identity.iam_principal` claim, which is what IAM bindings
  #     match. The verifier must ignore it.
  #
  # Pass email: nil for the "google.email attribute mapping absent" pool — the
  # claim disappears entirely, which is the whole failure mode.
  def wif_claims(email: "alice@cru.org", pool: "cru-okta-stage", **overrides)
    subject = email || "okta-user-9f31c0"
    iap_claims(
      email: email,
      sub: "sts.google.com:AAFTZtsl9PtVMy-6qd9Otvue3S1_9YyBfNyG0oX3xQdR7kKmMv",
      identity_source: "WORKFORCE_IDENTITY",
      workforce_identity: {
        "iam_principal" =>
          "principal://iam.googleapis.com/locations/global/workforcePools/#{pool}/subject/#{subject}",
        "workforce_pool_name" => "locations/global/workforcePools/#{pool}"
      },
      **overrides
    )
  end

  # Mint a signed assertion. `key:` defaults to the one in the published JWKS.
  def iap_token(key: IapJwt.signing_key, **claim_overrides)
    key.sign(iap_claims(**claim_overrides))
  end

  def wif_token(key: IapJwt.signing_key, **claim_overrides)
    key.sign(wif_claims(**claim_overrides))
  end
end
