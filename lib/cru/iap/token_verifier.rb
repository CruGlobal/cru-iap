require "cgi"
require "json"
require "uri"
require "googleauth/id_tokens"

module Cru
  module Iap
    # Verifies the Google-signed JWT that Identity-Aware Proxy injects as the
    # `x-goog-iap-jwt-assertion` request header on every request it lets
    # through to a backend, and extracts an email identity from it.
    #
    # Flow:
    #
    #   1. No token → reject. Callers normally only invoke us when the header
    #      is present, but stay defensive.
    #
    #   2. No audience configured → reject. `aud` for an IAP JWT is the
    #      backend-service resource path (`/projects/NUMBER/global/
    #      backendServices/ID`), supplied by cru-terraform as IAP_AUDIENCE.
    #      Fail closed if unset so a misconfigured deploy never accepts
    #      unaudienced tokens.
    #
    #   3. `Google::Auth::IDTokens.verify_iap` validates the signature against
    #      Google's published IAP JWKS, checks `aud`, and (confirmed in
    #      googleauth 1.17.1) checks `iss` against IAP_ISSUERS =
    #      ["https://cloud.google.com/iap"] by default. We re-assert `iss`
    #      manually anyway — belt-and-braces, so a future gem bump that
    #      loosens the default can't silently widen who we trust.
    #
    #   4. Extract identity. Under Workforce Identity Federation the JWT has
    #      NO `email` claim at all (confirmed live on beacon-stage) — the
    #      identity is the `sub` claim, the workforce principal URI
    #      ("principal://iam.googleapis.com/locations/global/workforcePools/
    #      <pool>/subject/<subject>", where subject is the pool's
    #      google.subject mapping = the Okta email). So: prefer `email` when
    #      present (Google-identity IAP), fall back to `sub`. Either value may
    #      also be namespaced ("accounts.google.com:<email>"). Unwrap,
    #      downcase, and require an email shape before handing back.
    #
    # Returns a Result (ok? + reason for telemetry/logging + email/name). The
    # caller decides what ok? means — upsert and sign in, or treat the request
    # as unauthenticated. This class never touches a User model or a session.
    class TokenVerifier
      Result = Struct.new(:ok, :reason, :email, :name, keyword_init: true) do
        def ok? = ok
      end

      IAP_ISSUER = "https://cloud.google.com/iap".freeze

      # The reason vocabulary, so every app behind IAP files the same Datadog
      # queries. Entries ending in ":" carry a variable suffix.
      REASONS = [
        "missing_token",            # header absent/blank
        "missing_audience_config",  # IAP_AUDIENCE unset — deploy misconfig
        "bad_iss:",                 # + the offending iss
        "missing_email",            # no email AND no sub — IAP/pool config gap
        "malformed_subject",        # present but not email-shaped after unwrap
        "signature_error:",         # + the underlying message
        "audience_mismatch",
        "expired_token",
        "issuer_mismatch",
        "verification_error:",      # + the googleauth error class
        "unexpected_error",         # fail-closed catch-all
        "iap_jwt"                   # the only ok? == true reason
      ].freeze

      # The WIF principal URI shape IAP puts in the identity claim for
      # workforce-federated identities. The subject segment is the pool's
      # google.subject mapping — Cru's pools map it to the Okta email
      # (cru-terraform workforce.tf). Percent-encoded by IAP, hence the
      # CGI.unescape when unwrapping.
      WORKFORCE_PRINCIPAL =
        %r{\Aprincipal://iam\.googleapis\.com/locations/[^/]+/workforcePools/[^/]+/subject/(?<subject>.+)\z}

      # @param assertion_header [String, nil] the raw x-goog-iap-jwt-assertion value
      # @param audience [String, nil] backend-service resource path; defaults to ENV["IAP_AUDIENCE"]
      # @param logger [Logger] defaults to Cru::Iap.logger (null logger unless the app sets one)
      def self.call(assertion_header, audience: ENV["IAP_AUDIENCE"], logger: Cru::Iap.logger)
        new(assertion_header, audience: audience, logger: logger).call
      end

      def initialize(assertion_header, audience: ENV["IAP_AUDIENCE"], logger: Cru::Iap.logger)
        @token = assertion_header.to_s
        @audience = audience.to_s
        @logger = logger
      end

      def call
        return Result.new(ok: false, reason: "missing_token") if blank?(@token)
        return Result.new(ok: false, reason: "missing_audience_config") if blank?(@audience)

        payload = Google::Auth::IDTokens.verify_iap(@token, aud: @audience)

        iss = payload["iss"].to_s
        return Result.new(ok: false, reason: "bad_iss:#{iss}") unless iss == IAP_ISSUER

        email = normalize_email(identity_claim(payload))
        # Two distinct failure reasons on purpose: both claims absent = an
        # IAP/pool config gap (usually a missing google.email attribute
        # mapping); present-but-not-email-shaped = a WIF principal shape we
        # didn't anticipate. Different fixes — keep them distinguishable.
        return Result.new(ok: false, reason: "missing_email") if blank?(email)

        unless email.match?(URI::MailTo::EMAIL_REGEXP)
          # Log the raw claims so a rejection is diagnosable without
          # re-deploying instrumentation. Identity claims, not credentials —
          # same sensitivity as the emails already in request logs. (The
          # 2026-07 beacon-stage cutover burned two blind deploy cycles
          # guessing at the workforce JWT's claim shape.)
          @logger.warn(
            "[Cru::Iap] malformed subject: normalized=#{email.inspect} payload=#{payload.to_json}"
          )
          return Result.new(ok: false, reason: "malformed_subject")
        end

        name = payload["name"].to_s.strip
        Result.new(ok: true, reason: "iap_jwt", email: email, name: (name.empty? ? nil : name))
      rescue Google::Auth::IDTokens::SignatureError => e
        Result.new(ok: false, reason: "signature_error:#{e.message}")
      rescue Google::Auth::IDTokens::AudienceMismatchError
        Result.new(ok: false, reason: "audience_mismatch")
      rescue Google::Auth::IDTokens::ExpiredTokenError
        Result.new(ok: false, reason: "expired_token")
      rescue Google::Auth::IDTokens::IssuerMismatchError
        Result.new(ok: false, reason: "issuer_mismatch")
      rescue Google::Auth::IDTokens::KeySourceError, Google::Auth::IDTokens::VerificationError => e
        Result.new(ok: false, reason: "verification_error:#{demodulize(e.class.name)}")
      rescue StandardError => e
        @logger.warn("[Cru::Iap] unexpected #{e.class}: #{e.message}")
        Result.new(ok: false, reason: "unexpected_error")
      end

      private

      # Prefer `email` (plain Google-identity IAP); fall back to `sub` (the
      # workforce JWT shape, which has no email claim at all).
      def identity_claim(payload)
        email = payload["email"]
        blank?(email.to_s) ? payload["sub"] : email
      end

      # Unwrap the two namespaced principal shapes IAP produces under WIF:
      #
      # 1. The workforce principal URI (the shape beacon-stage actually
      #    receives): "principal://iam.googleapis.com/.../subject/<email>".
      #    Must be checked FIRST — it contains colons, so the generic
      #    prefix-strip below would mangle it to "//iam.googleapis.com/…".
      # 2. An identity-source prefix, e.g. "accounts.google.com:alice@cru.org".
      #    A real email never contains a colon, so a leading "<prefix>:" is
      #    always the IAP namespace — split on the first colon, keep the rest.
      #
      # Then downcase, to match the usual citext/lowercased email column.
      #
      # Shape validation happens in `call` (malformed_subject): callers
      # generally persist whatever we hand back, so an unwrapped value that
      # still isn't email-shaped (group principalSets, unexpected pool paths,
      # opaque subjects) must reject rather than become a garbage user row.
      def normalize_email(raw)
        email = raw.to_s.strip
        if (workforce = email.match(WORKFORCE_PRINCIPAL))
          email = CGI.unescape(workforce[:subject])
        elsif email.include?(":")
          email = email.split(":", 2).last
        end
        email.to_s.downcase
      end

      def blank?(str)
        str.nil? || str.to_s.strip.empty?
      end

      def demodulize(name)
        name.to_s.split("::").last
      end
    end
  end
end
