require "json"
require "uri"
require "googleauth/id_tokens"

module CruIap
  # Verifies the Google-signed JWT that Identity-Aware Proxy injects on every
  # request it lets through to a backend, and extracts an email identity.
  #
  # Flow:
  #
  #   1. No token → reject. Callers normally only invoke us when the header is
  #      present, but stay defensive.
  #
  #   2. No audience configured → reject. `aud` for an IAP JWT is the
  #      backend-service resource path (`/projects/NUMBER/global/
  #      backendServices/ID`), supplied by cru-terraform as IAP_AUDIENCE. Fail
  #      closed if unset so a misconfigured deploy never accepts unaudienced
  #      tokens.
  #
  #   3. `Google::Auth::IDTokens.verify_iap` validates the signature against
  #      Google's published IAP JWKS, checks `aud`, and (confirmed in
  #      googleauth 1.17.1) checks `iss` against IAP_ISSUERS =
  #      ["https://cloud.google.com/iap"] by default. We re-assert `iss`
  #      manually anyway — belt-and-braces, so a future gem bump that loosens
  #      the default can't silently widen who we trust.
  #
  #   4. Extract identity from the `email` claim — and only that claim. See
  #      normalize_email for the evidence on why `sub` is never an identity.
  #
  # Returns a Result (ok? + reason for telemetry/logging + email/name). The
  # caller decides what ok? means — upsert and sign in, or treat the request as
  # unauthenticated. This class never touches a User model or a session.
  class TokenVerifier
    Result = Struct.new(:ok, :reason, :email, :name, keyword_init: true) do
      def ok? = ok
    end

    IAP_ISSUER = "https://cloud.google.com/iap".freeze

    # The header IAP injects. Exposed because infra config and test fixtures
    # legitimately need the wire name — application code should not, and
    # should call .from_request instead of reaching for it.
    HEADER = "x-goog-iap-jwt-assertion".freeze

    # The same header as Rack normalizes it into env.
    RACK_ENV_KEY = "HTTP_X_GOOG_IAP_JWT_ASSERTION".freeze

    # URI::MailTo::EMAIL_REGEXP alone is not a sufficient shape gate. RFC 5322
    # permits "/" in a local part, so a URI-shaped value ending in an address
    # — e.g. "principal://iam.googleapis.com/.../subject/alice@cru.org" —
    # MATCHES it, and would be persisted as a user whose email is that entire
    # string. No real Okta or Google identity contains a slash or a backslash,
    # so treat either as proof we are looking at a URI or principal rather
    # than an address.
    NEVER_IN_AN_EMAIL = %r{[/\\]}

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

    # Preferred entry point: pulls the assertion off the request itself, so
    # application code never has to name the header.
    #
    # Accepts an ActionDispatch::Request, a Rack::Request, or a bare Rack env
    # Hash.
    def self.from_request(request, **opts)
      call(assertion_from(request), **opts)
    end

    def self.assertion_from(request)
      if request.respond_to?(:get_header)
        request.get_header(RACK_ENV_KEY)
      elsif request.respond_to?(:[])
        request[RACK_ENV_KEY]
      end
    end

    # @param assertion_header [String, nil] the raw assertion JWT
    # @param audience [String, nil] backend-service resource path; defaults to ENV["IAP_AUDIENCE"]
    # @param logger [Logger] defaults to CruIap.logger (null unless the app sets one)
    def self.call(assertion_header, audience: ENV["IAP_AUDIENCE"], logger: CruIap.logger)
      new(assertion_header, audience: audience, logger: logger).call
    end

    def initialize(assertion_header, audience: ENV["IAP_AUDIENCE"], logger: CruIap.logger)
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

      email = normalize_email(payload["email"])
      # Two distinct failure reasons on purpose. `missing_email` = the pool
      # never sent one, which is an infrastructure fix (see the comment on
      # normalize_email). `malformed_subject` = something arrived that isn't
      # an address. Different fixes — keep them distinguishable in Datadog.
      return Result.new(ok: false, reason: "missing_email") if blank?(email)

      if !email.match?(URI::MailTo::EMAIL_REGEXP) || email.match?(NEVER_IN_AN_EMAIL)
        # Log the raw claims so a rejection is diagnosable without
        # re-deploying instrumentation. Identity claims, not credentials —
        # same sensitivity as the emails already in request logs. (The 2026-07
        # beacon-stage cutover burned two blind deploy cycles guessing at the
        # workforce JWT's claim shape.)
        @logger.warn(
          "[CruIap] malformed subject: normalized=#{email.inspect} payload=#{payload.to_json}"
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
      @logger.warn("[CruIap] unexpected #{e.class}: #{e.message}")
      Result.new(ok: false, reason: "unexpected_error")
    end

    private

    # `email` is the identity in every IAP mode. `sub` is NEVER an identity —
    # it is an opaque namespaced token — so this deliberately does not read
    # it. Confirmed 2026-07-24 against a captured live payload (keep-zero POC
    # echoserver) plus beacon-stage's Datadog logs on both sides of the
    # cru-terraform google.email mapping fix:
    #
    #   mode                       email                sub
    #   -------------------------- -------------------- -----------------------------
    #   plain IAP (Google id)      bare address         accounts.google.com:<opaque>
    #   WIF, google.email mapped   bare address         sts.google.com:<opaque STS>
    #   WIF, mapping absent        ABSENT               sts.google.com:<opaque STS>
    #
    # The third row is a broken pool, and no app-side fallback can recover an
    # address from it — `sub` carries none. Reaching for `sub` there buys
    # nothing and costs diagnosis: it turns an accurate `missing_email`
    # (= go fix the pool's attribute_mapping) into a misleading
    # `malformed_subject` (= we saw a principal shape we don't understand).
    # Beacon shipped exactly that fallback during the 2026-07 cutover and it
    # muddied the logs; don't reintroduce it.
    #
    # NB the workforce principal URI ("principal://iam.googleapis.com/.../
    # subject/<email>") IS real, but it lives in the nested
    # `workforce_identity.iam_principal` claim — it is the string IAM
    # bindings match, not an identity claim, and it never appears in `email`
    # or `sub`. A verifier that unwraps it out of those is handling a shape
    # IAP does not emit, and worse, is ACCEPTING a value it would otherwise
    # correctly reject.
    #
    # Strip a leading "<prefix>:" namespace before validating: a real email
    # never contains a colon, so the first colon is always the IAP namespace.
    # Observed prefixes are "accounts.google.com:", "sts.google.com:", and
    # Identity Platform's "securetoken.google.com/<project>/<tenant>:" —
    # split on the first colon rather than matching any literal prefix.
    #
    # Then downcase, to match the usual citext/lowercased email column.
    #
    # Shape validation happens in `call` (malformed_subject): callers
    # generally persist whatever we hand back, so a value that isn't
    # email-shaped must reject rather than become a garbage user row.
    def normalize_email(raw)
      email = raw.to_s.strip
      email = email.split(":", 2).last if email.include?(":")
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
