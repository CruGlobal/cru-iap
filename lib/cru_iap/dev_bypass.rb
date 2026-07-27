require "uri"

module CruIap
  # A dev/test identity that cannot be switched on in production by accident.
  #
  # Three consumers each grew their own bypass, in three incompatible shapes,
  # and one of them shipped an incident: dse-portal's `AUTH_ENABLED` defaulted
  # to the INSECURE value, so forgetting to set it disabled authentication.
  # That is the failure mode this primitive is built to make unreachable.
  #
  # Why there is no boolean
  # ----------------------
  # A boolean flag has a wrong default — someone has to choose it, and half the
  # time they choose the open one. An identity-carrying variable has no wrong
  # default: either you name a developer to be, or you don't, and "unset" can
  # only mean "no bypass". So the opt-in IS the identity:
  #
  #   CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org bin/rails server
  #
  # There is deliberately no `CruIap.dev_bypass_enabled = true` setter either.
  # Anything an app can turn on in a config file, an app can turn on in
  # config/environments/production.rb.
  #
  # Two independent guards on top
  # -----------------------------
  # Neither depends on the app being written correctly:
  #
  #   1. IAP_AUDIENCE set  => refuse. A deploy configured for IAP is a deploy
  #      that must verify, and cru-terraform injects IAP_AUDIENCE into every
  #      IAP-fronted container. So the bypass cannot coexist with the config
  #      that means "this is a real IAP environment".
  #   2. A cloud-runtime marker present => refuse. Cloud Run always sets
  #      K_SERVICE; App Engine sets GAE_ENV; Cloud Functions sets
  #      FUNCTION_TARGET. Nobody has to remember to set these, which is exactly
  #      what makes them trustworthy as a guard.
  #
  # Composition (the app writes one line, not a branch):
  #
  #   result = CruIap.dev_bypass || CruIap::TokenVerifier.from_request(request)
  #
  # Putting the bypass first is safe precisely because of the guards above: in
  # any environment where it could matter, it returns nil.
  module DevBypass
    EMAIL_VAR = "CRU_IAP_DEV_BYPASS_EMAIL".freeze
    NAME_VAR = "CRU_IAP_DEV_BYPASS_NAME".freeze

    # Set by the platform, not by us — see guard 2 above.
    CLOUD_MARKERS = %w[K_SERVICE K_REVISION GAE_ENV FUNCTION_TARGET].freeze

    class << self
      # @param env [Hash] defaults to ENV; injectable so specs need no shell
      # @param logger [Logger]
      # @return [CruIap::TokenVerifier::Result, nil] nil means "no bypass" —
      #   the caller must then verify for real
      def call(env: ENV, logger: CruIap.logger)
        email = env[EMAIL_VAR].to_s.strip
        return nil if email.empty?

        return refuse(logger, "IAP_AUDIENCE is set") unless blank?(env["IAP_AUDIENCE"])

        marker = CLOUD_MARKERS.find { |name| !blank?(env[name]) }
        return refuse(logger, "#{marker} is set, so this is a managed runtime") if marker

        identity = email.downcase
        unless plausible_email?(identity)
          return refuse(logger, "#{EMAIL_VAR}=#{email.inspect} is not an email address")
        end

        # Loud on every activation, deliberately. A bypass that logs once is a
        # bypass someone forgets is on; dev-server request volume makes this
        # affordable.
        logger.warn(
          "[CruIap] DEV BYPASS ACTIVE — the IAP assertion is NOT being verified. " \
          "Acting as #{identity}. Unset #{EMAIL_VAR} to restore verification."
        )

        name = env[NAME_VAR].to_s.strip
        TokenVerifier::Result.new(
          ok: true,
          reason: "dev_bypass",
          email: identity,
          name: (name.empty? ? nil : name)
        )
      end

      private

      def refuse(logger, why)
        logger.warn("[CruIap] ignoring #{EMAIL_VAR}: #{why}. Verifying the IAP assertion instead.")
        nil
      end

      # The same shape gate the verifier applies, so a bypass identity can never
      # become a user row the real path would have rejected.
      def plausible_email?(value)
        value.match?(URI::MailTo::EMAIL_REGEXP) &&
          !value.match?(TokenVerifier::NEVER_IN_AN_EMAIL)
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end

  class << self
    def dev_bypass(env: ENV, logger: CruIap.logger)
      DevBypass.call(env: env, logger: logger)
    end
  end
end
