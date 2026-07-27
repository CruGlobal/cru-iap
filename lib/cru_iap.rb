require "logger"

require_relative "cru_iap/version"
require_relative "cru_iap/token_verifier"
require_relative "cru_iap/strip_forwarded_host"
require_relative "cru_iap/urls"
require_relative "cru_iap/dev_bypass"

# Shared plumbing for Rails/Rack apps that sit behind Google Identity-Aware
# Proxy, with Okta federated in via Workforce Identity Federation.
#
# Deliberately scoped to the parts that do NOT vary between apps:
#
#   - CruIap::TokenVerifier      — verify the IAP assertion header and pull an
#                                  email identity out of it
#   - CruIap::StripForwardedHost — drop a client-forged X-Forwarded-Host
#   - CruIap::Urls               — the two IAP control URLs, built correctly
#   - CruIap::DevBypass          — a dev identity that cannot be enabled in
#                                  production by accident
#
# The last two were added once there were seven consumers rather than two: each
# had re-derived them, and two got them wrong (an infinite sign-in loop, and a
# bypass whose default was the insecure value). They are primitives, not glue —
# each is a pure function the app composes in one line.
#
# What still stays in the app: the controller concern, how rejection is rendered
# (redirect vs 401), the User upsert, session policy, and authorization. Those
# genuinely differ — beacon serves two hosts from one process, flightdeck is an
# OAuth provider — so a single opinionated concern would fit neither. See README
# "What this gem is not".
module CruIap
  class << self
    attr_writer :logger

    # Defaults to a null logger so the gem is silent until an app opts in
    # (`CruIap.logger = Rails.logger`). Rejections are the main thing worth
    # logging — a silent-by-default library beats one that writes to $stdout
    # in someone's test suite.
    def logger
      @logger ||= ::Logger.new(IO::NULL)
    end
  end
end
