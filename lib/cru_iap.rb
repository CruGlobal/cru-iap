require "logger"

require_relative "cru_iap/version"
require_relative "cru_iap/token_verifier"
require_relative "cru_iap/strip_forwarded_host"

# Shared plumbing for Rails/Rack apps that sit behind Google Identity-Aware
# Proxy, with Okta federated in via Workforce Identity Federation.
#
# Deliberately scoped to the parts that do NOT vary between apps:
#
#   - CruIap::TokenVerifier      — verify the IAP assertion header and pull an
#                                  email identity out of it
#   - CruIap::StripForwardedHost — drop a client-forged X-Forwarded-Host
#
# Everything downstream of "who is this?" stays in the app: the controller
# concern, how rejection is rendered (redirect vs 401), the dev/test bypass,
# the User upsert, and authorization. Those diverged immediately across the
# first two consumers (beacon, cru-bot) — see README "What this gem is not".
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
