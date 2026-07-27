module CruIap
  # The two IAP control URLs, which every consumer was re-typing.
  #
  # These are pure string builders — no request, no config, no I/O — because
  # the mistakes they prevent are string mistakes:
  #
  #   * Linking bare `/` for sign-in instead of `/?login=true`. IAP redirects
  #     to the IdP, the IdP redirects back to `/`, and round it goes. An
  #     infinite loop, and the single most-reported IAP footgun at Cru.
  #   * Signing out without `?gcp-iap-mode=CLEAR_LOGIN_COOKIE`. The app's own
  #     session goes away, IAP's federated login cookie does not, and the next
  #     request silently signs the same person straight back in.
  #
  # Both were checklist items in the README (see "Sign-in CTA"), which is to
  # say they were prose that four apps had to re-read correctly. Now they are
  # code.
  module Urls
    # Appended to trigger IAP's sign-in redirect.
    LOGIN_QUERY = "login=true".freeze

    # Appended to make IAP drop its federated login cookie.
    LOGOUT_QUERY = "gcp-iap-mode=CLEAR_LOGIN_COOKIE".freeze

    class << self
      # @param target [String] path or absolute URL to sign in and land on
      # @return [String] the same target with IAP's login trigger appended
      def login(target = "/")
        with_param(target, LOGIN_QUERY)
      end

      # @param target [String] path or absolute URL to land on after sign-out
      # @return [String] the same target with IAP's cookie-clear mode appended
      def logout(target = "/")
        with_param(target, LOGOUT_QUERY)
      end

      private

      # Query-string surgery that is easy to get wrong by hand, which is the
      # reason this exists rather than an interpolated string at each call site:
      #
      #   * a fragment must stay LAST — "/a#b" + "?login=true" appended naively
      #     yields "/a#b?login=true", where the param is part of the fragment
      #     and never reaches the server at all
      #   * the separator depends on whether a query is already present
      #   * idempotent, so login(login(x)) == login(x)
      def with_param(target, param)
        target = target.to_s
        target = "/" if target.strip.empty?

        base, _, fragment = target.partition("#")
        return target if already_has?(base, param)

        base += separator(base) + param
        fragment.empty? ? base : "#{base}##{fragment}"
      end

      def separator(base)
        return "?" unless base.include?("?")
        # A bare trailing "?" is an empty query: append directly rather than
        # producing "/path?&login=true".
        base.end_with?("?") ? "" : "&"
      end

      def already_has?(base, param)
        _, _, query = base.partition("?")
        query.split("&").include?(param)
      end
    end
  end

  # Convenience delegators, so the common case is CruIap.login_url.
  class << self
    def login_url(target = "/")
      Urls.login(target)
    end

    def logout_url(target = "/")
      Urls.logout(target)
    end
  end
end
