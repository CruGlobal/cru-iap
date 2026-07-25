module Cru
  module Iap
    # Drops the X-Forwarded-Host request header before anything reads it.
    #
    # Rails resolves `request.host` from X-Forwarded-Host BEFORE the Host
    # header (ActionDispatch::Http::URL#raw_host_with_port), Journey's
    # `constraints host:` route matching reads the same value, and
    # HostAuthorization checks it against `config.hosts` — which typically
    # allow-lists the app's own hostnames plus `*.run.app`, so a forged value
    # sails through.
    #
    # GCLB preserves Host and never sets X-Forwarded-Host, which means a
    # present value is always client-forged. Without this strip, an app that
    # keys anything off `request.host` — "only trust the IAP header on the
    # host IAP actually fronts", host-constrained routes, per-host layouts —
    # can be steered by an attacker-supplied header.
    #
    # Identity itself is never forgeable this way (the IAP JWT is signed), but
    # the routing/host layer should hold its own properties without leaning on
    # that.
    #
    # Install it ahead of everything, in config/application.rb:
    #
    #   config.middleware.insert_before 0, Cru::Iap::StripForwardedHost
    #
    # (before ActionDispatch::HostAuthorization, so nothing in the stack ever
    # sees the header).
    class StripForwardedHost
      def initialize(app)
        @app = app
      end

      def call(env)
        env.delete("HTTP_X_FORWARDED_HOST")
        @app.call(env)
      end
    end
  end
end
