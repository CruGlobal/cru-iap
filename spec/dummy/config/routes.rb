Dummy::Application.routes.draw do
  # Public: never looks at the assertion. Proves the gem is opt-in per route
  # and that a missing header does not break unauthenticated traffic.
  get "/public", to: "pages#public_page"

  # Auth-gated: fails closed. A rejection must not serve the content.
  get "/gated", to: "pages#gated"

  # Reads the identity several times in one action, to pin the memoization
  # contract the README's reference wiring depends on.
  get "/repeated", to: "pages#repeated"

  # Echoes what the app believes about its own host, for the
  # StripForwardedHost examples.
  get "/host", to: "pages#host"

  # A host-constrained route: the end-to-end proof that a forged
  # X-Forwarded-Host cannot steer routing. Journey matches this against
  # request.host, which is exactly the value the middleware protects.
  constraints host: "admin.example.com" do
    get "/admin", to: "pages#admin"
  end
end
