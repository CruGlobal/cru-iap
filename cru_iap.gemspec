require_relative "lib/cru_iap/version"

Gem::Specification.new do |spec|
  # Gem name is underscored so Bundler.require resolves it straight to
  # lib/cru_iap.rb — a hyphenated name needs a shim file. The GitHub repo
  # stays hyphenated (CruGlobal/cru-iap).
  spec.name        = "cru_iap"
  spec.version     = CruIap::VERSION
  spec.authors     = ["Matt Drees"]
  spec.email       = ["matt.drees@cru.org"]

  spec.summary     = "Google IAP (+ Workforce Identity Federation) request authentication for Cru Rails apps"
  spec.description = "Verifies the assertion header Google Identity-Aware Proxy injects, including " \
                     "the Workforce Identity Federation principal shapes Okta federation produces, " \
                     "and strips client-forged X-Forwarded-Host."
  spec.homepage    = "https://github.com/CruGlobal/cru-iap"
  spec.license     = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.metadata["homepage_uri"]  = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE.txt"]
  spec.require_paths = ["lib"]

  # verify_iap + the IAP JWKS key source. No Rails/ActiveSupport dependency
  # on purpose — this works in a plain Rack app too.
  spec.add_dependency "googleauth", ">= 1.11", "< 2.0"
end
