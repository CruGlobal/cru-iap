source "https://rubygems.org"

gemspec

gem "rake", "~> 13.0"
gem "rspec", "~> 3.13"

# Integration-suite only. The gem itself has NO Rails/ActiveSupport runtime
# dependency (see cru_iap.gemspec) and spec/integration/no_runtime_rails_spec.rb
# asserts that stays true. These exist so spec/dummy can be a *real* Rails app
# rather than a mock of one: railties + actionpack, deliberately not the `rails`
# meta-gem, so ActiveRecord/ActionMailer/etc. are not even installed.
group :test do
  gem "railties", "~> 8.0"
  gem "actionpack", "~> 8.0"
  gem "rack-test", "~> 2.1"
  # Serves the IAP JWKS from memory so googleauth's real JwkHttpKeySource runs
  # against locally-minted keys instead of www.gstatic.com.
  gem "webmock", "~> 3.19"
end
