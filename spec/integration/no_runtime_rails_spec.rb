require "open3"

# The gem's "no Rails, no ActiveSupport at runtime" promise, enforced rather
# than documented.
#
# It has to run in a subprocess: this suite loads a whole Rails app two files
# over, so in-process `defined?(ActiveSupport)` would always be truthy and the
# assertion would be worthless. The child runs inside the same bundle — Rails
# is installed and on the load path, it is simply never required — so this
# fails the moment lib/ picks up an `ActiveSupport::` call or a `require
# "active_support/..."`.
#
# No network: `bundle exec` against an already-installed bundle.
RSpec.describe "cru_iap runtime dependencies" do
  def gem_root
    File.expand_path("../..", __dir__)
  end

  def load_gem_in_subprocess(script)
    Open3.capture3(
      { "BUNDLE_GEMFILE" => File.join(gem_root, "Gemfile") },
      "bundle", "exec", "ruby", "-e", %(require "cru_iap"\n#{script}),
      chdir: gem_root
    )
  end

  it "loads without pulling in ActiveSupport or Rails" do
    stdout, stderr, status = load_gem_in_subprocess(<<~RUBY)
      loaded = { activesupport: !defined?(ActiveSupport).nil?,
                 rails: !defined?(Rails).nil?,
                 actionpack: !defined?(ActionDispatch).nil? }
      puts loaded.select { |_k, v| v }.keys.join(",")
    RUBY

    expect(status).to be_success, "subprocess failed: #{stderr}"
    expect(stdout.strip).to eq(""), "cru_iap pulled in: #{stdout.strip}"
  end

  it "exposes the whole public surface without Rails loaded" do
    _stdout, stderr, status = load_gem_in_subprocess(<<~RUBY)
      raise "TokenVerifier missing" unless defined?(CruIap::TokenVerifier)
      raise "StripForwardedHost missing" unless defined?(CruIap::StripForwardedHost)
      raise "logger missing" unless CruIap.logger

      # The bare-Rack-env path, exercised with no ActionDispatch anywhere.
      result = CruIap::TokenVerifier.from_request({}, audience: "/projects/1/global/backendServices/2")
      raise "expected missing_token, got \#{result.reason}" unless result.reason == "missing_token"

      # And the middleware, against a plain Rack app.
      app = CruIap::StripForwardedHost.new(->(env) { [200, {}, [env.key?("HTTP_X_FORWARDED_HOST").to_s]] })
      _s, _h, body = app.call({ "HTTP_X_FORWARDED_HOST" => "evil.example" })
      raise "header survived" unless body.first == "false"
    RUBY

    expect(status).to be_success, "subprocess failed: #{stderr}"
  end
end
