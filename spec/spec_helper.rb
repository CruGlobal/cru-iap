require "cru/iap"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.mock_with(:rspec) { |c| c.verify_partial_doubles = true }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed

  # The gem reads ENV["IAP_AUDIENCE"] as the default audience. Make sure an
  # ambient value in the developer's shell can't quietly satisfy a spec that
  # is meant to exercise the missing-config path.
  config.around do |example|
    original = ENV["IAP_AUDIENCE"]
    ENV.delete("IAP_AUDIENCE")
    example.run
  ensure
    ENV["IAP_AUDIENCE"] = original
  end
end
