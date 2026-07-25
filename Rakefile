require "bundler/gem_tasks"
require "rspec/core/rake_task"

# Two suites, deliberately run as two processes.
#
#   unit        — spec/cru_iap. Stubs Google::Auth::IDTokens.verify_iap and
#                 never loads Rails, which is what keeps the gem's "no Rails,
#                 no ActiveSupport at runtime" promise testable at all.
#   integration — spec/integration. Boots the dummy Rails app in spec/dummy and
#                 drives real requests carrying real signed JWTs, verified
#                 against a locally minted JWKS. Offline; no cloud dependency.
#
# Separate processes so the integration suite's Rails/ActiveSupport can never
# quietly satisfy something the unit suite is meant to prove without it.
RSpec::Core::RakeTask.new(:unit) do |task|
  task.pattern = "spec/cru_iap/**/*_spec.rb"
end

RSpec::Core::RakeTask.new(:integration) do |task|
  task.pattern = "spec/integration/**/*_spec.rb"
end

desc "Run both suites in a single process (what a bare `rspec` does)"
RSpec::Core::RakeTask.new(:spec)

task default: %i[unit integration]
