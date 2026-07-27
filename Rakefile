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

# e2e — spec/e2e. Verifies a REAL assertion captured from live Google
# infrastructure against Google's real JWKS. Needs `e2e/okta/capture.json`
# (written by e2e/okta/capture_assertion.mjs --json) and network egress; skips
# with a reason when either is absent. Never part of `default`.
#
# Its own process, and not merely its own pattern: the offline suites require
# `webmock/rspec`, which disables real net connect for the whole process. This
# suite is the one that must reach gstatic.com.
desc "Live e2e against a captured real IAP assertion (see e2e/README.md)"
RSpec::Core::RakeTask.new(:e2e) do |task|
  task.pattern = "spec/e2e/**/*_spec.rb"
end

# Both OFFLINE suites in a single process. Deliberately pattern-scoped rather
# than left at rspec's default `spec/**/*_spec.rb`, which would now also drag in
# spec/e2e — and with it webmock's net-connect block, under which the e2e suite
# cannot do the one thing it exists to do.
desc "Run both offline suites in a single process"
RSpec::Core::RakeTask.new(:spec) do |task|
  task.pattern = "spec/{cru_iap,integration}/**/*_spec.rb"
end

task default: %i[unit integration]
