require "cru_iap"
require "logger"

# The guards are the whole point, so most of this file is negative controls.
#
# The incident being prevented: dse-portal's AUTH_ENABLED defaulted to the
# insecure value, so forgetting to set it disabled authentication. Every example
# below that expects nil is a way that cannot happen here.
RSpec.describe CruIap::DevBypass do
  let(:quiet) { Logger.new(IO::NULL) }
  let(:email_var) { described_class::EMAIL_VAR }

  def bypass(env, logger: quiet)
    described_class.call(env: env, logger: logger)
  end

  it "is off when nothing is set — the default is closed" do
    expect(bypass({})).to be_nil
  end

  # The API surface is the assertion here: an identity-carrying variable has no
  # wrong default, where AUTH_ENABLED=false vs =true does. Setting the "enable"
  # flag people reach for by habit does nothing at all.
  it "has no boolean to get backwards" do
    expect(bypass({ "AUTH_ENABLED" => "false" })).to be_nil
    expect(bypass({ "CRU_IAP_DEV_BYPASS" => "true" })).to be_nil
    expect(bypass({ "CRU_IAP_DEV_BYPASS_ENABLED" => "1" })).to be_nil
  end

  it "activates when a developer names themselves" do
    result = bypass({ email_var => "dev@cru.org" })

    expect(result).to have_attributes(
      ok?: true,
      reason: "dev_bypass",
      email: "dev@cru.org",
      name: nil
    )
  end

  it "emits a reason from the shared vocabulary" do
    # So a bypassed request is queryable in Datadog alongside every real one,
    # rather than being invisible.
    expect(CruIap::TokenVerifier::REASONS).to include(bypass({ email_var => "dev@cru.org" }).reason)
  end

  it "normalizes the address and carries an optional display name" do
    result = bypass({ email_var => "  Dev@Cru.org  ", described_class::NAME_VAR => "A Developer" })

    expect(result.email).to eq("dev@cru.org")
    expect(result.name).to eq("A Developer")
  end

  describe "guard 1: IAP_AUDIENCE means this is a real IAP environment" do
    it "refuses when IAP_AUDIENCE is set" do
      # cru-terraform injects IAP_AUDIENCE into every IAP-fronted container, so
      # the bypass cannot coexist with the config that means "verify for real".
      env = { email_var => "dev@cru.org", "IAP_AUDIENCE" => "/projects/1/global/backendServices/2" }

      expect(bypass(env)).to be_nil
    end

    it "ignores a blank IAP_AUDIENCE, which is not a configured one" do
      expect(bypass({ email_var => "dev@cru.org", "IAP_AUDIENCE" => "   " }).ok?).to be true
    end
  end

  describe "guard 2: a managed runtime is never a dev machine" do
    # Nobody has to remember to set these — the platform does — which is exactly
    # what makes them trustworthy as a guard.
    described_class::CLOUD_MARKERS.each do |marker|
      it "refuses when #{marker} is present" do
        expect(bypass({ email_var => "dev@cru.org", marker => "anything" })).to be_nil
      end
    end

    it "refuses on Cloud Run even with IAP_AUDIENCE somehow missing" do
      # The guards are independent on purpose: this is the misconfigured-deploy
      # case, where relying on IAP_AUDIENCE alone would open the bypass.
      expect(bypass({ email_var => "dev@cru.org", "K_SERVICE" => "my-app" })).to be_nil
    end
  end

  describe "the identity must survive the same shape gate as a real one" do
    [
      "not-an-address",
      "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/dev@cru.org",
      "dev@cru.org/../admin",
      "sts.google.com:dev@cru.org",
      "@cru.org"
    ].each do |value|
      it "refuses #{value.inspect}" do
        expect(bypass({ email_var => value })).to be_nil
      end
    end
  end

  it "warns loudly on every activation" do
    # A bypass that logs once is a bypass someone forgets is on.
    logger = instance_double(Logger)
    allow(logger).to receive(:warn)

    2.times { bypass({ email_var => "dev@cru.org" }, logger: logger) }

    expect(logger).to have_received(:warn).with(/DEV BYPASS ACTIVE/).twice
  end

  it "explains itself when it refuses" do
    logger = instance_double(Logger)
    allow(logger).to receive(:warn)

    bypass({ email_var => "dev@cru.org", "K_SERVICE" => "my-app" }, logger: logger)

    expect(logger).to have_received(:warn).with(/K_SERVICE/)
  end

  describe "the top-level delegator" do
    it "is what application code is expected to call" do
      result = CruIap.dev_bypass(env: { email_var => "dev@cru.org" }, logger: quiet)

      expect(result.email).to eq("dev@cru.org")
    end
  end
end
