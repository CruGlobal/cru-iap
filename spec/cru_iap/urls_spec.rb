require "cru_iap"

# The two footguns these exist to close, then the string cases that make them
# worth being code rather than a README bullet.
RSpec.describe CruIap::Urls do
  describe ".login" do
    it "never returns bare / — the infinite-loop case" do
      # IAP sends bare / to the IdP, which sends it back to /, forever. The
      # single most-reported IAP footgun at Cru, so it gets the first example.
      expect(described_class.login).to eq("/?login=true")
      expect(described_class.login("/")).to eq("/?login=true")
      expect(described_class.login("")).to eq("/?login=true")
      expect(described_class.login("   ")).to eq("/?login=true")
    end

    it "appends to a path" do
      expect(described_class.login("/dashboard")).to eq("/dashboard?login=true")
    end

    it "appends to an absolute URL" do
      expect(described_class.login("https://app.cru.org/dashboard"))
        .to eq("https://app.cru.org/dashboard?login=true")
    end

    it "uses & when a query is already present" do
      expect(described_class.login("/dashboard?tab=reports"))
        .to eq("/dashboard?tab=reports&login=true")
    end

    it "does not produce ?& on a bare trailing question mark" do
      expect(described_class.login("/dashboard?")).to eq("/dashboard?login=true")
    end

    it "keeps the fragment last, so the param reaches the server at all" do
      # "/a#b" with "?login=true" appended naively is "/a#b?login=true", where
      # the param is part of the fragment and never leaves the browser. This is
      # the case a hand-rolled interpolation gets wrong.
      expect(described_class.login("/dashboard#reports")).to eq("/dashboard?login=true#reports")
      expect(described_class.login("/dashboard?tab=1#reports"))
        .to eq("/dashboard?tab=1&login=true#reports")
    end

    it "is idempotent" do
      expect(described_class.login(described_class.login("/dashboard")))
        .to eq("/dashboard?login=true")
    end

    it "does not mistake a param that merely contains the trigger" do
      expect(described_class.login("/go?next=%2F%3Flogin%3Dtrue"))
        .to eq("/go?next=%2F%3Flogin%3Dtrue&login=true")
    end
  end

  describe ".logout" do
    it "carries the cookie-clear mode, not just a path" do
      # Without this the app's session goes away, IAP's federated login cookie
      # does not, and the next request signs the same person straight back in.
      expect(described_class.logout).to eq("/?gcp-iap-mode=CLEAR_LOGIN_COOKIE")
      expect(described_class.logout("/goodbye")).to eq("/goodbye?gcp-iap-mode=CLEAR_LOGIN_COOKIE")
    end

    it "composes with an existing query and fragment" do
      expect(described_class.logout("/bye?reason=timeout#top"))
        .to eq("/bye?reason=timeout&gcp-iap-mode=CLEAR_LOGIN_COOKIE#top")
    end

    it "is idempotent" do
      expect(described_class.logout(described_class.logout("/bye")))
        .to eq("/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE")
    end
  end

  describe "the query constants" do
    it "are the literals IAP actually understands" do
      # Pinned rather than derived: a typo in either is a silent auth failure,
      # and these strings are Google's, not ours to normalise.
      expect(described_class::LOGIN_QUERY).to eq("login=true")
      expect(described_class::LOGOUT_QUERY).to eq("gcp-iap-mode=CLEAR_LOGIN_COOKIE")
    end
  end

  describe "the top-level delegators" do
    it "are what application code is expected to call" do
      expect(CruIap.login_url("/x")).to eq("/x?login=true")
      expect(CruIap.logout_url("/x")).to eq("/x?gcp-iap-mode=CLEAR_LOGIN_COOKIE")
    end
  end
end
