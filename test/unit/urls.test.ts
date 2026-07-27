import { describe, expect, it } from "vitest";

import { LOGIN_QUERY, LOGOUT_QUERY, loginUrl, logoutUrl } from "../../src/urls.js";

/**
 * The two footguns these exist to close, then the string cases that make them
 * worth being code rather than a README bullet.
 */
describe("loginUrl", () => {
  it("never returns bare / — the infinite-loop case", () => {
    // IAP sends bare / to the IdP, which sends it back to /, forever. This is
    // the single most-reported IAP footgun at Cru, so it gets the first test.
    expect(loginUrl()).toBe("/?login=true");
    expect(loginUrl("/")).toBe("/?login=true");
    expect(loginUrl("")).toBe("/?login=true");
    expect(loginUrl("   ")).toBe("/?login=true");
  });

  it("appends to a path", () => {
    expect(loginUrl("/dashboard")).toBe("/dashboard?login=true");
  });

  it("appends to an absolute URL", () => {
    expect(loginUrl("https://app.cru.org/dashboard")).toBe(
      "https://app.cru.org/dashboard?login=true",
    );
  });

  it("uses & when a query is already present", () => {
    expect(loginUrl("/dashboard?tab=reports")).toBe("/dashboard?tab=reports&login=true");
  });

  it("does not produce ?& on a bare trailing question mark", () => {
    expect(loginUrl("/dashboard?")).toBe("/dashboard?login=true");
  });

  it("keeps the fragment last, so the param reaches the server at all", () => {
    // "/a#b" + "?login=true" appended naively is "/a#b?login=true", where the
    // param is part of the fragment and never leaves the browser. This is the
    // case a hand-rolled template gets wrong.
    expect(loginUrl("/dashboard#reports")).toBe("/dashboard?login=true#reports");
    expect(loginUrl("/dashboard?tab=1#reports")).toBe("/dashboard?tab=1&login=true#reports");
  });

  it("is idempotent", () => {
    expect(loginUrl(loginUrl("/dashboard"))).toBe("/dashboard?login=true");
  });

  it("does not mistake a param that merely contains the trigger", () => {
    // "next=/?login=true" is a different param; the trigger is still absent.
    expect(loginUrl("/go?next=%2F%3Flogin%3Dtrue")).toBe(
      "/go?next=%2F%3Flogin%3Dtrue&login=true",
    );
  });
});

describe("logoutUrl", () => {
  it("carries the cookie-clear mode, not just a path", () => {
    // Without this, the app's session goes away, IAP's federated login cookie
    // does not, and the next request signs the same person straight back in.
    expect(logoutUrl()).toBe("/?gcp-iap-mode=CLEAR_LOGIN_COOKIE");
    expect(logoutUrl("/goodbye")).toBe("/goodbye?gcp-iap-mode=CLEAR_LOGIN_COOKIE");
  });

  it("composes with an existing query and fragment", () => {
    expect(logoutUrl("/bye?reason=timeout#top")).toBe(
      "/bye?reason=timeout&gcp-iap-mode=CLEAR_LOGIN_COOKIE#top",
    );
  });

  it("is idempotent", () => {
    expect(logoutUrl(logoutUrl("/bye"))).toBe("/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE");
  });
});

describe("the query constants", () => {
  it("are the literals IAP actually understands", () => {
    // Pinned rather than derived: a typo in either is a silent auth failure,
    // and these strings are Google's, not ours to normalise.
    expect(LOGIN_QUERY).toBe("login=true");
    expect(LOGOUT_QUERY).toBe("gcp-iap-mode=CLEAR_LOGIN_COOKIE");
  });
});
