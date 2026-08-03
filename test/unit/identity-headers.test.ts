import { describe, expect, it } from "vitest";

import {
  IDENTITY_HEADERS,
  identityFrom,
  stampIdentity,
  stripIdentity,
  type Identified,
} from "../../src/index.js";

/**
 * The headers are a trust boundary, so the tests that matter are the negative
 * ones: an inbound value must never be readable as something we stamped.
 */

const verified = (overrides: Partial<Identified> = {}): Identified =>
  ({
    ok: true,
    reason: "iap_jwt",
    email: "alice@cru.org",
    name: "Alice A",
    payload: { iat: 1_770_000_000 },
    ...overrides,
  }) as Identified;

const spoofed = (): Headers =>
  new Headers({
    [IDENTITY_HEADERS.email]: "admin@cru.org",
    [IDENTITY_HEADERS.name]: "An Admin",
    [IDENTITY_HEADERS.issuedAt]: "1",
  });

describe("IDENTITY_HEADERS", () => {
  it("names the three headers cru-web-campaign already ships", () => {
    // Frozen, not configurable: a rename is a silent behaviour change in both
    // the app that stamps and the app that reads.
    expect(IDENTITY_HEADERS).toEqual({
      email: "x-cru-iap-email",
      name: "x-cru-iap-name",
      issuedAt: "x-cru-iap-issued-at",
    });
  });
});

describe("stripIdentity", () => {
  it("removes all three, not just the email", () => {
    const headers = spoofed();

    stripIdentity(headers);

    expect([...headers.keys()]).toEqual([]);
  });

  it("leaves everything else alone", () => {
    const headers = spoofed();
    headers.set("x-request-id", "abc");

    stripIdentity(headers);

    expect(headers.get("x-request-id")).toBe("abc");
  });
});

describe("stampIdentity", () => {
  it("stamps all three from a verified assertion", () => {
    const headers = new Headers();

    stampIdentity(headers, verified());

    expect(Object.fromEntries(headers)).toEqual({
      [IDENTITY_HEADERS.email]: "alice@cru.org",
      [IDENTITY_HEADERS.name]: "Alice A",
      [IDENTITY_HEADERS.issuedAt]: "1770000000",
    });
  });

  it("overwrites an inbound email", () => {
    const headers = spoofed();

    stampIdentity(headers, verified());

    expect(headers.get(IDENTITY_HEADERS.email)).toBe("alice@cru.org");
  });

  it("drops an inbound name when the assertion has none", () => {
    // The real workforce payload has no `name` claim, so this is the production
    // path — a client must not be able to supply the display name.
    const headers = spoofed();

    stampIdentity(headers, verified({ name: null }));

    expect(headers.has(IDENTITY_HEADERS.name)).toBe(false);
  });

  it("drops an inbound issued-at for a dev bypass, which verified nothing", () => {
    const headers = spoofed();

    stampIdentity(headers, {
      ok: true,
      reason: "dev_bypass",
      email: "dev@cru.org",
      name: null,
      payload: null,
    });

    expect(Object.fromEntries(headers)).toEqual({ [IDENTITY_HEADERS.email]: "dev@cru.org" });
  });

  it("omits issued-at when iat is not a number", () => {
    const headers = new Headers();

    stampIdentity(headers, verified({ payload: { iat: "1770000000" } as never }));

    expect(headers.has(IDENTITY_HEADERS.issuedAt)).toBe(false);
  });
});

describe("identityFrom", () => {
  it("round-trips what stampIdentity wrote", () => {
    const headers = new Headers();
    stampIdentity(headers, verified());

    expect(identityFrom(headers)).toEqual({
      email: "alice@cru.org",
      name: "Alice A",
      issuedAt: 1_770_000_000,
    });
  });

  it("returns null when there is no email — the identity, not a partial object", () => {
    expect(identityFrom(new Headers())).toBeNull();
    expect(identityFrom({ [IDENTITY_HEADERS.name]: "An Admin" })).toBeNull();
    expect(identityFrom(new Headers({ [IDENTITY_HEADERS.email]: "   " }))).toBeNull();
  });

  it("reports an absent issued-at as null, not the epoch", () => {
    // Number("") is 0, which would read as 1970-01-01.
    const identity = identityFrom(new Headers({ [IDENTITY_HEADERS.email]: "alice@cru.org" }));

    expect(identity).toEqual({ email: "alice@cru.org", name: null, issuedAt: null });
  });

  it("reports a non-numeric issued-at as null", () => {
    const identity = identityFrom(
      new Headers({
        [IDENTITY_HEADERS.email]: "alice@cru.org",
        [IDENTITY_HEADERS.issuedAt]: "yesterday",
      }),
    );

    expect(identity?.issuedAt).toBeNull();
  });

  it("reads any HeaderSource, like the rest of the package", () => {
    const request = new Request("https://bills.cru.org/", {
      headers: { [IDENTITY_HEADERS.email]: "alice@cru.org" },
    });

    expect(identityFrom(request)?.email).toBe("alice@cru.org");
    expect(identityFrom({ "X-Cru-IAP-Email": "alice@cru.org" })?.email).toBe("alice@cru.org");
  });
});
