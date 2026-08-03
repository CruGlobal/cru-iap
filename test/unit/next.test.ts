import { NextRequest, NextResponse } from "next/server";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { DEV_BYPASS_EMAIL_VAR, DEV_BYPASS_NAME_VAR, HEADER, isKnownReason } from "../../src/index.js";
import { IDENTITY_HEADERS } from "../../src/identity-headers.js";
import { createIapProxy, type IapProxyOptions } from "../../src/next.js";
import { AUDIENCE, iapToken, localJwks, signingKey } from "../support/iap-jwt.js";

/**
 * The gate is mostly a composition of primitives that are tested elsewhere, so
 * what this file pins is the two things composition gets wrong: the ORDER of the
 * strip relative to the public-path early return, and what a rejection is
 * allowed to forward.
 */

let jwks: Awaited<ReturnType<typeof localJwks>>;

beforeAll(async () => {
  jwks = await localJwks(await signingKey());
});

const silent = { warn: () => {} };

/** No IAP_AUDIENCE and no bypass unless a test asks for them. */
const proxy = (options: IapProxyOptions = {}) =>
  createIapProxy({ logger: silent, env: {}, jwks, ...options });

const request = (path: string, headers: Record<string, string> = {}) =>
  new NextRequest(`https://bills.cru.org${path}`, { headers });

const spoofed = {
  [IDENTITY_HEADERS.email]: "admin@cru.org",
  [IDENTITY_HEADERS.name]: "An Admin",
  [IDENTITY_HEADERS.issuedAt]: "1",
};

/**
 * The request headers Next will actually forward. `NextResponse.next({ request:
 * { headers } })` mutates nothing — it encodes the REPLACEMENT set into
 * `x-middleware-override-headers` / `x-middleware-request-*`, and Next swaps the
 * downstream request headers for exactly that set. So this, not the inbound
 * request, is where a strip either happened or didn't.
 */
function forwarded(response: NextResponse): Headers {
  const names = (response.headers.get("x-middleware-override-headers") ?? "")
    .split(",")
    .filter((name) => name !== "");
  const headers = new Headers();
  for (const name of names) {
    headers.set(name, response.headers.get(`x-middleware-request-${name}`) ?? "");
  }
  return headers;
}

describe("createIapProxy: stripping inbound identity headers", () => {
  it("strips them on a PUBLIC path", async () => {
    // The ordering bug this exists to prevent: strip after the early return and
    // `curl -H 'x-cru-iap-email: admin@cru.org' /health` becomes an admin to
    // every downstream reader.
    const response = await proxy({ publicPrefixes: ["/health"] })(request("/health", spoofed));

    expect(response.status).toBe(200);
    expect([...forwarded(response).keys()]).toEqual([]);
  });

  it("strips them on a gated path that verifies", async () => {
    const response = await proxy({ audience: AUDIENCE })(
      request("/", { ...spoofed, [HEADER]: await iapToken() }),
    );

    expect(forwarded(response).get(IDENTITY_HEADERS.email)).toBe("alice@cru.org");
    expect(forwarded(response).get(IDENTITY_HEADERS.name)).toBe("Alice A");
  });

  it("forwards nothing at all when the request is rejected", async () => {
    const response = await proxy({ audience: AUDIENCE })(request("/", spoofed));

    expect(response.status).toBe(401);
    expect(response.headers.has("x-middleware-override-headers")).toBe(false);
    expect([...forwarded(response).keys()]).toEqual([]);
  });
});

describe("createIapProxy: publicPrefixes", () => {
  const gate = proxy({ publicPrefixes: ["/about", "/api/"] });

  it.each(["/about", "/about/x", "/api/", "/api/ping"])("passes %s anonymously", async (path) => {
    expect((await gate(request(path))).status).toBe(200);
  });

  it.each(["/", "/apiary", "/abo", "/x/about"])("gates %s", async (path) => {
    // "/api/" carries its trailing slash precisely so /apiary does not ride
    // along on a bare "/api" prefix.
    expect((await gate(request(path))).status).toBe(401);
  });

  it("gates everything when no prefixes are given", async () => {
    expect((await proxy()(request("/health"))).status).toBe(401);
  });
});

describe("createIapProxy: verified requests", () => {
  it("stamps all three headers, issued-at from the assertion's iat", async () => {
    const now = Math.floor(Date.now() / 1000);
    const response = await proxy({ audience: AUDIENCE })(
      request("/", { [HEADER]: await iapToken({ now }) }),
    );

    expect(Object.fromEntries(forwarded(response))).toEqual({
      [HEADER]: expect.any(String),
      [IDENTITY_HEADERS.email]: "alice@cru.org",
      [IDENTITY_HEADERS.name]: "Alice A",
      [IDENTITY_HEADERS.issuedAt]: String(now - 30),
    });
  });

  it("omits the name header when the assertion carries no name claim", async () => {
    const response = await proxy({ audience: AUDIENCE })(
      request("/", { [HEADER]: await iapToken({ name: null }) }),
    );

    expect(forwarded(response).has(IDENTITY_HEADERS.name)).toBe(false);
  });
});

describe("createIapProxy: the dev bypass", () => {
  it("stamps an identity with no issued-at", async () => {
    const response = await proxy({ env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" } })(request("/"));

    expect(Object.fromEntries(forwarded(response))).toEqual({
      [IDENTITY_HEADERS.email]: "dev@cru.org",
    });
  });

  it("carries the optional display name", async () => {
    const response = await proxy({
      env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org", [DEV_BYPASS_NAME_VAR]: "A Developer" },
    })(request("/"));

    expect(forwarded(response).get(IDENTITY_HEADERS.name)).toBe("A Developer");
  });

  it("loses to verification once its own guards refuse", async () => {
    const response = await proxy({
      env: {
        [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org",
        IAP_AUDIENCE: AUDIENCE,
        K_SERVICE: "bills",
      },
    })(request("/", { [HEADER]: await iapToken() }));

    expect(forwarded(response).get(IDENTITY_HEADERS.email)).toBe("alice@cru.org");
  });

  it("is unreachable when the audience is configured in code rather than the env", async () => {
    // Guard 1 reads IAP_AUDIENCE; `createIapProxy({ audience })` must arm it
    // just the same, or configuring the package properly would open the bypass.
    const response = await proxy({
      audience: AUDIENCE,
      env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" },
    })(request("/"));

    expect(response.status).toBe(401);
  });
});

describe("createIapProxy: rejections", () => {
  it("fails closed with nothing configured at all", async () => {
    // No assertion, no bypass, no audience. cru-web-campaign opened the gate
    // here; this is the whole reason the factory exists.
    expect((await proxy()(request("/"))).status).toBe(401);
  });

  it("answers 401, never a redirect", async () => {
    // IAP owns sign-in and has already run, so bouncing the browser just loops.
    const response = await proxy({ audience: AUDIENCE })(request("/"));

    expect(response.status).toBe(401);
    expect(response.headers.has("location")).toBe(false);
    expect(await response.text()).toBe("Unauthorized");
  });

  it("hints at the dev bypass when no audience is configured", async () => {
    const body = await (await proxy()(request("/"))).text();

    expect(body).toContain(DEV_BYPASS_EMAIL_VAR);
  });

  it("logs one line of structured JSON", async () => {
    const logger = { warn: vi.fn() };

    await proxy({ audience: AUDIENCE, logger })(request("/private", { [HEADER]: "not-a-jwt" }));

    const logged = logger.warn.mock.calls
      .map((call) => String(call[0]))
      .filter((line) => line.includes("iap_rejected"));
    expect(logged).toHaveLength(1);
    expect(JSON.parse(logged[0]!)).toEqual({
      severity: "WARNING",
      message: "iap_rejected",
      reason: expect.stringMatching(/./),
      path: "/private",
    });
  });

  it("reports a reason from the cross-language vocabulary", async () => {
    const logger = { warn: vi.fn() };

    await proxy({ audience: AUDIENCE, logger })(request("/"));

    const line = logger.warn.mock.calls
      .map((call) => String(call[0]))
      .find((call) => call.includes("iap_rejected"));
    expect(isKnownReason((JSON.parse(line!) as { reason: string }).reason)).toBe(true);
  });
});
