import { createRemoteJWKSet } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { IAP_JWKS_URL, resetJwksCache, verify } from "../../src/index.js";
import { AUDIENCE, iapToken, rogueKey, signingKey, type Keypair } from "../support/iap-jwt.js";
import { stubIapJwks, type JwksStub } from "../support/remote-jwks.js";

/**
 * These exercise the REAL `createRemoteJWKSet` — its fetch, its cache, its
 * rotation handling, and its failure modes — with only the network hop faked.
 * That layer is what produces `verification_error:KeySourceError` in
 * production, so it stays inside the tests' blast radius rather than being
 * short-circuited by `createLocalJWKSet` everywhere.
 */

let good: Keypair;
let rogue: Keypair;
let stub: JwksStub;

beforeAll(async () => {
  good = await signingKey();
  rogue = await rogueKey();
});

afterEach(() => {
  stub?.restore();
  resetJwksCache();
});

/** A fresh remote key set per test, so one test's cache can't serve another. */
function remote() {
  return createRemoteJWKSet(new URL(IAP_JWKS_URL), { cooldownDuration: 0 });
}

describe("the remote IAP key set", () => {
  it("fetches Google's JWKS and verifies against it", async () => {
    stub = await stubIapJwks(good);

    const result = await verify(await iapToken(), { audience: AUDIENCE, jwks: remote() });

    expect(result).toMatchObject({ ok: true, email: "alice@cru.org" });
    expect(stub.calls()).toBe(1);
  });

  it("caches the keys rather than re-fetching per request", async () => {
    // The reason this package uses jose over google-auth-library, whose
    // getIapPublicKeys has no cache at all: without this, every authenticated
    // request would carry a gstatic.com round-trip.
    stub = await stubIapJwks(good);
    const jwks = remote();

    for (let i = 0; i < 5; i += 1) {
      const result = await verify(await iapToken(), { audience: AUDIENCE, jwks });
      expect(result.ok).toBe(true);
    }

    expect(stub.calls()).toBe(1);
  });

  it("picks up a rotated key without a restart", async () => {
    stub = await stubIapJwks(good);
    const jwks = remote();

    expect((await verify(await iapToken(), { audience: AUDIENCE, jwks })).ok).toBe(true);

    // Google rotates: the old key is withdrawn and a new one published. The
    // token now arrives with an unseen kid, which forces a re-fetch.
    await stub.publish(rogue);
    const rotated = await verify(await iapToken({ key: rogue }), { audience: AUDIENCE, jwks });

    expect(rotated.ok).toBe(true);
    expect(stub.calls()).toBe(2);
  });

  it("rejects rather than crashing when the JWKS endpoint errors", async () => {
    stub = await stubIapJwks(good);
    stub.fail(503);

    const result = await verify(await iapToken(), { audience: AUDIENCE, jwks: remote() });

    expect(result).toMatchObject({ ok: false, reason: "verification_error:KeySourceError" });
  });

  it("rejects rather than crashing when the fetch itself fails", async () => {
    stub = await stubIapJwks(good);
    stub.failTransport();

    const result = await verify(await iapToken(), { audience: AUDIENCE, jwks: remote() });

    // A DNS/connect failure surfaces as a bare TypeError, not a JOSEError —
    // jose passes transport errors through untouched.
    expect(result).toMatchObject({ ok: false, reason: "verification_error:KeySourceError" });
  });

  it("does not fetch anything before the first verification", async () => {
    // Importing this package must not fire a network request, and neither
    // must constructing the key set — bundlers evaluate modules at build time.
    stub = await stubIapJwks(good);
    remote();

    expect(stub.calls()).toBe(0);
  });

  it("does not reach the network when the token is structurally rejected first", async () => {
    stub = await stubIapJwks(good);

    await verify("", { audience: AUDIENCE, jwks: remote() });
    await verify(await iapToken(), { audience: "", jwks: remote() });

    expect(stub.calls()).toBe(0);
  });

  it("targets the -jwk endpoint, not the PEM one google-auth-library uses", () => {
    expect(IAP_JWKS_URL).toBe("https://www.gstatic.com/iap/verify/public_key-jwk");
  });
});
