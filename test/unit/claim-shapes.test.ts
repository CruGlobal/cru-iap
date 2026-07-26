import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";

import { verify } from "../../src/index.js";
import {
  AUDIENCE,
  iapClaims,
  localJwks,
  signingKey,
  wifClaims,
  wifToken,
  type Keypair,
} from "../support/iap-jwt.js";

/**
 * The claim shapes IAP actually emits, each as a really-signed token.
 *
 * The contents here mirror spec/integration/claim_shapes_spec.rb example for
 * example. Both suites are anchored to the same pinned capture of a real
 * Google assertion, so if the two languages ever disagree about what IAP
 * sends, one of them goes red.
 */

let jwks: Awaited<ReturnType<typeof localJwks>>;
let key: Keypair;

beforeAll(async () => {
  key = await signingKey();
  jwks = await localJwks(key);
});

const run = (token: string) => verify(token, { audience: AUDIENCE, jwks });

describe("plain IAP (Google / Cloud Identity session)", () => {
  it("takes identity from the bare email claim", async () => {
    const result = await run(await key.sign(iapClaims()));

    expect(result).toMatchObject({ ok: true, email: "alice@cru.org" });
  });

  it("ignores the opaque accounts.google.com sub", async () => {
    const result = await run(
      await key.sign(iapClaims({ sub: "accounts.google.com:104291823410293841029" })),
    );

    expect(result.ok).toBe(true);
    expect(result.email).toBe("alice@cru.org");
  });

  it("rejects with missing_email when there is no email claim, however good sub looks", async () => {
    const result = await run(await key.sign(iapClaims({ email: null })));

    expect(result).toMatchObject({ ok: false, reason: "missing_email" });
  });
});

describe("workforce identity federation", () => {
  it("accepts a fully realistic WIF payload and takes identity from email", async () => {
    const result = await run(await wifToken());

    expect(result).toMatchObject({ ok: true, email: "alice@cru.org" });
    expect(result.payload).toMatchObject({ identity_source: "WORKFORCE_IDENTITY" });
  });

  it("ignores the nested iam_principal even when it names a different address", async () => {
    const claims = wifClaims();
    (claims["workforce_identity"] as Record<string, string>)["iam_principal"] =
      "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/someone-else@cru.org";

    const result = await run(await key.sign(claims));

    expect(result.email).toBe("alice@cru.org");
  });

  it("rejects an unmapped pool as missing_email, not malformed_subject", async () => {
    // A pool whose provider lacks `google.email` in its attribute_mapping.
    // The remedy is in terraform, and only `missing_email` names it.
    const result = await run(await wifToken({ email: null }));

    expect(result).toMatchObject({ ok: false, reason: "missing_email" });
  });

  it("does not recover an address from the principal URI in the unmapped case", async () => {
    // The nested principal carries a perfectly good subject. Unwrapping it
    // would be accepting a value IAP never offered as an identity claim.
    const claims = wifClaims({ email: null });
    const principal = (claims["workforce_identity"] as Record<string, string>)["iam_principal"];

    expect(principal).toContain("okta-user-9f31c0");
    expect((await run(await key.sign(claims))).email).toBeNull();
  });
});

describe("the pinned real capture", () => {
  // Ground truth: verbatim claims from a live Google IAP assertion, captured
  // 2026-07-25 through a headless Okta sign-in. See the fixture's _provenance.
  const fixture = JSON.parse(
    readFileSync(new URL("../../spec/fixtures/real_wif_iap_payload.json", import.meta.url), "utf8"),
  ) as { claims: Record<string, unknown> };

  /** Re-time and re-audience, since the captured pair expired 600s after capture. */
  function replay(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1000);
    return { ...fixture.claims, iat: now - 30, exp: now + 600, aud: AUDIENCE, ...overrides };
  }

  it("verifies when re-signed, and takes identity from email", async () => {
    const result = await run(await key.sign(replay()));

    expect(result).toMatchObject({
      ok: true,
      reason: "iap_jwt",
      email: "cru-iap-e2e-test@example.invalid",
      // The real WIF payload carries no name claim at all — the email
      // local-part fallback is the production path, not the exception.
      name: null,
    });
  });

  it("still verifies with the nested workforce_identity claim removed", async () => {
    const claims = replay();
    delete claims["workforce_identity"];

    expect((await run(await key.sign(claims))).ok).toBe(true);
  });

  it("rejects the real payload with its email stripped, as missing_email", async () => {
    const claims = replay();
    delete claims["email"];

    expect(await run(await key.sign(claims))).toMatchObject({
      ok: false,
      reason: "missing_email",
    });
  });

  it("keeps the synthetic wifClaims helper faithful to the real claim set", async () => {
    // If Google adds or renames a top-level claim, this fails and the rest of
    // the suite stops silently testing a fiction. It earned its keep on the
    // Ruby side immediately by catching a missing `azp`.
    const synthetic = new Set(Object.keys(wifClaims()));
    const missing = Object.keys(fixture.claims).filter((claim) => !synthetic.has(claim));

    expect(missing, `real payload has claims the synthetic helper lacks: ${missing}`).toEqual([]);
  });

  it("agrees with the Ruby suite about what the real payload means", async () => {
    // Both languages read this same fixture and must reach the same verdict.
    // Stated as an explicit assertion rather than left implicit, because the
    // fixture is the only shared artefact between the two test suites.
    const result = await run(await key.sign(replay()));

    expect({ ok: result.ok, reason: result.reason, email: result.email, name: result.name }).toEqual(
      { ok: true, reason: "iap_jwt", email: "cru-iap-e2e-test@example.invalid", name: null },
    );
  });
});
