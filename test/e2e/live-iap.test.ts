import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { HEADER, verify, verifyRequest } from "../../src/index.js";
import { Keypair } from "../support/iap-jwt.js";
import { loadCapture } from "../support/capture.js";

/**
 * End-to-end against LIVE Google infrastructure.
 *
 * Nothing here is stubbed. A real Okta sign-in federates through a real
 * workforce identity pool into a real IAP-fronted Cloud Run service, and the
 * assertion Google actually injected is fed to the verifier — which fetches
 * Google's real JWKS over the real network to check the real signature.
 *
 * This is the only kind of test that can answer the question the offline suite
 * cannot: *does a correctly configured workforce pool emit an `email` claim,
 * and does this library accept the token Google actually mints?*
 *
 * The capture itself is NOT driven from here. `e2e/okta/capture_assertion.mjs
 * --json` writes one artifact and the Ruby, Python, Go and TypeScript suites
 * all verify against it — see test/support/capture.ts for why. Run the whole
 * set with `e2e/run_all.sh`, or this suite alone with `npm run test:e2e` once
 * an artifact exists.
 *
 * Two things deliberately live elsewhere rather than being duplicated here:
 *
 *   - "is IAP actually in front of the host" → `node e2e/smoke.mjs iap-front`,
 *     which is language-agnostic and needs no capture. Keeping it there is
 *     also what stops the expected pool/provider id from being hardcoded in
 *     four test files, where it would rot the day the stack moves.
 *   - "does Google's key endpoint serve ES256/P-256" → `node e2e/smoke.mjs
 *     jwks`, wired into CI on every PR. The library's own constant is pinned
 *     offline in test/unit/remote-jwks.test.ts.
 */

const loaded = loadCapture();
const skipReason = typeof loaded === "string" ? loaded : null;

describe.skipIf(skipReason !== null)("live IAP", () => {
  // Non-null by construction inside this block; the skipIf above guarantees it.
  const { assertion, claims: liveClaims, audience, expectedEmail } = loaded as Exclude<
    typeof loaded,
    string
  >;

  describe("the real assertion", () => {
    it("was minted by Google minutes ago, not replayed from a fixture", () => {
      // Guards the whole file: every assertion below is only meaningful if the
      // capture really drove a live sign-in. A stale or hand-copied token
      // fails here rather than silently making the rest of the suite a
      // re-test of the offline fixtures.
      const age = Math.floor(Date.now() / 1000) - Number(liveClaims["iat"]);

      expect(age).toBeGreaterThanOrEqual(0);
      expect(age, "assertion is stale — did the capture actually run?").toBeLessThan(600);
      expect(Number(liveClaims["exp"])).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    it("verifies against Google's live JWKS and yields the signed-in identity", async () => {
      // No `jwks` option: this goes over the wire to
      // https://www.gstatic.com/iap/verify/public_key-jwk and checks the
      // signature Google produced with a key we have never seen.
      const result = await verify(assertion, { audience });

      expect(result).toMatchObject({
        ok: true,
        reason: "iap_jwt",
        email: expectedEmail,
      });
    });

    it("verifies straight off a request carrying the header, as an app would", async () => {
      const request = new Request("https://example.invalid/", {
        headers: { [HEADER]: assertion },
      });

      const result = await verifyRequest(request, { audience });

      expect(result.ok).toBe(true);
      expect(result.email).toBe(expectedEmail);
    });

    it("has no name claim, so display names must fall back to the local part", async () => {
      const result = await verify(assertion, { audience });

      expect(result.name).toBeNull();
    });
  });

  describe("the pass is not vacuous", () => {
    // Each of these takes the SAME genuine token and breaks exactly one thing.
    // Without them, "it verified" could mean the verifier accepts anything.

    it("rejects the genuine token once its payload is edited", async () => {
      const [header, payload, signature] = assertion.split(".");
      const claims = JSON.parse(Buffer.from(payload!, "base64url").toString());
      claims.email = "attacker@evil.example";
      const forged = [
        header,
        Buffer.from(JSON.stringify(claims)).toString("base64url"),
        signature,
      ].join(".");

      const result = await verify(forged, { audience });

      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/^signature_error:/);
      expect(result.email).toBeNull();
    });

    it("rejects the genuine token against a different backend service", async () => {
      // Same project, different backend-service id: the shape is right and
      // only the value is wrong, which is the realistic misconfiguration.
      const otherAudience = audience.replace(/\d+$/, "1111111111111111111");
      expect(otherAudience).not.toBe(audience);

      const result = await verify(assertion, { audience: otherAudience });

      expect(result).toMatchObject({ ok: false, reason: "audience_mismatch" });
    });

    it("rejects the genuine token when no audience is configured", async () => {
      const result = await verify(assertion, { audience: "" });

      expect(result).toMatchObject({ ok: false, reason: "missing_audience_config" });
    });

    it("rejects the same claims re-signed by a key of our own", async () => {
      // Proof that the JWKS fetch is load-bearing: identical payload, valid
      // ES256 signature, key Google never published.
      const ours = await Keypair.generate("not-googles-key");
      const forged = await ours.sign({
        ...liveClaims,
        iat: Math.floor(Date.now() / 1000) - 30,
        exp: Math.floor(Date.now() / 1000) + 600,
      });

      const result = await verify(forged, { audience });

      expect(result).toMatchObject({ ok: false, reason: "signature_error:no_matching_key" });
    });
  });

  describe("the claim shape production actually emits", () => {
    it("puts a bare address in email — no namespace prefix", () => {
      expect(liveClaims["email"]).toBe(expectedEmail);
      expect(String(liveClaims["email"])).not.toContain(":");
    });

    it("puts an opaque STS token in sub, which is not an identity", () => {
      expect(String(liveClaims["sub"])).toMatch(/^sts\.google\.com:/);
      expect(String(liveClaims["sub"])).not.toContain("@");
    });

    it("puts principal:// in the nested workforce_identity claim, not in sub or email", () => {
      const workforce = liveClaims["workforce_identity"] as { iam_principal?: string };

      expect(workforce.iam_principal).toMatch(/^principal:\/\/iam\.googleapis\.com\//);
      expect(String(liveClaims["sub"])).not.toContain("principal://");
      expect(String(liveClaims["email"])).not.toContain("principal://");
    });

    it("still matches the pinned capture, claim for claim", () => {
      // Drift detector against production Google. If this fails, the offline
      // suites in ALL FOUR languages are modelling a shape that no longer
      // exists — re-capture and update spec/fixtures/real_wif_iap_payload.json.
      const pinned = JSON.parse(
        readFileSync(new URL("../../spec/fixtures/real_wif_iap_payload.json", import.meta.url), "utf8"),
      ) as { claims: Record<string, unknown> };

      expect(Object.keys(liveClaims).sort()).toEqual(Object.keys(pinned.claims).sort());
    });
  });
});

if (skipReason !== null) {
  describe("live IAP e2e", () => {
    it.skip(`skipped: ${skipReason}`, () => {});
  });
}
