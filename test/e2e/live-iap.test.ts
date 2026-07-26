import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

import { HEADER, IAP_JWKS_URL, verify, verifyRequest } from "../../src/index.js";
import { Keypair } from "../support/iap-jwt.js";

/**
 * End-to-end against LIVE Google infrastructure.
 *
 * Nothing here is stubbed. A real Okta sign-in federates through a real
 * workforce identity pool into a real IAP-fronted Cloud Run service, and the
 * assertion Google actually injected is fed to the verifier — which fetches
 * Google's real JWKS over the real network to check the real signature.
 *
 * This is the only test that can answer the question the offline suite cannot:
 * *does a correctly configured workforce pool emit an `email` claim, and does
 * this library accept the token Google actually mints?*
 *
 * Requirements (all provisioned by e2e/terraform + e2e/okta):
 *
 *   - the `wif` terraform workspace applied — see e2e/terraform/README.md
 *   - e2e/okta/secrets.json present (test-user password + TOTP secret)
 *   - `npm --prefix e2e/okta install` (Playwright + its chromium)
 *   - network egress to gstatic.com, the LB, and cru.oktapreview.com
 *
 * Run with `npm run test:e2e`. Never runs under `npm test`, and skips itself
 * with a reason rather than failing when the stack is down.
 */

const repoRoot = new URL("../../", import.meta.url);
const oktaDir = fileURLToPath(new URL("e2e/okta/", repoRoot));

const LIVE_URL = process.env["CRU_IAP_E2E_URL"] ?? "https://cru-iap-wif.matt-sandbox.ustech.app/";
const LIVE_AUDIENCE =
  process.env["CRU_IAP_E2E_AUDIENCE"] ??
  "/projects/898330966415/global/backendServices/2605597618877293205";
const EXPECTED_EMAIL =
  process.env["CRU_IAP_E2E_EMAIL"] ?? "cru-iap-e2e-test@example.invalid";

/** Assertions are short-lived (~600s), so capture once and reuse across the file. */
let assertion: string;
let liveClaims: Record<string, unknown>;

const missingPrereq = (): string | null => {
  if (!existsSync(new URL("secrets.json", `file://${oktaDir}`))) {
    return "e2e/okta/secrets.json is absent — the Okta scratch setup has been torn down";
  }
  if (!existsSync(new URL("node_modules/playwright", `file://${oktaDir}`))) {
    return "playwright is not installed — run `npm --prefix e2e/okta install`";
  }
  return null;
};

const skipReason = missingPrereq();

describe.skipIf(skipReason !== null)(`live IAP at ${LIVE_URL}`, () => {
  beforeAll(() => {
    // The capture script drives a headless browser through Okta primary auth,
    // a TOTP challenge, the SAML leg, and the IAP callback. Several minutes of
    // real network in the worst case.
    const stdout = execFileSync(
      process.execPath,
      ["capture_assertion.mjs", "--url", `${LIVE_URL}?login=true`],
      { cwd: oktaDir, encoding: "utf8", timeout: 170_000 },
    );

    const match = stdout.match(/=== assertion ===\s*\n([A-Za-z0-9._-]+)/);
    if (!match?.[1]) throw new Error(`no assertion in capture output:\n${stdout}`);
    assertion = match[1];
    liveClaims = JSON.parse(
      Buffer.from(assertion.split(".")[1]!, "base64url").toString(),
    ) as Record<string, unknown>;
  }, 180_000);

  describe("the real assertion", () => {
    it("was minted by Google seconds ago, not replayed from a fixture", () => {
      // Guards the whole file: every assertion below is only meaningful if
      // the capture really drove a live sign-in. A stale or hand-copied token
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
      const result = await verify(assertion, { audience: LIVE_AUDIENCE });

      expect(result).toMatchObject({
        ok: true,
        reason: "iap_jwt",
        email: EXPECTED_EMAIL,
      });
    });

    it("verifies straight off a request carrying the header, as an app would", async () => {
      const request = new Request(LIVE_URL, { headers: { [HEADER]: assertion } });

      const result = await verifyRequest(request, { audience: LIVE_AUDIENCE });

      expect(result.ok).toBe(true);
      expect(result.email).toBe(EXPECTED_EMAIL);
    });

    it("has no name claim, so display names must fall back to the local part", async () => {
      const result = await verify(assertion, { audience: LIVE_AUDIENCE });

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

      const result = await verify(forged, { audience: LIVE_AUDIENCE });

      expect(result.ok).toBe(false);
      expect(result.reason).toMatch(/^signature_error:/);
      expect(result.email).toBeNull();
    });

    it("rejects the genuine token against a different backend service", async () => {
      const result = await verify(assertion, {
        audience: "/projects/898330966415/global/backendServices/1111111111111111111",
      });

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

      const result = await verify(forged, { audience: LIVE_AUDIENCE });

      expect(result).toMatchObject({ ok: false, reason: "signature_error:no_matching_key" });
    });
  });

  describe("the claim shape production actually emits", () => {
    it("puts a bare address in email — no namespace prefix", () => {
      expect(liveClaims["email"]).toBe(EXPECTED_EMAIL);
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
      // suites in BOTH languages are modelling a shape that no longer exists
      // — re-capture and update spec/fixtures/real_wif_iap_payload.json.
      const pinned = JSON.parse(
        readFileSync(new URL("spec/fixtures/real_wif_iap_payload.json", repoRoot), "utf8"),
      ) as { claims: Record<string, unknown> };

      expect(Object.keys(liveClaims).sort()).toEqual(Object.keys(pinned.claims).sort());
    });
  });

  describe("IAP itself is in front of the app", () => {
    it("ignores a client-supplied assertion header and challenges anyway", async () => {
      // The forged header never reaches the backend: IAP strips and replaces
      // it. Without this, an app could be behind a load balancer that merely
      // forwards whatever the client sent.
      const response = await fetch(`${LIVE_URL}?login=true`, {
        headers: { [HEADER]: assertion },
        redirect: "manual",
      });

      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toContain("auth.cloud.google/authorize");
    });

    it("hands off to the Okta workforce provider, not Google identity", async () => {
      const response = await fetch(`${LIVE_URL}?login=true`, { redirect: "manual" });

      expect(response.headers.get("location")).toContain("workforcePools/keepzero-okta-poc");
    });
  });

  describe("Google's key endpoint", () => {
    it("serves the JWK set the verifier expects at the -jwk URL", async () => {
      const response = await fetch(IAP_JWKS_URL);
      const body = (await response.json()) as { keys: { kty: string; crv: string }[] };

      expect(response.status).toBe(200);
      expect(body.keys.length).toBeGreaterThan(0);
      // ES256 / P-256, which is why the offline fixtures mint EC keys rather
      // than the RSA a generic JWT fixture would reach for.
      expect(body.keys.every((k) => k.kty === "EC" && k.crv === "P-256")).toBe(true);
    });
  });
});

if (skipReason !== null) {
  describe("live IAP e2e", () => {
    it.skip(`skipped: ${skipReason}`, () => {});
  });
}
