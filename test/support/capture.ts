import { existsSync, readFileSync } from "node:fs";

/**
 * Loader for the shared live-capture artifact that all four language e2e
 * suites verify against.
 *
 * One browser login, four verifications. Each suite driving its own capture
 * would be ~12 minutes of real Okta/SAML/IAP round-trips and four independent
 * chances to flake, for no extra coverage — the interesting question is
 * "does THIS library accept the token Google actually minted", and one token
 * answers it four times.
 *
 * Written by `node e2e/okta/capture_assertion.mjs --json`. Contract documented
 * in e2e/README.md; the Ruby, Python and Go loaders read the same file and
 * apply the same staleness rule.
 *
 * Nothing infrastructure-specific is hardcoded here. The audience and expected
 * email resolve from the environment or the artifact and otherwise cause a
 * skip — so moving the e2e stack to another project does not touch test code.
 */

export interface Capture {
  captured_at: number;
  url: string;
  assertion: string;
  claims: Record<string, unknown>;
  audience: string | null;
  expected_email: string | null;
}

export interface LoadedCapture {
  capture: Capture;
  assertion: string;
  claims: Record<string, unknown>;
  audience: string;
  expectedEmail: string;
}

/** Refuse a capture that is within this many seconds of expiry. */
const EXPIRY_MARGIN_SECONDS = 30;

export const capturePath = (): string =>
  process.env["CRU_IAP_E2E_CAPTURE"] ??
  new URL("../../e2e/okta/capture.json", import.meta.url).pathname;

/**
 * Returns the loaded capture, or a string explaining why the suite must skip.
 * Never throws: a missing stack is a skip, not a failure — except under CI,
 * where see the note in each suite about inverting that.
 */
export const loadCapture = (): LoadedCapture | string => {
  const path = capturePath();
  if (!existsSync(path)) {
    return `no capture at ${path} — run: node e2e/okta/capture_assertion.mjs --json`;
  }

  let capture: Capture;
  try {
    capture = JSON.parse(readFileSync(path, "utf8")) as Capture;
  } catch (error) {
    return `capture at ${path} is not readable JSON: ${(error as Error).message}`;
  }

  if (!capture.assertion || !capture.claims) {
    return `capture at ${path} has no assertion/claims — was it written by an older capture script?`;
  }

  // Assertions live ~600s. Keying the staleness gate on `exp` rather than on
  // captured_at is the honest check: exp is what actually decides whether a
  // verify can succeed, and it comes from Google rather than from our clock.
  const exp = Number(capture.claims["exp"]);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(exp)) {
    return `capture at ${path} has no numeric exp claim`;
  }
  if (exp <= now + EXPIRY_MARGIN_SECONDS) {
    const age = now - exp;
    return `capture at ${path} expired ${age}s ago — re-run the capture`;
  }

  // Audience is configuration, never read off the token: taking it from the
  // `aud` claim would turn the positive verify into "does aud equal aud".
  const audience = process.env["CRU_IAP_E2E_AUDIENCE"] ?? capture.audience;
  if (!audience) {
    return (
      "no audience: set CRU_IAP_E2E_AUDIENCE or capture with " +
      "--audience \"$(terraform output -raw iap_audience)\""
    );
  }

  const expectedEmail = process.env["CRU_IAP_E2E_EMAIL"] ?? capture.expected_email;
  if (!expectedEmail) {
    return "no expected email: set CRU_IAP_E2E_EMAIL or re-run the capture script";
  }

  return {
    capture,
    assertion: capture.assertion,
    claims: capture.claims,
    audience,
    expectedEmail,
  };
};
