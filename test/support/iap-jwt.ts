import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from "jose";
import type { JWTVerifyGetKey } from "jose";

/**
 * Mints REAL, REALLY-SIGNED IAP assertion JWTs and serves the matching JWKS,
 * so the verifier runs its actual signature/aud/exp/iss checks. Nothing is
 * stubbed at the jose API boundary.
 *
 * TypeScript sibling of spec/support/iap_jwt.rb — the claim builders below are
 * kept claim-for-claim identical to the Ruby ones on purpose, so a change to
 * either language's understanding of the payload shape shows up as a diff.
 *
 * Two key-source seams, used for different things:
 *
 *   * `localJwks()` — a `createLocalJWKSet` over our generated public keys.
 *     Real JWK parsing, real ES256 verification, no network at all. This is
 *     what nearly every unit test wants.
 *
 *   * `stubbedRemoteJwks()` — a genuine `createRemoteJWKSet` over the real
 *     gstatic URL, with `fetch` stubbed. Keeps the HTTP key source and its
 *     caching in the blast radius, since that layer is precisely what produces
 *     `verification_error:KeySourceError` in production.
 */

export const AUDIENCE = "/projects/178891842216/global/backendServices/9876543210";
export const IAP_ISSUER = "https://cloud.google.com/iap";

/**
 * Real IAP signs with ES256 / P-256 and publishes EC JWKs, so that is what we
 * mint rather than the RSA keys a generic JWT fixture would reach for.
 */
export class Keypair {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicJwk: JWK;

  private constructor(kid: string, privateKey: CryptoKey, publicJwk: JWK) {
    this.kid = kid;
    this.privateKey = privateKey;
    this.publicJwk = publicJwk;
  }

  static async generate(kid: string): Promise<Keypair> {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = await exportJWK(publicKey);
    return new Keypair(kid, privateKey, { ...jwk, alg: "ES256", use: "sig", kid });
  }

  sign(claims: Record<string, unknown>): Promise<string> {
    // setProtectedHeader only — every temporal claim comes from the claim
    // builders, so a test can place a token precisely in time.
    return new SignJWT(claims as Record<string, unknown>)
      .setProtectedHeader({ alg: "ES256", kid: this.kid })
      .sign(this.privateKey);
  }
}

let signing: Keypair | undefined;
let rogue: Keypair | undefined;

/** The keypair whose public half we publish as the IAP JWKS. */
export async function signingKey(): Promise<Keypair> {
  signing ??= await Keypair.generate("cru-iap-test-signing");
  return signing;
}

/** A keypair that is NOT in the published JWKS — for the wrong-signer case. */
export async function rogueKey(): Promise<Keypair> {
  rogue ??= await Keypair.generate("rogue-not-in-jwks");
  return rogue;
}

export async function jwks(...keypairs: Keypair[]): Promise<{ keys: JWK[] }> {
  const keys = keypairs.length > 0 ? keypairs : [await signingKey()];
  return { keys: keys.map((k) => k.publicJwk) };
}

/** In-process key set. No network. */
export async function localJwks(...keypairs: Keypair[]): Promise<JWTVerifyGetKey> {
  return createLocalJWKSet(await jwks(...keypairs));
}

export interface ClaimOverrides {
  [claim: string]: unknown;
}

/**
 * A PLAIN-IAP claim set (Google/Cloud Identity account, no federation).
 *
 * Set a claim to `null` to OMIT it entirely — a broken workforce pool sends a
 * JWT with no "email" key at all, not an empty one, and the two are not the
 * same input to the verifier. (Ruby uses nil + .compact for the same effect.)
 *
 * Times are computed from a caller-supplied `now` so nothing depends on how
 * long the suite takes to run.
 */
export function iapClaims(
  overrides: ClaimOverrides & { now?: number } = {},
): Record<string, unknown> {
  const { now = Math.floor(Date.now() / 1000), ...rest } = overrides;
  return compact({
    iss: IAP_ISSUER,
    aud: AUDIENCE,
    // Real IAP JWTs carry azp equal to aud. Present here so the synthetic
    // payload matches a live capture claim-for-claim — see the drift check in
    // test/unit/claim-shapes.test.ts.
    azp: AUDIENCE,
    iat: now - 30,
    exp: now + 600,
    // Opaque and namespaced. Never an identity in any IAP mode.
    sub: "accounts.google.com:104291823410293841029",
    email: "alice@cru.org",
    name: "Alice A",
    hd: "cru.org",
    ...rest,
  });
}

/**
 * A WORKFORCE IDENTITY FEDERATION claim set, in the shape confirmed 2026-07-24
 * against a captured live payload. Two things matter and are easy to get wrong
 * from memory:
 *
 *   * `sub` is "sts.google.com:<opaque STS token>" — NOT a principal:// URI,
 *     and not recoverable into an address.
 *   * the principal:// URI is real but lives in the nested
 *     `workforce_identity.iam_principal` claim, which is what IAM bindings
 *     match. The verifier must ignore it.
 *
 * Pass `email: null` for the "google.email attribute mapping absent" pool —
 * the claim disappears entirely, which is the whole failure mode.
 */
export function wifClaims(
  overrides: ClaimOverrides & { now?: number; pool?: string } = {},
): Record<string, unknown> {
  const { pool = "cru-okta-stage", ...rest } = overrides;
  const email = "email" in rest ? rest["email"] : "alice@cru.org";
  const subject = typeof email === "string" ? email : "okta-user-9f31c0";
  return iapClaims({
    email,
    sub: "sts.google.com:AAFTZtsl9PtVMy-6qd9Otvue3S1_9YyBfNyG0oX3xQdR7kKmMv",
    identity_source: "WORKFORCE_IDENTITY",
    workforce_identity: {
      iam_principal: `principal://iam.googleapis.com/locations/global/workforcePools/${pool}/subject/${subject}`,
      workforce_pool_name: `locations/global/workforcePools/${pool}`,
    },
    ...rest,
  });
}

/** Mint a signed assertion with the key that IS in the published JWKS. */
export async function iapToken(
  overrides: ClaimOverrides & { now?: number; key?: Keypair } = {},
): Promise<string> {
  const { key, ...claims } = overrides;
  return (key ?? (await signingKey())).sign(iapClaims(claims));
}

export async function wifToken(
  overrides: ClaimOverrides & { now?: number; pool?: string; key?: Keypair } = {},
): Promise<string> {
  const { key, ...claims } = overrides;
  return (key ?? (await signingKey())).sign(wifClaims(claims));
}

/** Drop keys explicitly set to null, so "omitted" and "empty" stay distinct. */
function compact(claims: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(claims).filter(([, v]) => v !== null));
}
