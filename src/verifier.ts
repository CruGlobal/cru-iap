import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";

import { isKnownReason, type ResultReason } from "./reasons.js";
import { assertionFrom, type HeaderSource } from "./request.js";

/**
 * Verifies the Google-signed JWT that Identity-Aware Proxy injects on every
 * request it lets through to a backend, and extracts an email identity.
 *
 * A direct port of `CruIap::TokenVerifier` (lib/cru_iap/token_verifier.rb).
 * The two implementations share a rejection vocabulary and every claim-shape
 * decision; keep them in step. The differences are deliberate and noted below:
 *
 *  - jose rather than google-auth-library. google-auth-library's
 *    `getIapPublicKeys` re-fetches Google's key set on EVERY call — no cache,
 *    unlike the Ruby googleauth's one-hour memoized key source — so using it
 *    per-request would put a gstatic.com round-trip in front of every
 *    authenticated request. It also throws bare `Error`s with prose messages,
 *    which would leave the reason vocabulary matched on substrings. And it is
 *    Node-only: `jose` is WebCrypto-based and runs in Next.js middleware on
 *    the Edge runtime, which is exactly where an IAP gate wants to live.
 *
 *  - async. WebCrypto verification is promise-based; there is no sync path.
 */

export const IAP_ISSUER = "https://cloud.google.com/iap";

/**
 * Google's IAP JWKS. Note the `-jwk` suffix: the bare
 * `.../iap/verify/public_key` endpoint serves a PEM map instead, which is what
 * google-auth-library consumes and is NOT parseable as a JWK set.
 */
export const IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";

/**
 * IAP signs with ES256. Pinning it means a future key set that also published
 * an RSA or HMAC key could not be used to talk us into a weaker verification.
 */
const IAP_ALGORITHMS = ["ES256"];

/**
 * URI::MailTo::EMAIL_REGEXP, ported character-for-character from Ruby so the
 * two verifiers accept and reject exactly the same strings.
 */
const EMAIL_REGEXP =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

/**
 * EMAIL_REGEXP alone is not a sufficient shape gate. RFC 5322 permits "/" in a
 * local part, so a URI-shaped value ending in an address — e.g.
 * "principal://iam.googleapis.com/.../subject/alice@cru.org" — MATCHES it, and
 * would be persisted as a user whose email is that entire string. No real Okta
 * or Google identity contains a slash or a backslash, so treat either as proof
 * we are looking at a URI or principal rather than an address.
 */
const NEVER_IN_AN_EMAIL = /[/\\]/;

export interface Logger {
  warn(message: string): void;
}

const NULL_LOGGER: Logger = { warn: () => {} };

export interface VerifyOptions {
  /**
   * Backend-service resource path. Defaults to `process.env.IAP_AUDIENCE`,
   * read at call time so a test can set it per-example.
   */
  audience?: string | undefined;
  /** Defaults to a null logger. */
  logger?: Logger | undefined;
  /**
   * Key source. Defaults to a module-level `createRemoteJWKSet` over
   * IAP_JWKS_URL, shared across calls so its cache is actually a cache.
   * Override in tests, or to point at a different key set.
   */
  jwks?: JWTVerifyGetKey | undefined;
  /** Leeway in seconds for exp/nbf. Defaults to jose's 0. */
  clockToleranceSeconds?: number | undefined;
}

export type VerifyResult =
  | {
      ok: true;
      reason: "iap_jwt";
      email: string;
      name: string | null;
      payload: JWTPayload;
    }
  | {
      ok: false;
      reason: ResultReason;
      email: null;
      name: null;
      payload: null;
    };

let defaultJwks: JWTVerifyGetKey | undefined;

function sharedJwks(): JWTVerifyGetKey {
  // Lazily constructed: building it eagerly at import time would fire a
  // network request from any module that merely imports this package, and
  // would break bundlers that evaluate modules during a build.
  defaultJwks ??= createRemoteJWKSet(new URL(IAP_JWKS_URL));
  return defaultJwks;
}

/**
 * Drop the cached key set. Only useful in tests, where a stubbed fetch must
 * not be served from a cache populated by a previous example — the mirror of
 * googleauth's `Google::Auth::IDTokens.forget_sources!`.
 */
export function resetJwksCache(): void {
  defaultJwks = undefined;
}

/**
 * Preferred entry point: pulls the assertion off the request itself, so
 * application code never has to name the header.
 */
export function verifyRequest(
  source: HeaderSource,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  return verify(assertionFrom(source), options);
}

/**
 * Verify a raw assertion JWT.
 *
 * Never throws — every path returns a Result. The outer catch is the
 * fail-closed backstop: a caller's logger raising, or a jose version throwing
 * something unanticipated, must not turn an authentication check into an
 * unhandled rejection that some framework's error boundary renders as a 500
 * (or worse, that a `.catch(() => next())` swallows into a pass).
 */
export async function verify(
  assertion: string | null | undefined,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const logger = options.logger ?? NULL_LOGGER;
  try {
    return await attemptVerify(assertion, options, logger);
  } catch (error) {
    const described = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    try {
      logger.warn(`[cru-iap] unexpected ${described}`);
    } catch {
      // A logger that throws is exactly the case this backstop exists for.
    }
    return reject("unexpected_error");
  }
}

async function attemptVerify(
  assertion: string | null | undefined,
  options: VerifyOptions,
  logger: Logger,
): Promise<VerifyResult> {
  const audience = (options.audience ?? process.env["IAP_AUDIENCE"] ?? "").trim();
  const token = (assertion ?? "").trim();

  if (token === "") return reject("missing_token");
  // Fail closed if unset, so a misconfigured deploy never accepts unaudienced
  // tokens.
  if (audience === "") return reject("missing_audience_config");

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, options.jwks ?? sharedJwks(), {
      issuer: IAP_ISSUER,
      audience,
      algorithms: IAP_ALGORITHMS,
      // jose treats `exp` as optional and simply skips the expiry check when
      // it is absent — the same trap the Ruby jwt gem has. Require it, so a
      // validly signed assertion carrying no expiry can never be accepted
      // forever. IAP always sets one; this just removes the dependency on
      // that staying true.
      requiredClaims: ["exp"],
      ...(options.clockToleranceSeconds === undefined
        ? {}
        : { clockTolerance: options.clockToleranceSeconds }),
    }));
  } catch (error) {
    return reject(reasonForError(error));
  }

  // Belt-and-braces: jose already enforced `issuer` above. Re-assert so a
  // future change that drops that option can't silently widen who we trust.
  const iss = String(payload.iss ?? "");
  if (iss !== IAP_ISSUER) return reject(`bad_iss:${iss}`);

  const rawEmail = payload["email"];
  // A non-string `email` is something that arrived and is not an address, so
  // it belongs in malformed_subject alongside the other bad shapes — not in
  // missing_email. Handled before normalization rather than by coercing:
  // `String(["a@cru.org"])` is `"a@cru.org"`, so a multi-address array claim
  // would coerce into an accepted single address. Ruby's `Array#to_s` renders
  // the brackets and rejects; JS would not, so don't coerce.
  if (rawEmail !== undefined && rawEmail !== null && typeof rawEmail !== "string") {
    logger.warn(
      `[cru-iap] malformed subject: email claim is ${typeof rawEmail} payload=${JSON.stringify(payload)}`,
    );
    return reject("malformed_subject");
  }

  const email = normalizeEmail(rawEmail);
  // Two distinct failure reasons on purpose. `missing_email` = the pool never
  // sent one, which is an infrastructure fix. `malformed_subject` = something
  // arrived that isn't an address. Different fixes — keep them
  // distinguishable in Datadog.
  if (email === "") return reject("missing_email");

  if (!EMAIL_REGEXP.test(email) || NEVER_IN_AN_EMAIL.test(email)) {
    // Log the raw claims so a rejection is diagnosable without re-deploying
    // instrumentation. Identity claims, not credentials — same sensitivity as
    // the emails already in request logs.
    logger.warn(
      `[cru-iap] malformed subject: normalized=${JSON.stringify(email)} payload=${JSON.stringify(payload)}`,
    );
    return reject("malformed_subject");
  }

  // String-only, for the same reason as `email`: coercion would render an
  // array or object into a plausible-looking display name. A non-string here
  // is not worth rejecting the whole request over — `name` is decoration, not
  // identity — so it degrades to null and the caller's local-part fallback
  // takes over. (The real WIF payload has no `name` claim at all, so that
  // fallback is the production path anyway.)
  const rawName = payload["name"];
  const name = typeof rawName === "string" ? rawName.trim() : "";
  return { ok: true, reason: "iap_jwt", email, name: name === "" ? null : name, payload };
}

function reject(reason: string): VerifyResult {
  return { ok: false, reason: reason as ResultReason, email: null, name: null, payload: null };
}

/**
 * Map a jose failure onto the shared vocabulary. jose's typed errors are the
 * main reason this package doesn't use google-auth-library, which reports
 * every one of these as a bare Error with a prose message.
 */
function reasonForError(error: unknown): string {
  if (error instanceof joseErrors.JWTExpired) return "expired_token";

  if (error instanceof joseErrors.JWTClaimValidationFailed) {
    switch (error.claim) {
      case "aud":
        return "audience_mismatch";
      case "iss":
        return "issuer_mismatch";
      case "exp":
        // Only reachable via `requiredClaims` above — an exp that is present
        // but past raises JWTExpired instead.
        return "missing_exp";
      default:
        return `verification_error:ClaimValidationFailed_${error.claim}`;
    }
  }

  if (
    error instanceof joseErrors.JWSSignatureVerificationFailed ||
    error instanceof joseErrors.JWSInvalid ||
    error instanceof joseErrors.JWTInvalid
  ) {
    return `signature_error:${error.message}`;
  }

  // No key in the current JWKS matches the token's `kid`. The Ruby side
  // surfaces this as a SignatureError ("Token not verified as issued by
  // Google"), so keep it in the same bucket rather than splitting the Datadog
  // query — the detail lives in the suffix.
  if (error instanceof joseErrors.JWKSNoMatchingKey) {
    return "signature_error:no_matching_key";
  }

  if (error instanceof joseErrors.JOSEAlgNotAllowed) {
    return "verification_error:AlgNotAllowed";
  }

  // Couldn't reach or parse Google's key set. Matches the Ruby side's
  // `verification_error:KeySourceError`, which is the same condition — the
  // reason names the fault, not the library's class name, so the two agree.
  if (
    error instanceof joseErrors.JWKSTimeout ||
    error instanceof joseErrors.JWKSInvalid ||
    error instanceof joseErrors.JWKInvalid ||
    error instanceof joseErrors.JWKSMultipleMatchingKeys ||
    isJwksFetchFailure(error) ||
    isFetchFailure(error)
  ) {
    return "verification_error:KeySourceError";
  }

  if (error instanceof joseErrors.JOSEError) {
    return `verification_error:${error.constructor.name}`;
  }

  // Anything else is not a jose failure at all — let the outer fail-closed
  // backstop in `verify` log and classify it, so there is exactly one place
  // that decides what "unexpected" means.
  throw error;
}

/**
 * A failed `fetch` of the JWKS surfaces as a TypeError ("fetch failed"), not a
 * JOSEError — jose lets the transport error through untouched.
 */
function isFetchFailure(error: unknown): boolean {
  return error instanceof TypeError && /fetch/i.test(error.message);
}

/**
 * A non-200 or non-JSON response from the JWKS endpoint. jose reports both as
 * the BASE JOSEError class (ERR_JOSE_GENERIC), which looks alarmingly broad to
 * key off — but those two are the only places in the whole library that throw
 * the bare base class (jose 6.2, dist/webapi/jwks/remote.js), and both are
 * this exact condition. Verified rather than assumed, because if a future
 * release starts throwing the base class elsewhere this mapping would quietly
 * mislabel it; the test suite pins both the 503 and the transport case.
 */
function isJwksFetchFailure(error: unknown): boolean {
  return (
    error instanceof joseErrors.JOSEError &&
    (error as { code?: string }).code === "ERR_JOSE_GENERIC"
  );
}

/**
 * `email` is the identity in every IAP mode. `sub` is NEVER an identity — it
 * is an opaque namespaced token — so this deliberately does not read it.
 * Confirmed 2026-07-24 against a captured live workforce payload:
 *
 *   mode                       email                sub
 *   -------------------------- -------------------- -----------------------------
 *   plain IAP (Google id)      bare address         accounts.google.com:<opaque>
 *   WIF, google.email mapped   bare address         sts.google.com:<opaque STS>
 *   WIF, mapping absent        ABSENT               sts.google.com:<opaque STS>
 *
 * The third row is a broken pool, and no app-side fallback can recover an
 * address from it. Reaching for `sub` there buys nothing and costs diagnosis:
 * it turns an accurate `missing_email` (= go fix the pool's attribute_mapping)
 * into a misleading `malformed_subject`.
 *
 * NB the workforce principal URI ("principal://iam.googleapis.com/.../subject/
 * <email>") IS real, but it lives in the nested `workforce_identity
 * .iam_principal` claim — it is the string IAM bindings match, not an identity
 * claim, and it never appears in `email` or `sub`.
 *
 * Strip a leading "<prefix>:" namespace before validating: a real email never
 * contains a colon, so the first colon is always the IAP namespace. Observed
 * prefixes are "accounts.google.com:", "sts.google.com:", and Identity
 * Platform's "securetoken.google.com/<project>/<tenant>:" — split on the first
 * colon rather than matching any literal prefix.
 */
function normalizeEmail(raw: unknown): string {
  if (typeof raw !== "string") return "";
  let email = raw.trim();
  const colon = email.indexOf(":");
  if (colon !== -1) email = email.slice(colon + 1);
  return email.toLowerCase();
}

/** Re-exported so callers can assert against the vocabulary. */
export { isKnownReason };
