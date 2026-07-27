import type { Logger } from "./verifier.js";

/**
 * A dev/test identity that cannot be switched on in production by accident.
 *
 * Three consumers each grew their own bypass, in three incompatible shapes, and
 * one of them shipped an incident: dse-portal's `AUTH_ENABLED` defaulted to the
 * INSECURE value, so forgetting to set it disabled authentication. That is the
 * failure mode this primitive is built to make unreachable.
 *
 * ## Why there is no boolean
 *
 * A boolean flag has a wrong default — someone has to choose it, and half the
 * time they choose the open one. An identity-carrying variable has no wrong
 * default: either you name a developer to be, or you don't, and "unset" can
 * only mean "no bypass". So the opt-in IS the identity:
 *
 * ```sh
 * CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org npm run dev
 * ```
 *
 * There is deliberately no `setDevBypassEnabled(true)` either. Anything an app
 * can turn on in a config file, an app can turn on in production config.
 *
 * ## Two independent guards on top
 *
 * Neither depends on the app being written correctly:
 *
 *   1. `IAP_AUDIENCE` set => refuse. A deploy configured for IAP is a deploy
 *      that must verify, and cru-terraform injects `IAP_AUDIENCE` into every
 *      IAP-fronted container.
 *   2. A cloud-runtime marker present => refuse. Cloud Run always sets
 *      `K_SERVICE`; App Engine sets `GAE_ENV`; Cloud Functions sets
 *      `FUNCTION_TARGET`. Nobody has to remember to set these, which is exactly
 *      what makes them trustworthy as a guard.
 *
 * Composition — the app writes one line, not a branch:
 *
 * ```ts
 * const result = devBypass() ?? (await verifyRequest(request, { audience }));
 * ```
 *
 * Putting the bypass first is safe precisely because of the guards above: in
 * any environment where it could matter, it returns null.
 */

export const DEV_BYPASS_EMAIL_VAR = "CRU_IAP_DEV_BYPASS_EMAIL";
export const DEV_BYPASS_NAME_VAR = "CRU_IAP_DEV_BYPASS_NAME";

/** Set by the platform, not by us — see guard 2 above. */
export const CLOUD_MARKERS = ["K_SERVICE", "K_REVISION", "GAE_ENV", "FUNCTION_TARGET"] as const;

/**
 * The bypass outcome. A separate type rather than a third `VerifyResult`
 * variant, so that widening does not turn every existing consumer's
 * `result.payload` from `JWTPayload` into `JWTPayload | null`. There is
 * genuinely no payload here — nothing was verified.
 */
export interface DevBypassResult {
  ok: true;
  reason: "dev_bypass";
  email: string;
  name: string | null;
  payload: null;
}

export interface DevBypassOptions {
  /** Defaults to process.env; injectable so tests need no shell. */
  env?: Record<string, string | undefined>;
  log?: Logger;
}

// At least as strict as the verifier's gate, so a bypass identity can never
// become a user the real path would have rejected.
//
//   - "/" and "\" are excluded because RFC 5322 permits "/" in a local part, so
//     a principal:// URI would otherwise pass a naive address check.
//   - ":" is excluded because a namespaced claim value ("sts.google.com:me@…")
//     is a copy-paste out of a JWT, not a developer's address. The verifier
//     STRIPS that prefix; here it is refused instead, because silently
//     reinterpreting what someone typed into an auth-disabling variable is
//     worse than making them retype it. Matches Ruby, whose
//     URI::MailTo::EMAIL_REGEXP rejects it outright.
const PLAUSIBLE_EMAIL = /^[^\s@/\\:]+@[^\s@/\\:]+\.[^\s@/\\:]+$/;

const blank = (value: string | undefined): boolean => (value ?? "").trim() === "";

export function devBypass(options: DevBypassOptions = {}): DevBypassResult | null {
  const env = options.env ?? (typeof process === "undefined" ? {} : process.env);
  const log = options.log ?? console;

  const raw = (env[DEV_BYPASS_EMAIL_VAR] ?? "").trim();
  if (raw === "") return null;

  const refuse = (why: string): null => {
    log.warn?.(
      `[cru-iap] ignoring ${DEV_BYPASS_EMAIL_VAR}: ${why}. Verifying the IAP assertion instead.`,
    );
    return null;
  };

  if (!blank(env["IAP_AUDIENCE"])) return refuse("IAP_AUDIENCE is set");

  const marker = CLOUD_MARKERS.find((name) => !blank(env[name]));
  if (marker) return refuse(`${marker} is set, so this is a managed runtime`);

  const email = raw.toLowerCase();
  if (!PLAUSIBLE_EMAIL.test(email)) {
    return refuse(`${DEV_BYPASS_EMAIL_VAR}="${raw}" is not an email address`);
  }

  // Loud on every activation, deliberately. A bypass that logs once is a bypass
  // someone forgets is on; dev-server request volume makes this affordable.
  log.warn?.(
    `[cru-iap] DEV BYPASS ACTIVE — the IAP assertion is NOT being verified. ` +
      `Acting as ${email}. Unset ${DEV_BYPASS_EMAIL_VAR} to restore verification.`,
  );

  const name = (env[DEV_BYPASS_NAME_VAR] ?? "").trim();
  return {
    ok: true,
    reason: "dev_bypass",
    email,
    name: name === "" ? null : name,
    payload: null,
  };
}
