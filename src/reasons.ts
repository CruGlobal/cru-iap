/**
 * The rejection vocabulary, shared verbatim with the Ruby gem
 * (`CruIap::TokenVerifier::REASONS`) so every Cru app behind IAP — Rails or
 * Node — files the same Datadog queries.
 *
 * Entries ending in ":" carry a variable suffix.
 *
 * If you add one here, add it to the Ruby, Python and Go lists too — in the
 * same ORDER, since the cross-language tests compare them element by element
 * (tests/test_package.py checks Ruby and TypeScript against Python;
 * cruiap/vocabulary_test.go checks all three against Go). A test in each
 * language additionally asserts its own verifier can only emit listed reasons.
 */
export const REASONS = [
  "missing_token", //           header absent/blank
  "missing_audience_config", // IAP_AUDIENCE unset — deploy misconfig
  "bad_iss:", //                + the offending iss
  "missing_exp", //             signed but with no expiry — never goes stale
  "missing_email", //           no email claim — IAP/pool config gap
  "malformed_subject", //       present but not an address
  "signature_error:", //        + the underlying detail
  "audience_mismatch",
  "expired_token",
  "issuer_mismatch",
  "verification_error:", //     + the jose error name
  "unexpected_error", //        fail-closed catch-all
  "iap_jwt", //                 ok === true — a verified IAP assertion
  "dev_bypass", //              ok === true — devBypass(), never in production
] as const;

export type Reason = (typeof REASONS)[number];

/** Reasons that carry a `:`-delimited suffix. */
export type PrefixedReason = Extract<Reason, `${string}:`>;

/** The literal strings the verifier can return, suffixes included. */
export type ResultReason = Exclude<Reason, PrefixedReason> | `${PrefixedReason}${string}`;

/**
 * True if `reason` is a member of the shared vocabulary — exact match for the
 * plain entries, prefix match for the ones ending in ":".
 */
export function isKnownReason(reason: string): boolean {
  return REASONS.some((known) =>
    known.endsWith(":") ? reason.startsWith(known) : reason === known,
  );
}
