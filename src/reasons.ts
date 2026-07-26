/**
 * The rejection vocabulary, shared verbatim with the Ruby gem
 * (`CruIap::TokenVerifier::REASONS`) so every Cru app behind IAP — Rails or
 * Node — files the same Datadog queries.
 *
 * Entries ending in ":" carry a variable suffix.
 *
 * If you add one here, add it to lib/cru_iap/token_verifier.rb too. A test in
 * each language asserts its own verifier can only emit listed reasons; nothing
 * mechanically enforces that the two lists match, so keep them in step by hand.
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
  "iap_jwt", //                 the only ok === true reason
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
