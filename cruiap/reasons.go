package cruiap

import "strings"

// Reasons is the rejection vocabulary, shared verbatim with the Ruby gem
// (CruIap::TokenVerifier::REASONS), the TypeScript package (src/reasons.ts) and
// the Python package (cru_iap/reasons.py), so every Cru app behind IAP — Rails,
// Node, FastAPI or Go — files the same Datadog queries.
//
// Entries ending in ":" carry a variable suffix.
//
// If you add one here, add it to the other three too. A test in each language
// asserts its own verifier can only emit listed reasons, and the Python suite
// cross-checks the Ruby and TypeScript lists against its own; the Go suite
// cross-checks all three against this one.
var Reasons = []string{
	ReasonMissingToken,
	ReasonMissingAudienceConfig,
	ReasonBadIss,
	ReasonMissingExp,
	ReasonMissingEmail,
	ReasonMalformedSubject,
	ReasonSignatureError,
	ReasonAudienceMismatch,
	ReasonExpiredToken,
	ReasonIssuerMismatch,
	ReasonVerificationError,
	ReasonUnexpectedError,
	ReasonIAPJWT,
}

const (
	// ReasonMissingToken means the assertion header was absent or blank.
	ReasonMissingToken = "missing_token"
	// ReasonMissingAudienceConfig means IAP_AUDIENCE was unset — a deploy
	// misconfiguration. The verifier fails closed rather than skipping the check.
	ReasonMissingAudienceConfig = "missing_audience_config"
	// ReasonBadIss carries the offending iss as a suffix.
	ReasonBadIss = "bad_iss:"
	// ReasonMissingExp means the token was signed but carries no expiry, so
	// nothing downstream would ever consider it stale.
	ReasonMissingExp = "missing_exp"
	// ReasonMissingEmail means no email claim arrived — an IAP/pool config gap,
	// fixed in terraform rather than in the app.
	ReasonMissingEmail = "missing_email"
	// ReasonMalformedSubject means something arrived that is not an address.
	ReasonMalformedSubject = "malformed_subject"
	// ReasonSignatureError carries the underlying detail as a suffix.
	ReasonSignatureError = "signature_error:"
	// ReasonAudienceMismatch means aud was not the configured audience.
	ReasonAudienceMismatch = "audience_mismatch"
	// ReasonExpiredToken means exp was present and in the past.
	ReasonExpiredToken = "expired_token"
	// ReasonIssuerMismatch means iss was not IAP's.
	ReasonIssuerMismatch = "issuer_mismatch"
	// ReasonVerificationError carries the fault name as a suffix.
	ReasonVerificationError = "verification_error:"
	// ReasonUnexpectedError is the fail-closed catch-all.
	ReasonUnexpectedError = "unexpected_error"
	// ReasonIAPJWT is the only reason for which OK is true.
	ReasonIAPJWT = "iap_jwt"
)

// IsKnownReason reports whether reason is a member of the shared vocabulary:
// exact match for the plain entries, prefix match for the ones ending in ":".
func IsKnownReason(reason string) bool {
	for _, known := range Reasons {
		if strings.HasSuffix(known, ":") {
			if strings.HasPrefix(reason, known) {
				return true
			}
			continue
		}
		if reason == known {
			return true
		}
	}
	return false
}
