package cruiap

import "net/http"

// Header is the header IAP injects. Exposed because infra config and test
// fixtures legitimately need the wire name — application code should not, and
// should call VerifyRequest instead of reaching for it.
//
// Canonical MIME form, since that is what http.Header keys on. Lookups through
// http.Header.Get and http.Header.Values are case-insensitive regardless.
const Header = "X-Goog-Iap-Jwt-Assertion"

// AssertionFrom returns the raw assertion JWT carried by r, or "" if absent.
//
// A repeated header is treated as absent rather than resolved to one of the
// values: two assertions is not a shape IAP produces, so guessing which to trust
// would be worse than failing closed. The verifier then reports
// ReasonMissingToken.
func AssertionFrom(r *http.Request) string {
	if r == nil {
		return ""
	}
	return AssertionFromHeader(r.Header)
}

// AssertionFromHeader is AssertionFrom for callers that hold only the headers —
// a middleware chain that has already consumed the request, or a test.
func AssertionFromHeader(h http.Header) string {
	if h == nil {
		return ""
	}
	values := h.Values(Header)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
