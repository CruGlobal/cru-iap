package cruiap

import "strings"

// The two IAP control URLs, which every consumer was re-typing.
//
// Pure string builders — no request, no config, no I/O — because the mistakes
// they prevent are string mistakes:
//
//   - Linking bare "/" for sign-in instead of "/?login=true". IAP redirects to
//     the IdP, the IdP redirects back to "/", and round it goes. An infinite
//     loop, and the single most-reported IAP footgun at Cru.
//   - Signing out without "?gcp-iap-mode=CLEAR_LOGIN_COOKIE". The app's own
//     session goes away, IAP's federated login cookie does not, and the next
//     request silently signs the same person straight back in.
//
// Both were checklist items in the README, which is to say they were prose that
// four apps had to re-read correctly. Now they are code.
//
// Kept in step with lib/cru_iap/urls.rb, src/urls.ts and cru_iap/urls.py by a
// cross-language test (see vocabulary_test.go).
const (
	// LoginQuery is appended to trigger IAP's sign-in redirect.
	LoginQuery = "login=true"
	// LogoutQuery is appended to make IAP drop its federated login cookie.
	LogoutQuery = "gcp-iap-mode=CLEAR_LOGIN_COOKIE"
)

// LoginURL returns target with IAP's login trigger appended. An empty target
// means "/".
func LoginURL(target string) string {
	return withParam(target, LoginQuery)
}

// LogoutURL returns target with IAP's cookie-clear mode appended. An empty
// target means "/".
func LogoutURL(target string) string {
	return withParam(target, LogoutQuery)
}

// withParam is query-string surgery that is easy to get wrong by hand, which is
// the reason this exists rather than a Sprintf at each call site:
//
//   - a fragment must stay LAST — "/a#b" with "?login=true" appended naively
//     yields "/a#b?login=true", where the param is part of the fragment and
//     never reaches the server at all
//   - the separator depends on whether a query is already present
//   - idempotent, so LoginURL(LoginURL(x)) == LoginURL(x)
func withParam(target, param string) string {
	resolved := target
	if strings.TrimSpace(resolved) == "" {
		resolved = "/"
	}

	base, fragment := resolved, ""
	if hash := strings.Index(resolved, "#"); hash != -1 {
		base, fragment = resolved[:hash], resolved[hash:]
	}

	if _, query, found := strings.Cut(base, "?"); found {
		for _, existing := range strings.Split(query, "&") {
			if existing == param {
				return resolved
			}
		}
	}

	separator := "?"
	switch {
	case !strings.Contains(base, "?"):
		separator = "?"
	case strings.HasSuffix(base, "?"):
		separator = ""
	default:
		separator = "&"
	}

	return base + separator + param + fragment
}
