package cruiap

import "testing"

// The two footguns these exist to close, then the string cases that make them
// worth being code rather than a README bullet.

func TestLoginURLNeverReturnsBareSlash(t *testing.T) {
	// IAP sends bare / to the IdP, which sends it back to /, forever. The single
	// most-reported IAP footgun at Cru, so it gets the first test.
	for _, target := range []string{"", "/", "   "} {
		if got := LoginURL(target); got != "/?login=true" {
			t.Errorf("LoginURL(%q) = %q, want /?login=true", target, got)
		}
	}
}

func TestLoginURL(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"a path", "/dashboard", "/dashboard?login=true"},
		{
			"an absolute URL",
			"https://app.cru.org/dashboard",
			"https://app.cru.org/dashboard?login=true",
		},
		{"an existing query uses &", "/dashboard?tab=reports", "/dashboard?tab=reports&login=true"},
		{"a bare trailing ? does not become ?&", "/dashboard?", "/dashboard?login=true"},
		// "/a#b" with "?login=true" appended naively is "/a#b?login=true", where
		// the param is part of the fragment and never leaves the browser. This is
		// the case a hand-rolled Sprintf gets wrong.
		{"a fragment stays last", "/dashboard#reports", "/dashboard?login=true#reports"},
		{
			"a query and a fragment together",
			"/dashboard?tab=1#reports",
			"/dashboard?tab=1&login=true#reports",
		},
		{"already triggered is unchanged", "/dashboard?login=true", "/dashboard?login=true"},
		{
			"a param merely containing the trigger is not the trigger",
			"/go?next=%2F%3Flogin%3Dtrue",
			"/go?next=%2F%3Flogin%3Dtrue&login=true",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := LoginURL(test.target); got != test.want {
				t.Errorf("LoginURL(%q) = %q, want %q", test.target, got, test.want)
			}
		})
	}
}

func TestLogoutURL(t *testing.T) {
	// Without the cookie-clear mode the app's session goes away, IAP's federated
	// login cookie does not, and the next request signs the same person straight
	// back in.
	cases := []struct {
		target string
		want   string
	}{
		{"", "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"},
		{"/goodbye", "/goodbye?gcp-iap-mode=CLEAR_LOGIN_COOKIE"},
		{"/bye?reason=timeout#top", "/bye?reason=timeout&gcp-iap-mode=CLEAR_LOGIN_COOKIE#top"},
		{"/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE", "/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE"},
	}

	for _, test := range cases {
		if got := LogoutURL(test.target); got != test.want {
			t.Errorf("LogoutURL(%q) = %q, want %q", test.target, got, test.want)
		}
	}
}

func TestURLHelpersAreIdempotent(t *testing.T) {
	if got := LoginURL(LoginURL("/dashboard")); got != "/dashboard?login=true" {
		t.Errorf("LoginURL twice = %q", got)
	}
	if got := LogoutURL(LogoutURL("/bye")); got != "/bye?gcp-iap-mode=CLEAR_LOGIN_COOKIE" {
		t.Errorf("LogoutURL twice = %q", got)
	}
}

func TestQueryConstants(t *testing.T) {
	// Pinned rather than derived: a typo in either is a silent auth failure, and
	// these strings are Google's, not ours to normalise.
	if LoginQuery != "login=true" {
		t.Errorf("LoginQuery = %q", LoginQuery)
	}
	if LogoutQuery != "gcp-iap-mode=CLEAR_LOGIN_COOKIE" {
		t.Errorf("LogoutQuery = %q", LogoutQuery)
	}
}
