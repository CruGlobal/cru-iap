package cruiap

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Promises the package makes about itself, and — the reason this file exists —
// the cross-language check that the rejection vocabulary has not drifted.
//
// The Python suite compares its list against Ruby's and TypeScript's. This one
// compares Go's against all three, so whichever language a contributor adds a
// reason in, at least one suite goes red until the others catch up.

var quotedString = regexp.MustCompile(`"([^"]+)"`)

func readSibling(t *testing.T, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(relative))
	if err != nil {
		t.Fatalf("reading %s: %v", relative, err)
	}
	return string(body)
}

func extractReasons(t *testing.T, source, pattern string) []string {
	t.Helper()
	block := regexp.MustCompile(pattern).FindStringSubmatch(source)
	if block == nil {
		t.Fatalf("could not find the REASONS block with %q", pattern)
	}
	var reasons []string
	for _, match := range quotedString.FindAllStringSubmatch(block[1], -1) {
		reasons = append(reasons, match[1])
	}
	return reasons
}

func assertSameVocabulary(t *testing.T, language string, theirs []string) {
	t.Helper()
	if len(theirs) != len(Reasons) {
		t.Fatalf("%s has %d reasons, Go has %d:\n  %s\n  %v\n  %v",
			language, len(theirs), len(Reasons),
			"the shared Datadog vocabulary has drifted", theirs, Reasons)
	}
	for i := range Reasons {
		if theirs[i] != Reasons[i] {
			t.Errorf("%s reason %d = %q, Go has %q", language, i, theirs[i], Reasons[i])
		}
	}
}

func TestTheVocabularyMatchesTheRubyGem(t *testing.T) {
	source := readSibling(t, "../lib/cru_iap/token_verifier.rb")

	assertSameVocabulary(t, "Ruby", extractReasons(t, source, `(?s)REASONS = \[(.*?)\]\.freeze`))
}

func TestTheVocabularyMatchesTheTypeScriptPackage(t *testing.T) {
	source := readSibling(t, "../src/reasons.ts")

	assertSameVocabulary(t, "TypeScript",
		extractReasons(t, source, `(?s)export const REASONS = \[(.*?)\] as const;`))
}

func TestTheVocabularyMatchesThePythonPackage(t *testing.T) {
	source := readSibling(t, "../cru_iap/reasons.py")

	assertSameVocabulary(t, "Python",
		extractReasons(t, source, `(?s)REASONS: tuple\[str, \.\.\.\] = \((.*?)\n\)`))
}

// The login/logout triggers are Google's literals, and a typo in any one
// language is a silent auth failure in that language only — an infinite sign-in
// loop, or a sign-out that does not sign out. Cheap to pin here, where the
// sibling sources are already being read.
func TestTheIAPControlQueriesMatchAcrossLanguages(t *testing.T) {
	cases := []struct {
		language string
		file     string
		login    string
		logout   string
	}{
		{"Ruby", "../lib/cru_iap/urls.rb", `LOGIN_QUERY = "([^"]+)"`, `LOGOUT_QUERY = "([^"]+)"`},
		{
			"TypeScript", "../src/urls.ts",
			`export const LOGIN_QUERY = "([^"]+)"`, `export const LOGOUT_QUERY = "([^"]+)"`,
		},
		{"Python", "../cru_iap/urls.py", `LOGIN_QUERY = "([^"]+)"`, `LOGOUT_QUERY = "([^"]+)"`},
	}

	for _, test := range cases {
		t.Run(test.language, func(t *testing.T) {
			source := readSibling(t, test.file)

			for _, pair := range []struct {
				what    string
				pattern string
				want    string
			}{
				{"login", test.login, LoginQuery},
				{"logout", test.logout, LogoutQuery},
			} {
				match := regexp.MustCompile(pair.pattern).FindStringSubmatch(source)
				if match == nil {
					t.Fatalf("could not find the %s query in %s with %q",
						pair.what, test.file, pair.pattern)
				}
				if match[1] != pair.want {
					t.Errorf("%s %s query = %q, Go has %q",
						test.language, pair.what, match[1], pair.want)
				}
			}
		})
	}
}

func TestIsKnownReason(t *testing.T) {
	t.Run("accepts every listed reason", func(t *testing.T) {
		for _, reason := range Reasons {
			if !IsKnownReason(reason) {
				t.Errorf("%q is in Reasons but IsKnownReason rejects it", reason)
			}
		}
	})

	t.Run("accepts a prefixed reason with its suffix", func(t *testing.T) {
		if !IsKnownReason("signature_error:whatever the library said") {
			t.Error("expected a suffixed signature_error to be known")
		}
	})

	t.Run("rejects an invented reason", func(t *testing.T) {
		if IsKnownReason("something_invented") {
			t.Error("expected rejection")
		}
	})
}

func TestBadIssIsUnreachableInGoByConstruction(t *testing.T) {
	// The siblings emit issuer_mismatch from their JWT library's own check and then
	// re-assert, emitting bad_iss: if the library ever stopped checking. There is no
	// library to distrust here, so the single issuer check emits issuer_mismatch and
	// bad_iss: is unreachable. Recorded as a test so the absence reads as a decision
	// rather than an oversight — and so that if someone later adds a second issuer
	// layer, they are prompted to wire bad_iss: up.
	s := newSigner(t)

	for _, iss := range []string{"", "https://evil.example", "https://accounts.google.com"} {
		result := verifyWith(t, s, iapClaims(map[string]any{"iss": iss}))

		if result.Reason != ReasonIssuerMismatch {
			t.Errorf("iss %q gave reason %q, want %q", iss, result.Reason, ReasonIssuerMismatch)
		}
	}
}

func TestTheJWKSURLIsTheJWKEndpointNotThePEMOne(t *testing.T) {
	// The bare .../iap/verify/public_key endpoint serves a PEM map, which is not
	// parseable as a JWK set. Pinned because the difference is one suffix and the
	// failure is a confusing parse error at runtime.
	const want = "-jwk"
	if len(IAPJWKSURL) < len(want) || IAPJWKSURL[len(IAPJWKSURL)-len(want):] != want {
		t.Errorf("IAPJWKSURL = %q, want it to end in %q", IAPJWKSURL, want)
	}
}

func TestTheWireHeaderNameIsWhatInfraExpects(t *testing.T) {
	// Pinned because terraform, the LB and test fixtures all name it literally.
	if Header != "X-Goog-Iap-Jwt-Assertion" {
		t.Errorf("Header = %q", Header)
	}
}
