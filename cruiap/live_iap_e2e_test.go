//go:build e2e

// End-to-end against LIVE Google infrastructure.
//
// Nothing here is stubbed. A real Okta sign-in federates through a real
// workforce identity pool into a real IAP-fronted Cloud Run service, and the
// assertion Google actually injected is fed to the verifier — which fetches
// Google's real JWKS over the real network to check the real signature.
//
// The Go sibling of test/e2e/live-iap.test.ts, verifying the SAME captured
// assertion. The capture is not driven from here — see the loader below and
// e2e/README.md for the artifact contract.
//
//	e2e/run_all.sh                   # capture once, run all four languages
//	go test -tags e2e ./cruiap/...   # this suite alone, against an existing capture
//
// Behind a build tag rather than an env check so that `go test ./...` does not
// even compile it: the offline suite must stay provably network-free.

package cruiap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Refuse a capture that is within this many seconds of expiry.
const expiryMarginSeconds = 30

type liveCapture struct {
	Assertion     string         `json:"assertion"`
	Claims        map[string]any `json:"claims"`
	Audience      string         `json:"audience"`
	ExpectedEmail string         `json:"expected_email"`
	CapturedAt    int64          `json:"captured_at"`
	URL           string         `json:"url"`
}

func capturePath() string {
	if override := os.Getenv("CRU_IAP_E2E_CAPTURE"); override != "" {
		return override
	}
	// This file lives in cruiap/; the artifact is at <repo>/e2e/okta/.
	return filepath.Join("..", "e2e", "okta", "capture.json")
}

// loadCapture returns the capture, or a reason to skip. It never fails the
// test: an absent stack is a skip, not a failure.
func loadCapture() (*liveCapture, string) {
	path := capturePath()
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Sprintf("no capture at %s — run: node e2e/okta/capture_assertion.mjs --json", path)
	}

	var capture liveCapture
	if err := json.Unmarshal(body, &capture); err != nil {
		return nil, fmt.Sprintf("capture at %s is not readable JSON: %v", path, err)
	}
	if capture.Assertion == "" || capture.Claims == nil {
		return nil, fmt.Sprintf("capture at %s has no assertion/claims — was it written by an older capture script?", path)
	}

	// Keyed on exp rather than captured_at: exp is what actually decides whether
	// a verify can succeed, and it comes from Google not our clock.
	exp, ok := numericClaim(capture.Claims["exp"])
	if !ok {
		return nil, fmt.Sprintf("capture at %s has no numeric exp claim", path)
	}
	now := time.Now().Unix()
	if exp <= now+expiryMarginSeconds {
		return nil, fmt.Sprintf("capture at %s expired %ds ago — re-run the capture", path, now-exp)
	}

	// Audience is configuration, never read off the token: taking it from the
	// aud claim would turn the positive verify into "does aud equal aud".
	if env := os.Getenv("CRU_IAP_E2E_AUDIENCE"); env != "" {
		capture.Audience = env
	}
	if capture.Audience == "" {
		return nil, `no audience: set CRU_IAP_E2E_AUDIENCE or capture with --audience "$(terraform output -raw iap_audience)"`
	}

	if env := os.Getenv("CRU_IAP_E2E_EMAIL"); env != "" {
		capture.ExpectedEmail = env
	}
	if capture.ExpectedEmail == "" {
		return nil, "no expected email: set CRU_IAP_E2E_EMAIL or re-run the capture script"
	}

	return &capture, ""
}

// requireCapture skips the calling test with an explanatory reason when the
// stack or the artifact is absent.
func requireCapture(t *testing.T) *liveCapture {
	t.Helper()
	capture, skip := loadCapture()
	if skip != "" {
		t.Skip(skip)
	}
	return capture
}

func TestLiveAssertionWasMintedByGoogleMinutesAgo(t *testing.T) {
	// Guards the whole file: every test below is only meaningful if the capture
	// really drove a live sign-in. A stale or hand-copied token fails here
	// rather than silently making the rest of the suite a re-test of the
	// offline fixtures.
	capture := requireCapture(t)

	iat, ok := numericClaim(capture.Claims["iat"])
	if !ok {
		t.Fatal("capture has no numeric iat claim")
	}
	age := time.Now().Unix() - iat

	if age < 0 {
		t.Errorf("iat is in the future by %ds", -age)
	}
	if age >= 600 {
		t.Errorf("assertion is stale (%ds old) — did the capture actually run?", age)
	}
	exp, _ := numericClaim(capture.Claims["exp"])
	if exp <= time.Now().Unix() {
		t.Errorf("assertion already expired")
	}
}

func TestLiveAssertionVerifiesAgainstGooglesLiveJWKS(t *testing.T) {
	// No WithKeySource: this goes over the wire to
	// https://www.gstatic.com/iap/verify/public_key-jwk and checks the
	// signature Google produced with a key we have never seen.
	capture := requireCapture(t)

	result := Verify(context.Background(), capture.Assertion, WithAudience(capture.Audience))

	if !result.OK {
		t.Fatalf("expected OK, got reason %q", result.Reason)
	}
	if result.Reason != "iap_jwt" {
		t.Errorf("reason = %q, want iap_jwt", result.Reason)
	}
	if result.Email != capture.ExpectedEmail {
		t.Errorf("email = %q, want %q", result.Email, capture.ExpectedEmail)
	}
}

func TestLiveAssertionVerifiesStraightOffARequest(t *testing.T) {
	capture := requireCapture(t)

	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	request.Header.Set(Header, capture.Assertion)

	result := VerifyRequest(context.Background(), request, WithAudience(capture.Audience))

	if !result.OK {
		t.Fatalf("expected OK, got reason %q", result.Reason)
	}
	if result.Email != capture.ExpectedEmail {
		t.Errorf("email = %q, want %q", result.Email, capture.ExpectedEmail)
	}
}

func TestLiveAssertionHasNoNameClaim(t *testing.T) {
	// Display names must fall back to the email local part.
	capture := requireCapture(t)

	result := Verify(context.Background(), capture.Assertion, WithAudience(capture.Audience))

	if result.Name != "" {
		t.Errorf("name = %q, want empty", result.Name)
	}
}

// The tests below each take the SAME genuine token and break exactly one
// thing. Without them, "it verified" could mean the verifier accepts anything.

func TestLiveAssertionIsRejectedOnceItsPayloadIsEdited(t *testing.T) {
	capture := requireCapture(t)

	segments := strings.Split(capture.Assertion, ".")
	if len(segments) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(segments))
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}
	claims["email"] = "attacker@evil.example"
	edited, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("re-encoding payload: %v", err)
	}
	forged := strings.Join([]string{
		segments[0],
		base64.RawURLEncoding.EncodeToString(edited),
		segments[2],
	}, ".")

	result := Verify(context.Background(), forged, WithAudience(capture.Audience))

	if result.OK {
		t.Fatal("a tampered payload verified")
	}
	if !strings.HasPrefix(result.Reason, ReasonSignatureError) {
		t.Errorf("reason = %q, want a %s* reason", result.Reason, ReasonSignatureError)
	}
	if result.Email != "" {
		t.Errorf("email = %q, want empty on failure", result.Email)
	}
}

func TestLiveAssertionIsRejectedAgainstADifferentBackendService(t *testing.T) {
	capture := requireCapture(t)

	// Same project, different backend-service id: the shape is right and only
	// the value is wrong, which is the realistic misconfiguration.
	other := capture.Audience[:strings.LastIndex(capture.Audience, "/")] + "/1111111111111111111"
	if other == capture.Audience {
		t.Fatalf("failed to build a different audience from %q", capture.Audience)
	}

	result := Verify(context.Background(), capture.Assertion, WithAudience(other))

	if result.OK || result.Reason != "audience_mismatch" {
		t.Errorf("got OK=%v reason=%q, want false / audience_mismatch", result.OK, result.Reason)
	}
}

func TestLiveAssertionIsRejectedWithNoAudienceConfigured(t *testing.T) {
	capture := requireCapture(t)

	// Explicitly empty, and IAP_AUDIENCE cleared so an ambient value in the
	// shell cannot quietly satisfy the path this test exists to exercise.
	t.Setenv("IAP_AUDIENCE", "")

	result := Verify(context.Background(), capture.Assertion, WithAudience(""))

	if result.OK || result.Reason != "missing_audience_config" {
		t.Errorf("got OK=%v reason=%q, want false / missing_audience_config", result.OK, result.Reason)
	}
}

func TestLiveClaimsReSignedByOurOwnKeyAreRejected(t *testing.T) {
	// Proof that the live JWKS fetch is load-bearing: identical payload, valid
	// ES256 signature, key Google never published.
	capture := requireCapture(t)

	now := time.Now().Unix()
	claims := make(map[string]any, len(capture.Claims)+2)
	for key, value := range capture.Claims {
		claims[key] = value
	}
	claims["iat"] = now - 30
	claims["exp"] = now + 600

	ours := newSigner(t)
	forged := ours.signWithKid(t, "not-googles-key", claims)

	result := Verify(context.Background(), forged, WithAudience(capture.Audience))

	if result.OK {
		t.Fatal("a token signed with our own key verified against Google's JWKS")
	}
	if want := ReasonSignatureError + "no_matching_key"; result.Reason != want {
		t.Errorf("reason = %q, want %q", result.Reason, want)
	}
}

func TestLiveClaimShapeProductionActuallyEmits(t *testing.T) {
	capture := requireCapture(t)

	t.Run("puts a bare address in email, with no namespace prefix", func(t *testing.T) {
		email, _ := capture.Claims["email"].(string)
		if email != capture.ExpectedEmail {
			t.Errorf("email = %q, want %q", email, capture.ExpectedEmail)
		}
		if strings.Contains(email, ":") {
			t.Errorf("email %q carries a namespace prefix", email)
		}
	})

	t.Run("puts an opaque STS token in sub, which is not an identity", func(t *testing.T) {
		sub, _ := capture.Claims["sub"].(string)
		if !strings.HasPrefix(sub, "sts.google.com:") {
			t.Errorf("sub = %q, want an sts.google.com: prefix", sub)
		}
		if strings.Contains(sub, "@") {
			t.Errorf("sub %q looks like an address; it must not be usable as one", sub)
		}
	})

	t.Run("puts principal:// only in the nested workforce_identity claim", func(t *testing.T) {
		workforce, ok := capture.Claims["workforce_identity"].(map[string]any)
		if !ok {
			t.Fatalf("workforce_identity is %T, want an object", capture.Claims["workforce_identity"])
		}
		principal, _ := workforce["iam_principal"].(string)
		if !strings.HasPrefix(principal, "principal://iam.googleapis.com/") {
			t.Errorf("iam_principal = %q, want a principal:// URI", principal)
		}
		for _, claim := range []string{"sub", "email"} {
			if value, _ := capture.Claims[claim].(string); strings.Contains(value, "principal://") {
				t.Errorf("%s = %q leaks a principal:// URI", claim, value)
			}
		}
	})

	t.Run("still matches the pinned capture, claim for claim", func(t *testing.T) {
		// Drift detector against production Google. If this fails, the offline
		// suites in ALL FOUR languages are modelling a shape that no longer
		// exists — re-capture and update spec/fixtures/real_wif_iap_payload.json.
		// fixtureRelativePath is already relative to this package directory.
		body, err := os.ReadFile(fixtureRelativePath)
		if err != nil {
			t.Fatalf("reading pinned fixture: %v", err)
		}
		var fixture struct {
			Claims map[string]any `json:"claims"`
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatalf("parsing pinned fixture: %v", err)
		}

		live := sortedKeys(capture.Claims)
		pinned := sortedKeys(fixture.Claims)
		if strings.Join(live, ",") != strings.Join(pinned, ",") {
			t.Errorf("claim keys drifted:\n  live:   %v\n  pinned: %v", live, pinned)
		}
	})
}

func sortedKeys(claims map[string]any) []string {
	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
