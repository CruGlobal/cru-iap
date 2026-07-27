package cruiap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The claim shapes IAP actually emits, each as a really-signed token.
//
// The contents here mirror test/unit/claim-shapes.test.ts,
// tests/test_claim_shapes.py and spec/integration/claim_shapes_spec.rb test for
// test. All four suites are anchored to the same pinned capture of a real Google
// assertion, so if the languages ever disagree about what IAP sends, one of them
// goes red.

const fixtureRelativePath = "../spec/fixtures/real_wif_iap_payload.json"

type capturedFixture struct {
	Claims map[string]any `json:"claims"`
}

func loadFixture(t *testing.T) capturedFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(fixtureRelativePath))
	if err != nil {
		t.Fatalf("reading the pinned capture: %v", err)
	}
	var fixture capturedFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatalf("parsing the pinned capture: %v", err)
	}
	return fixture
}

// replayCapture re-times and re-audiences the captured claims, since the captured
// pair expired 600s after capture and its signature is deliberately not stored.
func replayCapture(t *testing.T, overrides map[string]any) map[string]any {
	t.Helper()
	now := time.Now().Unix()
	claims := loadFixture(t).Claims
	claims["iat"] = now - 30
	claims["exp"] = now + 600
	claims["aud"] = testAudience
	return apply(claims, overrides)
}

func TestPlainIAPTakesIdentityFromTheBareEmailClaim(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(nil))

	if !result.OK || result.Email != "alice@cru.org" {
		t.Errorf("got %+v", result)
	}
}

func TestPlainIAPIgnoresTheOpaqueSub(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{
		"sub": "accounts.google.com:104291823410293841029",
	}))

	if !result.OK || result.Email != "alice@cru.org" {
		t.Errorf("got %+v", result)
	}
}

func TestWorkforceIdentityFederation(t *testing.T) {
	s := newSigner(t)

	t.Run("accepts a realistic WIF payload and takes identity from email", func(t *testing.T) {
		result := verifyWith(t, s, wifClaims(nil))

		if !result.OK {
			t.Fatalf("expected OK, got %q", result.Reason)
		}
		if result.Email != "alice@cru.org" {
			t.Errorf("email = %q", result.Email)
		}
		if result.Payload["identity_source"] != "WORKFORCE_IDENTITY" {
			t.Errorf("identity_source = %v", result.Payload["identity_source"])
		}
	})

	t.Run("ignores the nested iam_principal even when it names someone else", func(t *testing.T) {
		claims := wifClaims(nil)
		claims["workforce_identity"] = map[string]any{
			"iam_principal": "principal://iam.googleapis.com/locations/global/" +
				"workforcePools/p/subject/someone-else@cru.org",
		}

		if got := verifyWith(t, s, claims).Email; got != "alice@cru.org" {
			t.Errorf("email = %q", got)
		}
	})

	t.Run("reports an unmapped pool as missing_email, not malformed_subject", func(t *testing.T) {
		// A pool whose provider lacks google.email in its attribute_mapping. The
		// remedy is in terraform, and only missing_email names it.
		if got := verifyWith(t, s, wifClaims(map[string]any{"email": nil})).Reason; got != ReasonMissingEmail {
			t.Errorf("reason = %q, want %q", got, ReasonMissingEmail)
		}
	})

	t.Run("does not recover an address from the principal URI", func(t *testing.T) {
		// The nested principal carries a perfectly good subject. Unwrapping it would
		// be accepting a value IAP never offered as an identity claim.
		claims := wifClaims(map[string]any{"email": nil})
		nested := claims["workforce_identity"].(map[string]any)
		if !strings.Contains(nested["iam_principal"].(string), "okta-user-9f31c0") {
			t.Fatal("fixture drifted: the principal no longer carries a recoverable subject")
		}

		if got := verifyWith(t, s, claims).Email; got != "" {
			t.Errorf("email = %q, want empty", got)
		}
	})

	t.Run("carries no group membership", func(t *testing.T) {
		// Gotcha 8c, asserted rather than left as prose: there is no groups claim
		// and nothing to derive one from. This is why the coarse authz gate has to
		// move into an IAM binding for flightdeck, dgt and dse-portal, none of which
		// can read a group app-side any more.
		result := verifyWith(t, s, wifClaims(nil))

		for claim := range result.Payload {
			if strings.Contains(strings.ToLower(claim), "group") {
				t.Errorf("unexpected group-ish claim %q — gotcha 8c may be stale", claim)
			}
		}
	})
}

func TestThePinnedRealCapture(t *testing.T) {
	// Ground truth: verbatim claims from a live Google IAP assertion, captured
	// 2026-07-25 through a headless Okta sign-in. See the fixture's _provenance.
	s := newSigner(t)

	t.Run("verifies when re-signed and takes identity from email", func(t *testing.T) {
		result := verifyWith(t, s, replayCapture(t, nil))

		if !result.OK {
			t.Fatalf("expected OK, got %q", result.Reason)
		}
		if result.Email != "cru-iap-e2e-test@example.invalid" {
			t.Errorf("email = %q", result.Email)
		}
		// The real WIF payload carries no name claim at all — the email local-part
		// fallback is the production path, not the exception.
		if result.Name != "" {
			t.Errorf("name = %q, want empty", result.Name)
		}
	})

	t.Run("still verifies with the nested workforce_identity claim removed", func(t *testing.T) {
		result := verifyWith(t, s, replayCapture(t, map[string]any{"workforce_identity": nil}))

		if !result.OK {
			t.Errorf("expected OK, got %q", result.Reason)
		}
	})

	t.Run("rejects the real payload with its email stripped", func(t *testing.T) {
		got := verifyWith(t, s, replayCapture(t, map[string]any{"email": nil})).Reason

		if got != ReasonMissingEmail {
			t.Errorf("reason = %q, want %q", got, ReasonMissingEmail)
		}
	})

	t.Run("keeps the synthetic wifClaims helper faithful to the real claim set", func(t *testing.T) {
		// If Google adds or renames a top-level claim, this fails and the rest of the
		// suite stops silently testing a fiction. It earned its keep on the Ruby side
		// immediately by catching a missing azp.
		synthetic := wifClaims(nil)
		var missing []string
		for claim := range loadFixture(t).Claims {
			if _, ok := synthetic[claim]; !ok {
				missing = append(missing, claim)
			}
		}

		if len(missing) > 0 {
			t.Errorf("real payload has claims the synthetic helper lacks: %v", missing)
		}
	})

	t.Run("agrees with the other languages about what the real payload means", func(t *testing.T) {
		// All four languages read this same fixture and must reach the same verdict.
		// Stated as an explicit assertion rather than left implicit, because the
		// fixture is the only shared artefact between the suites.
		result := verifyWith(t, s, replayCapture(t, nil))

		if result.OK != true ||
			result.Reason != ReasonIAPJWT ||
			result.Email != "cru-iap-e2e-test@example.invalid" ||
			result.Name != "" {
			t.Errorf("verdict = %+v", result)
		}
	})
}

func TestTheCaptureIsSignedNowhereInTheFixture(t *testing.T) {
	// The provenance note says the signature is deliberately not stored. If someone
	// ever pastes one in, it would be dead weight at best and a misleading
	// "verified" artefact at worst.
	body, err := os.ReadFile(filepath.Clean(fixtureRelativePath))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}

	if _, present := raw["signature"]; present {
		t.Error("the fixture gained a signature field; see its _provenance note")
	}
}

var _ = context.Background
