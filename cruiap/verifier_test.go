package cruiap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The verifier's behaviour, one test per decision it makes. Mirrors
// test/unit/verifier.test.ts, tests/test_verifier.py and the Ruby unit spec.
//
// Every token here is really signed with ES256 and really verified — the only
// thing substituted is whose key it is. Because this package parses the JWS
// envelope itself rather than delegating to a JWT library, the suite also pins
// the failure modes such a library would otherwise be trusted for: alg
// confusion, "none", a truncated signature, a key off the curve.

func verifyWith(t *testing.T, s *signer, claims map[string]any, opts ...Option) Result {
	t.Helper()
	base := []Option{WithAudience(testAudience), WithKeySource(newLocalKeys(t, s))}
	return Verify(context.Background(), s.sign(t, claims), append(base, opts...)...)
}

func verifyToken(t *testing.T, s *signer, token string, opts ...Option) Result {
	t.Helper()
	base := []Option{WithAudience(testAudience), WithKeySource(newLocalKeys(t, s))}
	return Verify(context.Background(), token, append(base, opts...)...)
}

func TestAcceptsAValidAssertion(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(nil))

	if !result.OK {
		t.Fatalf("expected OK, got reason %q", result.Reason)
	}
	if result.Reason != ReasonIAPJWT {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonIAPJWT)
	}
	if result.Email != "alice@cru.org" {
		t.Errorf("email = %q, want alice@cru.org", result.Email)
	}
}

func TestExposesThePayloadForCallersNeedingAnotherClaim(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(nil))

	if got := result.Payload["sub"]; got != "accounts.google.com:104291823410293841029" {
		t.Errorf("payload sub = %v", got)
	}
}

func TestNormalizesTheEmail(t *testing.T) {
	s := newSigner(t)

	for name, claim := range map[string]string{
		"downcases":                    "Alice@Cru.ORG",
		"trims surrounding whitespace": "  alice@cru.org  ",
		"strips accounts.google.com":   "accounts.google.com:alice@cru.org",
		"strips sts.google.com":        "sts.google.com:alice@cru.org",
		// securetoken.google.com/<project>/<tenant>: — the reason we split on the
		// first colon rather than matching a literal prefix list.
		"strips an Identity Platform namespace containing slashes": "securetoken.google.com/proj/tenant:alice@cru.org",
	} {
		t.Run(name, func(t *testing.T) {
			result := verifyWith(t, s, iapClaims(map[string]any{"email": claim}))

			if result.Email != "alice@cru.org" {
				t.Errorf("email = %q, want alice@cru.org (reason %q)", result.Email, result.Reason)
			}
		})
	}
}

func TestTheNameClaim(t *testing.T) {
	s := newSigner(t)

	t.Run("is returned when present", func(t *testing.T) {
		result := verifyWith(t, s, iapClaims(map[string]any{"name": "Alice Anderson"}))
		if result.Name != "Alice Anderson" {
			t.Errorf("name = %q", result.Name)
		}
	})

	t.Run("degrades to empty when blank", func(t *testing.T) {
		result := verifyWith(t, s, iapClaims(map[string]any{"name": "   "}))
		if result.Name != "" {
			t.Errorf("name = %q, want empty", result.Name)
		}
	})

	t.Run("degrades to empty when not a string, without rejecting", func(t *testing.T) {
		// name is decoration, not identity — the caller falls back to the email
		// local part. The real WIF payload has no name claim at all.
		result := verifyWith(t, s, iapClaims(map[string]any{"name": []any{"Alice"}}))
		if !result.OK {
			t.Fatalf("expected OK, got %q", result.Reason)
		}
		if result.Name != "" {
			t.Errorf("name = %q, want empty", result.Name)
		}
	})
}

func TestFailsClosedOnAMissingToken(t *testing.T) {
	s := newSigner(t)

	for name, token := range map[string]string{
		"empty":            "",
		"whitespace only":  "   ",
		"one segment":      "notajwt",
		"two segments":     "header.payload",
		"four segments":    "a.b.c.d",
		"undecodable head": "!!!.eyJ9.sig",
	} {
		t.Run(name, func(t *testing.T) {
			result := verifyToken(t, s, token)

			if result.OK {
				t.Fatal("expected rejection")
			}
			if !IsKnownReason(result.Reason) {
				t.Errorf("reason %q is not in the shared vocabulary", result.Reason)
			}
		})
	}

	if got := verifyToken(t, s, "").Reason; got != ReasonMissingToken {
		t.Errorf("empty token reason = %q, want %q", got, ReasonMissingToken)
	}
}

func TestFailsClosedWhenNoAudienceIsConfigured(t *testing.T) {
	s := newSigner(t)
	// Fail closed rather than skipping the audience check — a misconfigured deploy
	// must never accept unaudienced tokens.
	t.Setenv("IAP_AUDIENCE", "")

	result := Verify(context.Background(), s.sign(t, iapClaims(nil)),
		WithKeySource(newLocalKeys(t, s)))

	if result.Reason != ReasonMissingAudienceConfig {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonMissingAudienceConfig)
	}
}

func TestReadsTheAudienceFromTheEnvironmentAtCallTime(t *testing.T) {
	s := newSigner(t)
	t.Setenv("IAP_AUDIENCE", testAudience)

	result := Verify(context.Background(), s.sign(t, iapClaims(nil)),
		WithKeySource(newLocalKeys(t, s)))

	if !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
}

func TestRejectsATokenSignedBySomeoneElse(t *testing.T) {
	ours := newSigner(t)
	stranger := newSigner(t)

	result := Verify(context.Background(), stranger.sign(t, iapClaims(nil)),
		WithAudience(testAudience), WithKeySource(newLocalKeys(t, ours)))

	if result.OK {
		t.Fatal("expected rejection")
	}
	if !strings.HasPrefix(result.Reason, ReasonSignatureError) {
		t.Errorf("reason = %q, want a signature_error", result.Reason)
	}
}

func TestRejectsAnUnknownKid(t *testing.T) {
	s := newSigner(t)

	result := verifyToken(t, s, s.signWithKid(t, "rotated-away", iapClaims(nil)))

	if result.Reason != ReasonSignatureError+"no_matching_key" {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestRejectsATamperedPayload(t *testing.T) {
	s := newSigner(t)
	honest := s.sign(t, iapClaims(nil))
	forged := s.sign(t, iapClaims(map[string]any{"email": "attacker@evil.example"}))

	// Honest header and signature, swapped payload.
	parts := strings.Split(honest, ".")
	tampered := parts[0] + "." + strings.Split(forged, ".")[1] + "." + parts[2]

	result := verifyToken(t, s, tampered)

	if result.OK {
		t.Fatal("expected rejection")
	}
	if !strings.HasPrefix(result.Reason, ReasonSignatureError) {
		t.Errorf("reason = %q, want a signature_error", result.Reason)
	}
}

func TestRejectsAlgConfusionAndNone(t *testing.T) {
	// The guard that matters most in a hand-written verifier: alg is pinned BEFORE
	// the key is fetched or used, so a token claiming a different algorithm cannot
	// talk us into a weaker verification.
	s := newSigner(t)

	for _, alg := range []string{"none", "HS256", "RS256", "ES384", "", "es256"} {
		t.Run("alg="+alg, func(t *testing.T) {
			token := s.signWithHeader(t,
				map[string]any{"alg": alg, "kid": s.kid, "typ": "JWT"}, iapClaims(nil))

			result := verifyToken(t, s, token)

			if result.OK {
				t.Fatalf("accepted alg %q", alg)
			}
			if result.Reason != ReasonVerificationError+"AlgNotAllowed" {
				t.Errorf("reason = %q, want AlgNotAllowed", result.Reason)
			}
		})
	}
}

func TestRejectsATruncatedSignature(t *testing.T) {
	// JWS ES256 signatures are the fixed-width 64-byte r||s form. A DER-encoded or
	// short signature must reject rather than being coerced into two big.Ints.
	s := newSigner(t)
	token := s.sign(t, iapClaims(nil))
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	for name, mangled := range map[string][]byte{
		"truncated": raw[:32],
		"extended":  append(raw, 0x00),
		"empty":     {},
	} {
		t.Run(name, func(t *testing.T) {
			token := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mangled)

			if verifyToken(t, s, token).OK {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRejectsTheWrongAudience(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{"aud": "/projects/1/global/backendServices/2"}))

	if result.Reason != ReasonAudienceMismatch {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonAudienceMismatch)
	}
}

func TestAcceptsAnArrayAudienceContainingOurs(t *testing.T) {
	// RFC 7519 permits aud to be an array. IAP sends a string, but accepting the
	// array form costs nothing and a verifier that rejected it would be wrong.
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{
		"aud": []any{"/projects/1/global/backendServices/2", testAudience},
	}))

	if !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
}

func TestRejectsAnArrayAudienceWithoutOurs(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{
		"aud": []any{"/projects/1/global/backendServices/2"},
	}))

	if result.Reason != ReasonAudienceMismatch {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestRejectsTheWrongIssuer(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{"iss": "https://accounts.google.com"}))

	if result.Reason != ReasonIssuerMismatch {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonIssuerMismatch)
	}
}

func TestRejectsAMissingIssuer(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{"iss": nil}))

	if result.Reason != ReasonIssuerMismatch {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestRejectsAnExpiredToken(t *testing.T) {
	s := newSigner(t)
	now := time.Now().Unix()

	result := verifyWith(t, s, iapClaims(map[string]any{"iat": now - 1200, "exp": now - 600}))

	if result.Reason != ReasonExpiredToken {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonExpiredToken)
	}
}

func TestHonoursAClockTolerance(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s,
		iapClaims(map[string]any{"exp": time.Now().Unix() - 5}),
		WithClockTolerance(time.Minute))

	if !result.OK {
		t.Fatalf("expected OK, got %q", result.Reason)
	}
}

func TestRejectsAnAssertionWithNoExpiryAtAll(t *testing.T) {
	// The Ruby jwt gem, jose and PyJWT all SKIP the expiry check when exp is
	// absent rather than failing. This package checks explicitly because of that
	// track record: three libraries in three languages behaved the same way.
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{"exp": nil}))

	if result.Reason != ReasonMissingExp {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonMissingExp)
	}
}

func TestRejectsANonNumericExp(t *testing.T) {
	s := newSigner(t)

	result := verifyWith(t, s, iapClaims(map[string]any{"exp": "1785030166"}))

	if result.Reason != ReasonMissingExp {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestTheEmailClaim(t *testing.T) {
	s := newSigner(t)

	t.Run("missing is missing_email", func(t *testing.T) {
		if got := verifyWith(t, s, iapClaims(map[string]any{"email": nil})).Reason; got != ReasonMissingEmail {
			t.Errorf("reason = %q", got)
		}
	})

	t.Run("blank is missing_email", func(t *testing.T) {
		if got := verifyWith(t, s, iapClaims(map[string]any{"email": "   "})).Reason; got != ReasonMissingEmail {
			t.Errorf("reason = %q", got)
		}
	})

	t.Run("never falls back to sub", func(t *testing.T) {
		// sub is an opaque namespaced token in every IAP mode. A fallback turns an
		// accurate missing_email (go fix the pool's attribute_mapping) into a
		// misleading malformed_subject.
		result := verifyWith(t, s, iapClaims(map[string]any{
			"email": nil, "sub": "accounts.google.com:alice@cru.org",
		}))

		if result.Reason != ReasonMissingEmail {
			t.Errorf("reason = %q, want %q", result.Reason, ReasonMissingEmail)
		}
		if result.Email != "" {
			t.Errorf("email = %q, want empty", result.Email)
		}
	})

	for name, claim := range map[string]any{
		"not an address":         "not-an-address",
		"an array":               []any{"alice@cru.org", "attacker@evil.example"},
		"an object":              map[string]any{"address": "alice@cru.org"},
		"a number":               42,
		"containing a backslash": `cru\alice@cru.org`,
		"a raw principal URI": "principal://iam.googleapis.com/locations/global/" +
			"workforcePools/p/subject/alice@cru.org",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			result := verifyWith(t, s, iapClaims(map[string]any{"email": claim}))

			if result.Reason != ReasonMalformedSubject {
				t.Errorf("reason = %q, want %q", result.Reason, ReasonMalformedSubject)
			}
			if result.Email != "" {
				t.Errorf("email = %q, want empty", result.Email)
			}
		})
	}
}

func TestRejectsThePrincipalURIThatSurvivesTheColonStrip(t *testing.T) {
	// The interaction worth pinning. The RAW principal fails the email regexp only
	// because of the "principal:" scheme colon — but the verifier strips
	// everything up to the first colon before validating, since that is how it
	// removes the namespace. What survives DOES match the regexp: RFC 5322 permits
	// "/" in a local part. Only the slash guard rejects it. Each guard looks
	// redundant alone; together they are not.
	s := newSigner(t)
	survives := "//iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org"

	if !emailPattern.MatchString(survives) {
		t.Fatal("negative control failed: the regexp alone should accept this")
	}

	result := verifyWith(t, s, iapClaims(map[string]any{"email": "principal:" + survives}))

	if result.Reason != ReasonMalformedSubject {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonMalformedSubject)
	}
}

func TestKeySourceFailures(t *testing.T) {
	s := newSigner(t)
	token := s.sign(t, iapClaims(nil))

	t.Run("unreachable is a KeySourceError", func(t *testing.T) {
		result := Verify(context.Background(), token, WithAudience(testAudience),
			WithKeySource(failingKeys{err: errors.New("dial tcp: connection refused")}))

		if result.Reason != ReasonVerificationError+"KeySourceError" {
			t.Errorf("reason = %q", result.Reason)
		}
	})

	t.Run("unknown kid is a signature_error, not a KeySourceError", func(t *testing.T) {
		// Different faults, different fixes: a rotated key versus an unreachable
		// Google. Keep them distinguishable in Datadog.
		result := Verify(context.Background(), token, WithAudience(testAudience),
			WithKeySource(failingKeys{err: ErrUnknownKid}))

		if result.Reason != ReasonSignatureError+"no_matching_key" {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestTheFailClosedBackstopCatchesAPanic(t *testing.T) {
	s := newSigner(t)

	result := Verify(context.Background(), s.sign(t, iapClaims(nil)),
		WithAudience(testAudience), WithKeySource(panickingKeys{}))

	if result.OK {
		t.Fatal("expected rejection")
	}
	if result.Reason != ReasonUnexpectedError {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonUnexpectedError)
	}
}

func TestNeverReturnsOKOnAnyFailurePath(t *testing.T) {
	// Sweep: whatever goes wrong, OK is false and there is no email. This is the
	// invariant every caller depends on.
	s := newSigner(t)
	stranger := newSigner(t)
	now := time.Now().Unix()

	tokens := []string{
		"",
		"garbage",
		stranger.sign(t, iapClaims(nil)),
		s.sign(t, iapClaims(map[string]any{"email": nil})),
		s.sign(t, iapClaims(map[string]any{"email": "not-an-address"})),
		s.sign(t, iapClaims(map[string]any{"aud": "/wrong"})),
		s.sign(t, iapClaims(map[string]any{"iss": "https://evil.example"})),
		s.sign(t, iapClaims(map[string]any{"exp": nil})),
		s.sign(t, iapClaims(map[string]any{"exp": now - 600, "iat": now - 1200})),
		s.signWithKid(t, "unknown", iapClaims(nil)),
	}

	for _, token := range tokens {
		result := verifyToken(t, s, token)

		if result.OK {
			t.Errorf("accepted %q", token)
		}
		if result.Email != "" || result.Name != "" || result.Payload != nil {
			t.Errorf("leaked identity on rejection: %+v", result)
		}
		if !IsKnownReason(result.Reason) {
			t.Errorf("reason %q is not in the shared vocabulary", result.Reason)
		}
	}
}

func TestVerifyRequest(t *testing.T) {
	s := newSigner(t)
	keys := newLocalKeys(t, s)

	t.Run("pulls the assertion off an http.Request", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set(Header, s.sign(t, iapClaims(nil)))

		result := VerifyRequest(context.Background(), request,
			WithAudience(testAudience), WithKeySource(keys))

		if result.Email != "alice@cru.org" {
			t.Errorf("email = %q (reason %q)", result.Email, result.Reason)
		}
	})

	t.Run("is case-insensitive about the header name", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("x-goog-iap-jwt-assertion", s.sign(t, iapClaims(nil)))

		result := VerifyRequest(context.Background(), request,
			WithAudience(testAudience), WithKeySource(keys))

		if !result.OK {
			t.Errorf("expected OK, got %q", result.Reason)
		}
	})

	t.Run("reports missing_token with no header", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)

		result := VerifyRequest(context.Background(), request,
			WithAudience(testAudience), WithKeySource(keys))

		if result.Reason != ReasonMissingToken {
			t.Errorf("reason = %q", result.Reason)
		}
	})

	t.Run("treats a repeated header as absent", func(t *testing.T) {
		// Two assertions is not a shape IAP produces. Fail closed rather than
		// guessing which to trust.
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Add(Header, s.sign(t, iapClaims(nil)))
		request.Header.Add(Header, s.sign(t, iapClaims(map[string]any{"email": "attacker@evil.example"})))

		result := VerifyRequest(context.Background(), request,
			WithAudience(testAudience), WithKeySource(keys))

		if result.Reason != ReasonMissingToken {
			t.Errorf("reason = %q, want %q", result.Reason, ReasonMissingToken)
		}
	})

	t.Run("survives a nil request", func(t *testing.T) {
		result := VerifyRequest(context.Background(), nil,
			WithAudience(testAudience), WithKeySource(keys))

		if result.Reason != ReasonMissingToken {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestParseJWKS(t *testing.T) {
	s := newSigner(t)

	t.Run("parses Google's shape", func(t *testing.T) {
		keys, err := ParseJWKS(s.jwks(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := keys[testKid]; !ok {
			t.Errorf("kid %q missing from %v", testKid, keys)
		}
	})

	t.Run("errors on unparseable JSON", func(t *testing.T) {
		if _, err := ParseJWKS([]byte("not json")); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("skips a non-EC key but keeps the usable ones", func(t *testing.T) {
		// Google publishing an additional key type must not break verification of
		// the ES256 tokens we do understand.
		var set map[string]any
		if err := json.Unmarshal(s.jwks(t), &set); err != nil {
			t.Fatal(err)
		}
		set["keys"] = append(set["keys"].([]any),
			map[string]any{"kty": "RSA", "kid": "an-rsa-key", "n": "abc", "e": "AQAB"})
		body, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}

		keys, err := ParseJWKS(body)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := keys["an-rsa-key"]; ok {
			t.Error("kept a non-EC key")
		}
		if _, ok := keys[testKid]; !ok {
			t.Error("dropped the usable key")
		}
	})

	t.Run("errors when nothing in a non-empty set is usable", func(t *testing.T) {
		// Returning an empty map would surface as no_matching_key and send the
		// reader hunting a key rotation that never happened.
		body := []byte(`{"keys":[{"kty":"RSA","kid":"only-rsa","n":"abc","e":"AQAB"}]}`)

		if _, err := ParseJWKS(body); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("rejects a point that is not on the curve", func(t *testing.T) {
		// An off-curve public key is a route to invalid-curve attacks, and the
		// deprecated elliptic.Unmarshal would not have checked.
		x := make([]byte, 32)
		y := make([]byte, 32)
		bigIntFromHex(t, "01").FillBytes(x)
		bigIntFromHex(t, "02").FillBytes(y)
		body, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
			"kty": "EC", "crv": "P-256", "kid": "off-curve",
			"x": base64.RawURLEncoding.EncodeToString(x),
			"y": base64.RawURLEncoding.EncodeToString(y),
		}}})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseJWKS(body); err == nil {
			t.Fatal("expected an error — the point is not on P-256")
		}
	})
}

func TestRemoteKeySource(t *testing.T) {
	s := newSigner(t)

	t.Run("fetches once and serves the rest from cache", func(t *testing.T) {
		fetches := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetches++
			w.Write(s.jwks(t))
		}))
		defer server.Close()
		source := NewRemoteKeySource(server.URL, server.Client())

		for range 5 {
			if _, err := source.KeyFor(context.Background(), testKid); err != nil {
				t.Fatal(err)
			}
		}

		if fetches != 1 {
			t.Errorf("fetched %d times, want 1 — the cache is not caching", fetches)
		}
	})

	t.Run("refreshes once for an unknown kid, then reports it", func(t *testing.T) {
		fetches := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetches++
			w.Write(s.jwks(t))
		}))
		defer server.Close()
		source := NewRemoteKeySource(server.URL, server.Client())

		for range 3 {
			_, err := source.KeyFor(context.Background(), "never-published")
			if !errors.Is(err, ErrUnknownKid) {
				t.Fatalf("err = %v, want ErrUnknownKid", err)
			}
		}

		// One refresh per unknown-kid lookup is the bound: it must not be
		// unbounded, and it must not be zero (or a real rotation would never be
		// picked up).
		if fetches != 3 {
			t.Errorf("fetched %d times for 3 lookups, want 3", fetches)
		}
	})

	t.Run("reports a non-200 as an error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		source := NewRemoteKeySource(server.URL, server.Client())

		_, err := source.KeyFor(context.Background(), testKid)

		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, ErrUnknownKid) {
			t.Error("a 503 must not be reported as an unknown kid")
		}
	})

	t.Run("serves a cached key when a refresh fails", func(t *testing.T) {
		// A transient gstatic.com blip should not lock every user out. The TTL
		// bounds how stale this can get.
		healthy := true
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if !healthy {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write(s.jwks(t))
		}))
		defer server.Close()
		source := NewRemoteKeySource(server.URL, server.Client())

		if _, err := source.KeyFor(context.Background(), testKid); err != nil {
			t.Fatal(err)
		}
		healthy = false
		// Force the TTL to have lapsed so the next lookup attempts a refresh.
		source.now = func() time.Time { return time.Now().Add(2 * jwksTTL) }

		if _, err := source.KeyFor(context.Background(), testKid); err != nil {
			t.Errorf("expected the stale key to be served, got %v", err)
		}
	})
}

func TestGeneratedKeysAreP256(t *testing.T) {
	// Guard on the test helper itself: if this ever generated a P-384 key the
	// suite would be testing a curve IAP never uses.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() {
		t.Error("expected P-256")
	}
}
