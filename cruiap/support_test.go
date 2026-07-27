package cruiap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// Minting real ES256-signed IAP assertions offline.
//
// The mirror of test/support/iap-jwt.ts, tests/support/iap_jwt.py and the Ruby
// suite's equivalent: a locally generated key, a key source backed by it, and
// claim builders for each shape IAP actually emits. Nothing here touches the
// network — the tokens are really signed and really verified, just against our
// own key rather than Google's.

const testAudience = "/projects/123456789/global/backendServices/9876543210"

const testKid = "test-key-1"

type signer struct {
	kid     string
	private *ecdsa.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return &signer{kid: testKid, private: private}
}

// sign produces a real ES256 compact JWS over claims.
func (s *signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return s.signWithHeader(t, map[string]any{"alg": "ES256", "kid": s.kid, "typ": "JWT"}, claims)
}

func (s *signer) signWithKid(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	return s.signWithHeader(t, map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"}, claims)
}

func (s *signer) signWithHeader(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshalling header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling claims: %v", err)
	}
	signingInput := encode(headerJSON) + "." + encode(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, sVal, err := ecdsa.Sign(rand.Reader, s.private, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	// The fixed-width r||s form JWS requires, not ASN.1 DER.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sVal.FillBytes(signature[32:])
	return signingInput + "." + encode(signature)
}

// jwks renders the signer's public key as a JWK Set, exactly as Google's endpoint
// would, so ParseJWKS is exercised rather than bypassed.
func (s *signer) jwks(t *testing.T) []byte {
	t.Helper()
	public := s.private.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	public.X.FillBytes(x)
	public.Y.FillBytes(y)
	set := map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
		"kid": s.kid, "x": encode(x), "y": encode(y),
	}}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshalling jwks: %v", err)
	}
	return body
}

// localKeys is a KeySource over an in-memory key set. Deliberately built by
// parsing a rendered JWKS rather than handing the key over directly, so the
// production parse path runs in every test.
type localKeys struct {
	keys map[string]*ecdsa.PublicKey
}

func newLocalKeys(t *testing.T, s *signer) *localKeys {
	t.Helper()
	keys, err := ParseJWKS(s.jwks(t))
	if err != nil {
		t.Fatalf("parsing jwks: %v", err)
	}
	return &localKeys{keys: keys}
}

func (l *localKeys) KeyFor(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	if key, ok := l.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKid, kid)
}

// failingKeys simulates an unreachable or unparseable key set.
type failingKeys struct{ err error }

func (f failingKeys) KeyFor(_ context.Context, _ string) (*ecdsa.PublicKey, error) {
	return nil, f.err
}

// panickingKeys exists to prove the fail-closed backstop catches a panic.
type panickingKeys struct{}

func (panickingKeys) KeyFor(_ context.Context, _ string) (*ecdsa.PublicKey, error) {
	panic("something nobody anticipated")
}

func encode(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// iapClaims is a plain-IAP assertion: a Google/Cloud Identity session, bare email
// claim. Pass a nil value in overrides to DELETE a claim.
func iapClaims(overrides map[string]any) map[string]any {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":   IAPIssuer,
		"aud":   testAudience,
		"azp":   testAudience,
		"sub":   "accounts.google.com:104291823410293841029",
		"email": "alice@cru.org",
		"iat":   now - 30,
		"exp":   now + 600,
	}
	return apply(claims, overrides)
}

// wifClaims is a Workforce Identity Federation assertion, shaped like the real
// capture in spec/fixtures/real_wif_iap_payload.json.
func wifClaims(overrides map[string]any) map[string]any {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":             IAPIssuer,
		"aud":             testAudience,
		"azp":             testAudience,
		"sub":             "sts.google.com:AAFTZtu4HH_YB5N-0PKpuRFXZj-ziDJSvJCIhth-IjORtiSFUzzGWOVy",
		"email":           "alice@cru.org",
		"iat":             now - 30,
		"exp":             now + 600,
		"identity_source": "WORKFORCE_IDENTITY",
		"workforce_identity": map[string]any{
			"iam_principal": "principal://iam.googleapis.com/locations/global/" +
				"workforcePools/keepzero-okta-poc/subject/okta-user-9f31c0@cru.org",
			"workforce_pool_name": "locations/global/workforcePools/keepzero-okta-poc",
		},
	}
	return apply(claims, overrides)
}

func apply(claims, overrides map[string]any) map[string]any {
	for key, value := range overrides {
		if value == nil {
			delete(claims, key)
			continue
		}
		claims[key] = value
	}
	return claims
}

// bigIntFromHex is a helper for the invalid-curve test.
func bigIntFromHex(t *testing.T, hex string) *big.Int {
	t.Helper()
	value, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		t.Fatalf("bad hex: %q", hex)
	}
	return value
}
