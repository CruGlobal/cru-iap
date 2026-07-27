// Package cruiap verifies the Google-signed JWT that Identity-Aware Proxy
// injects on every request it lets through to a backend, and extracts an email
// identity.
//
// A direct port of CruIap::TokenVerifier (lib/cru_iap/token_verifier.rb),
// src/verifier.ts and cru_iap/verifier.py. All four share a rejection vocabulary
// and every claim-shape decision; keep them in step.
//
// # Why stdlib-only
//
// The three siblings each lean on their ecosystem's JWT library — googleauth,
// jose, PyJWT. This one deliberately does not, for reasons specific to Go and to
// this problem:
//
//   - wormhole, the only consumer as of 2026-07, already contains a stdlib-only
//     OIDC verifier (internal/oidcverify) that makes and documents the same
//     choice. Introducing a dependency here to replace a dependency-free
//     implementation there would be a net loss.
//
//   - ES256 verification is genuinely small in Go: base64url and JSON for the
//     envelope, and crypto/ecdsa for the signature. Nothing here implements a
//     cryptographic primitive; it calls stdlib ones.
//
//   - The reason vocabulary is *better* served without a translation layer. Each
//     sibling had to reverse-engineer its library's error taxonomy to map onto
//     the shared reasons, and two of the nastier notes in the README exist
//     because of it — jose reporting a non-200 JWKS as its base error class,
//     PyJWKClient using one error type for two unrelated faults distinguishable
//     only by message. Here every condition is raised at the site that detects
//     it, so the mapping is exact rather than inferred.
//
// The tradeoff, stated plainly: the JWS envelope parsing and the claim checks are
// this package's own rather than a widely-audited library's. That is why the
// suite pins alg confusion, the "none" algorithm, a wrong-curve key, a truncated
// signature, and a token whose exp is absent rather than merely past — the
// failure modes a JWT library would otherwise be trusted for.
package cruiap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// IAPIssuer is the only issuer the verifier trusts.
const IAPIssuer = "https://cloud.google.com/iap"

// IAPJWKSURL is Google's IAP key set. Note the "-jwk" suffix: the bare
// .../iap/verify/public_key endpoint serves a PEM map instead, which is not
// parseable as a JWK set.
const IAPJWKSURL = "https://www.gstatic.com/iap/verify/public_key-jwk"

// jwksTTL is how long a fetched key set may be served from cache, matching the
// Ruby googleauth key source's one hour and the Python PyJWKClient lifespan.
const jwksTTL = time.Hour

// emailPattern is URI::MailTo::EMAIL_REGEXP, ported character-for-character from
// Ruby so all four verifiers accept and reject exactly the same strings.
var emailPattern = regexp.MustCompile(
	`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+` +
		`@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?` +
		`(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// neverInAnEmail: emailPattern alone is not a sufficient shape gate. RFC 5322
// permits "/" in a local part, so a URI-shaped value ending in an address — e.g.
// principal://iam.googleapis.com/.../subject/alice@cru.org — MATCHES it, and
// would be persisted as a user whose email is that entire string. No real Okta or
// Google identity contains a slash or a backslash, so treat either as proof we
// are looking at a URI or principal rather than an address.
var neverInAnEmail = regexp.MustCompile(`[/\\]`)

// Result is the outcome of a verification.
//
// OK is the only field a caller must branch on; Reason is for telemetry and is
// drawn from the vocabulary shared with the Ruby, TypeScript and Python
// siblings. Email and Name are populated only when OK.
type Result struct {
	OK      bool
	Reason  string
	Email   string
	Name    string
	Payload map[string]any
}

func reject(reason string) Result {
	return Result{OK: false, Reason: reason}
}

// KeySource supplies the ECDSA public key for a given JWK "kid".
//
// Narrow on purpose: it is the whole seam the tests substitute, so a suite can
// mint real ES256 tokens against its own key without a network fetch and still
// exercise the production code path.
type KeySource interface {
	// KeyFor returns the key matching kid. It must return an error wrapping
	// ErrUnknownKid when no such key exists, and any other error when the key set
	// could not be fetched or parsed — the verifier maps those two onto different
	// reasons.
	KeyFor(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// ErrUnknownKid signals that the key set was retrieved successfully but contains
// no key matching the token's kid. Distinguished from a fetch failure because the
// two mean different things: a rotated-away key versus an unreachable Google.
var ErrUnknownKid = errors.New("cruiap: no key matches the token's kid")

type options struct {
	audience       string
	audienceSet    bool
	keys           KeySource
	logger         *slog.Logger
	clockTolerance time.Duration
	now            func() time.Time
}

// Option configures Verify and VerifyRequest.
type Option func(*options)

// WithAudience overrides the audience, which otherwise comes from the
// IAP_AUDIENCE environment variable, read at call time.
func WithAudience(audience string) Option {
	return func(o *options) { o.audience = audience; o.audienceSet = true }
}

// WithKeySource overrides the key source, which otherwise is a process-wide
// cache over IAPJWKSURL shared across calls so its cache is actually a cache.
func WithKeySource(keys KeySource) Option {
	return func(o *options) { o.keys = keys }
}

// WithLogger sets the logger. Defaults to one that discards, so the package is
// silent until an app opts in.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// WithClockTolerance allows leeway on exp. Defaults to zero.
func WithClockTolerance(d time.Duration) Option {
	return func(o *options) { o.clockTolerance = d }
}

// WithClock overrides the time source. For tests.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// VerifyRequest is the preferred entry point: it pulls the assertion off the
// request itself, so application code never has to name the header.
func VerifyRequest(ctx context.Context, r *http.Request, opts ...Option) Result {
	return Verify(ctx, AssertionFrom(r), opts...)
}

// Verify verifies a raw assertion JWT.
//
// It never panics and never returns an error — every path returns a Result. That
// is the fail-closed contract: an authentication check must not become a panic
// that a framework's recover middleware renders as a 500, or worse, that some
// upstream error path swallows into a pass.
func Verify(ctx context.Context, assertion string, opts ...Option) (result Result) {
	cfg := &options{logger: slog.New(slog.DiscardHandler), now: time.Now}
	for _, apply := range opts {
		apply(cfg)
	}

	// The fail-closed backstop. Nothing below is expected to panic; if something
	// does, the request must still be rejected rather than crashing the server.
	defer func() {
		if recovered := recover(); recovered != nil {
			cfg.logger.Warn("[cru-iap] unexpected panic", "recovered", fmt.Sprint(recovered))
			result = reject(ReasonUnexpectedError)
		}
	}()

	return attemptVerify(ctx, assertion, cfg)
}

func attemptVerify(ctx context.Context, assertion string, cfg *options) Result {
	audience := cfg.audience
	if !cfg.audienceSet {
		audience = os.Getenv("IAP_AUDIENCE")
	}
	audience = strings.TrimSpace(audience)
	token := strings.TrimSpace(assertion)

	if token == "" {
		return reject(ReasonMissingToken)
	}
	// Fail closed if unset, so a misconfigured deploy never accepts unaudienced
	// tokens.
	if audience == "" {
		return reject(ReasonMissingAudienceConfig)
	}

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return reject(ReasonSignatureError + "not a compact JWS")
	}

	headerBytes, err := decodeSegment(segments[0])
	if err != nil {
		return reject(ReasonSignatureError + "undecodable header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return reject(ReasonSignatureError + "unparseable header")
	}
	// Pin ES256 BEFORE touching the key. This is the alg-confusion guard: a key
	// set that also published an RSA or HMAC key, or a token claiming "none",
	// must not be able to talk us into a weaker verification.
	if header.Alg != "ES256" {
		return reject(ReasonVerificationError + "AlgNotAllowed")
	}

	payloadBytes, err := decodeSegment(segments[1])
	if err != nil {
		return reject(ReasonSignatureError + "undecodable payload")
	}
	signature, err := decodeSegment(segments[2])
	if err != nil {
		return reject(ReasonSignatureError + "undecodable signature")
	}

	keys := cfg.keys
	if keys == nil {
		keys = sharedKeySource()
	}
	key, err := keys.KeyFor(ctx, header.Kid)
	if err != nil {
		if errors.Is(err, ErrUnknownKid) {
			// The Ruby side surfaces this as a SignatureError ("Token not verified
			// as issued by Google") and the TypeScript and Python sides as
			// signature_error:no_matching_key, so keep it in the same bucket rather
			// than splitting the Datadog query.
			return reject(ReasonSignatureError + "no_matching_key")
		}
		// Couldn't reach or parse Google's key set. Matches the other three
		// languages' verification_error:KeySourceError — the reason names the
		// fault, not the library's type, so all four agree.
		return reject(ReasonVerificationError + "KeySourceError")
	}

	if !verifyES256(key, segments[0]+"."+segments[1], signature) {
		return reject(ReasonSignatureError + "signature did not verify")
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return reject(ReasonSignatureError + "unparseable payload")
	}

	// Order matters here and mirrors the siblings: issuer, then audience, then
	// expiry, then identity. A caller reading Datadog wants the most fundamental
	// fault named, not whichever check happened to run first.
	// Note on vocabulary parity: the siblings emit issuer_mismatch from their JWT
	// library's own check and then re-assert, emitting bad_iss: if the library
	// ever stopped checking. There is no library to distrust here, so this single
	// check emits issuer_mismatch and bad_iss: is unreachable in Go by
	// construction. A test asserts that, so the absence is recorded rather than
	// looking like an oversight.
	iss, _ := claims["iss"].(string)
	if iss != IAPIssuer {
		return reject(ReasonIssuerMismatch)
	}

	if !audienceMatches(claims["aud"], audience) {
		return reject(ReasonAudienceMismatch)
	}

	// Require an expiry rather than trusting one is present. This is the same
	// hole the Ruby jwt gem, jose and PyJWT all have — each skips the expiry
	// check when the claim is ABSENT rather than failing — so a validly signed
	// assertion carrying no exp would otherwise be accepted forever. IAP always
	// sets one; this removes the dependency on that staying true. Three
	// libraries in three languages behaved this way, which is why it is checked
	// explicitly here rather than assumed away.
	exp, ok := numericClaim(claims["exp"])
	if !ok {
		return reject(ReasonMissingExp)
	}
	if cfg.now().Add(-cfg.clockTolerance).After(time.Unix(exp, 0)) {
		return reject(ReasonExpiredToken)
	}

	rawEmail, present := claims["email"]
	// A non-string email is something that arrived and is not an address, so it
	// belongs in malformed_subject alongside the other bad shapes — not in
	// missing_email. Go will not coerce it for us, which removes the JavaScript
	// hazard (String(["a@cru.org"]) === "a@cru.org") by construction; the check
	// is explicit anyway so the intent is legible.
	if present && rawEmail != nil {
		if _, isString := rawEmail.(string); !isString {
			cfg.logger.Warn("[cru-iap] malformed subject",
				"detail", fmt.Sprintf("email claim is %T", rawEmail),
				"payload", describe(claims))
			return reject(ReasonMalformedSubject)
		}
	}

	email := normalizeEmail(rawEmail)
	// Two distinct failure reasons on purpose. missing_email = the pool never
	// sent one, which is an infrastructure fix (see normalizeEmail).
	// malformed_subject = something arrived that isn't an address. Different
	// fixes — keep them distinguishable in Datadog.
	if email == "" {
		return reject(ReasonMissingEmail)
	}

	if !emailPattern.MatchString(email) || neverInAnEmail.MatchString(email) {
		// Log the raw claims so a rejection is diagnosable without re-deploying
		// instrumentation. Identity claims, not credentials — same sensitivity as
		// the emails already in request logs.
		cfg.logger.Warn("[cru-iap] malformed subject",
			"normalized", email, "payload", describe(claims))
		return reject(ReasonMalformedSubject)
	}

	// String-only, for the same reason as email. A non-string here is not worth
	// rejecting the whole request over — name is decoration, not identity — so it
	// degrades to "" and the caller's local-part fallback takes over. (The real
	// WIF payload has no name claim at all, so that fallback is the production
	// path anyway.)
	name, _ := claims["name"].(string)

	return Result{
		OK:      true,
		Reason:  ReasonIAPJWT,
		Email:   email,
		Name:    strings.TrimSpace(name),
		Payload: claims,
	}
}

// audienceMatches compares the aud claim against the configured audience.
//
// aud is permitted by RFC 7519 to be either a string or an array of strings.
// IAP sends a string, but accepting the array form costs nothing and a
// constant-time compare avoids leaking the audience through timing — it is a
// deploy-config value rather than a secret, so this is hygiene, not a fix.
func audienceMatches(claim any, want string) bool {
	switch actual := claim.(type) {
	case string:
		return subtle.ConstantTimeCompare([]byte(actual), []byte(want)) == 1
	case []any:
		for _, candidate := range actual {
			if s, ok := candidate.(string); ok {
				if subtle.ConstantTimeCompare([]byte(s), []byte(want)) == 1 {
					return true
				}
			}
		}
	}
	return false
}

// numericClaim reads a NumericDate claim. encoding/json decodes every JSON
// number into float64, so exp arrives as a float even though it is an integer
// count of seconds.
func numericClaim(claim any) (int64, bool) {
	switch value := claim.(type) {
	case float64:
		return int64(value), true
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	}
	return 0, false
}

// verifyES256 checks an ES256 signature over the signing input.
//
// JWS ES256 signatures are the fixed-width r||s concatenation (RFC 7515 A.3),
// 32 bytes each — NOT the ASN.1 DER encoding that ecdsa.VerifyASN1 expects and
// that most non-JOSE tooling produces. Getting this wrong fails closed (nothing
// verifies), which is the safe direction, but it is the single most common
// mistake in a hand-written JWS verifier.
func verifyES256(key *ecdsa.PublicKey, signingInput string, signature []byte) bool {
	const coordinateBytes = 32
	if len(signature) != 2*coordinateBytes {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(signature[:coordinateBytes])
	s := new(big.Int).SetBytes(signature[coordinateBytes:])
	return ecdsa.Verify(key, digest[:], r, s)
}

// decodeSegment decodes a JWS segment, which is base64url WITHOUT padding.
func decodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(segment)
}

func describe(claims map[string]any) string {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return fmt.Sprintf("%v", claims)
	}
	return string(encoded)
}

// normalizeEmail pulls an email identity out of the email claim.
//
// email is the identity in every IAP mode. sub is NEVER an identity — it is an
// opaque namespaced token — so this deliberately does not read it. Confirmed
// 2026-07-24 against a captured live workforce payload
// (spec/fixtures/real_wif_iap_payload.json):
//
//	mode                      email         sub
//	------------------------- ------------- ----------------------------
//	plain IAP (Google id)     bare address  accounts.google.com:<opaque>
//	WIF, google.email mapped  bare address  sts.google.com:<opaque STS>
//	WIF, mapping absent       ABSENT        sts.google.com:<opaque STS>
//
// The third row is a broken pool, and no app-side fallback can recover an
// address from it. Reaching for sub there buys nothing and costs diagnosis: it
// turns an accurate missing_email (= go fix the pool's attribute_mapping) into a
// misleading malformed_subject.
//
// NB the workforce principal URI
// (principal://iam.googleapis.com/.../subject/<email>) IS real, but it lives in
// the nested workforce_identity.iam_principal claim — it is the string IAM
// bindings match, not an identity claim, and it never appears in email or sub.
//
// Strip a leading "<prefix>:" namespace before validating: a real email never
// contains a colon, so the first colon is always the IAP namespace. Observed
// prefixes are "accounts.google.com:", "sts.google.com:", and Identity
// Platform's "securetoken.google.com/<project>/<tenant>:" — split on the first
// colon rather than matching any literal prefix.
//
// Then downcase, to match the usual lowercased email column.
func normalizeEmail(raw any) string {
	email, ok := raw.(string)
	if !ok {
		return ""
	}
	email = strings.TrimSpace(email)
	if _, after, found := strings.Cut(email, ":"); found {
		email = after
	}
	return strings.ToLower(email)
}

// remoteKeySource fetches and caches Google's IAP key set.
//
// The hot path — a token whose kid is already cached and unexpired — performs no
// network I/O. A token whose kid is unknown triggers exactly one refresh before
// being rejected, so a key rotation is picked up without a fetch per request and
// without an unbounded stampede on bad input.
type remoteKeySource struct {
	url    string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
	now       func() time.Time
}

var (
	sharedKeysOnce sync.Once
	sharedKeys     *remoteKeySource
)

func sharedKeySource() *remoteKeySource {
	// Lazily constructed: building it at init would be harmless here (it makes no
	// request until used) but keeping the shape identical to the siblings' lazy
	// construction makes the four easier to read side by side.
	sharedKeysOnce.Do(func() {
		sharedKeys = NewRemoteKeySource(IAPJWKSURL, &http.Client{Timeout: 10 * time.Second})
	})
	return sharedKeys
}

// NewRemoteKeySource builds a caching KeySource over a JWKS endpoint. Exported so
// a consumer can supply its own HTTP client — one with a proxy, a tighter
// timeout, or instrumentation.
func NewRemoteKeySource(url string, client *http.Client) *remoteKeySource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &remoteKeySource{url: url, client: client, now: time.Now}
}

func (s *remoteKeySource) KeyFor(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fresh := s.now().Sub(s.fetchedAt) < jwksTTL
	if key, ok := s.keys[kid]; ok && fresh {
		return key, nil
	}
	// Either the cache is stale, or the kid is unknown and might have appeared in
	// a rotation since the last fetch. One refresh, then a definitive answer.
	if err := s.refreshLocked(ctx); err != nil {
		// Serve a cached key rather than failing the request if we have one: a
		// transient gstatic.com blip should not lock every user out. The TTL
		// bounds how stale this can be.
		if key, ok := s.keys[kid]; ok {
			return key, nil
		}
		return nil, err
	}
	if key, ok := s.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKid, kid)
}

func (s *remoteKeySource) refreshLocked(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("cruiap: JWKS fetch returned %d", response.StatusCode)
	}
	// Bounded read: an endpoint that streamed forever would otherwise hang the
	// mutex this is called under, taking every concurrent request with it.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	s.keys = keys
	s.fetchedAt = s.now()
	return nil
}

// ParseJWKS parses an EC JWK Set into public keys by kid. Exported because a
// consumer pinning a key set from disk, or a test, legitimately needs it.
//
// Non-EC and non-P-256 keys are skipped rather than erroring: Google publishing
// an additional key type must not break verification of the ES256 tokens we do
// understand. A key set that yields nothing usable is an error, though —
// silently returning an empty map would surface as no_matching_key and send the
// reader hunting a rotation that never happened.
func ParseJWKS(body []byte) (map[string]*ecdsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("cruiap: unparseable JWKS: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey)
	for _, jwk := range set.Keys {
		if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Kid == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			continue
		}
		y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			continue
		}
		if len(x) != 32 || len(y) != 32 {
			continue
		}
		// Uncompressed point form, so ParseUncompressedPublicKey validates the
		// point is actually on the curve. A public key off the curve is a route to
		// invalid-curve attacks, and the deprecated elliptic.Unmarshal would not
		// have checked.
		point := append([]byte{4}, append(x, y...)...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}

	if len(set.Keys) > 0 && len(keys) == 0 {
		return nil, errors.New("cruiap: JWKS contained no usable P-256 keys")
	}
	return keys, nil
}
