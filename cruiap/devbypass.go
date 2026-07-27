package cruiap

import (
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// A dev/test identity that cannot be switched on in production by accident.
//
// Three consumers each grew their own bypass, in three incompatible shapes, and
// one of them shipped an incident: dse-portal's AUTH_ENABLED defaulted to the
// INSECURE value, so forgetting to set it disabled authentication. That is the
// failure mode this primitive is built to make unreachable.
//
// # Why there is no boolean
//
// A boolean flag has a wrong default — someone has to choose it, and half the
// time they choose the open one. An identity-carrying variable has no wrong
// default: either you name a developer to be, or you don't, and "unset" can only
// mean "no bypass". So the opt-in IS the identity:
//
//	CRU_IAP_DEV_BYPASS_EMAIL=you@cru.org go run ./cmd/server
//
// There is deliberately no WithDevBypassEnabled(true) option either. Anything an
// app can turn on in a config struct, an app can turn on in production.
//
// # Two independent guards on top
//
// Neither depends on the app being written correctly:
//
//  1. IAP_AUDIENCE set => refuse. A deploy configured for IAP is a deploy that
//     must verify, and cru-terraform injects IAP_AUDIENCE into every IAP-fronted
//     container.
//  2. A cloud-runtime marker present => refuse. Cloud Run always sets K_SERVICE;
//     App Engine sets GAE_ENV; Cloud Functions sets FUNCTION_TARGET. Nobody has
//     to remember to set these, which is exactly what makes them trustworthy as
//     a guard.
//
// Composition — the app writes one branch, not a policy:
//
//	result, bypassed := cruiap.DevBypass()
//	if !bypassed {
//	    result = cruiap.VerifyRequest(ctx, r, cruiap.WithAudience(audience))
//	}
//
// Checking the bypass first is safe precisely because of the guards above: in
// any environment where it could matter, it reports false.
const (
	// DevBypassEmailVar names the developer to act as. Its presence is the opt-in.
	DevBypassEmailVar = "CRU_IAP_DEV_BYPASS_EMAIL"
	// DevBypassNameVar optionally supplies a display name.
	DevBypassNameVar = "CRU_IAP_DEV_BYPASS_NAME"
)

// CloudMarkers are set by the platform, not by us — see guard 2 above.
var CloudMarkers = []string{"K_SERVICE", "K_REVISION", "GAE_ENV", "FUNCTION_TARGET"}

// plausibleEmail is at least as strict as the verifier's gate, so a bypass
// identity can never become a user the real path would have rejected.
//
//   - "/" and "\" are excluded because RFC 5322 permits "/" in a local part, so
//     a principal:// URI would otherwise pass a naive address check.
//   - ":" is excluded because a namespaced claim value ("sts.google.com:me@…")
//     is a copy-paste out of a JWT, not a developer's address. The verifier
//     STRIPS that prefix; here it is refused instead, because silently
//     reinterpreting what someone typed into an auth-disabling variable is worse
//     than making them retype it. Matches Ruby, whose URI::MailTo::EMAIL_REGEXP
//     rejects it outright.
var plausibleEmail = regexp.MustCompile(`^[^\s@/\\:]+@[^\s@/\\:]+\.[^\s@/\\:]+$`)

// devBypassOptions is separate from the verifier's options: DevBypass shares
// none of them (no audience, no key source, no clock), and folding it in would
// advertise knobs that do nothing here.
type devBypassOptions struct {
	lookup func(string) string
	logger *slog.Logger
}

// DevBypassOption configures DevBypass.
type DevBypassOption func(*devBypassOptions)

// WithDevBypassEnv replaces the environment lookup, so tests need no t.Setenv.
func WithDevBypassEnv(lookup func(string) string) DevBypassOption {
	return func(options *devBypassOptions) { options.lookup = lookup }
}

// WithDevBypassLogger sets the logger used for the activation and refusal
// warnings.
func WithDevBypassLogger(logger *slog.Logger) DevBypassOption {
	return func(options *devBypassOptions) { options.logger = logger }
}

// DevBypass reports whether a dev identity is configured and permitted. The
// second return is false whenever the caller must verify for real, which is
// every case in a managed runtime.
func DevBypass(opts ...DevBypassOption) (Result, bool) {
	config := &devBypassOptions{lookup: os.Getenv, logger: slog.Default()}
	for _, apply := range opts {
		apply(config)
	}

	raw := strings.TrimSpace(config.lookup(DevBypassEmailVar))
	if raw == "" {
		return Result{}, false
	}

	refuse := func(why string) (Result, bool) {
		config.logger.Warn("[cruiap] ignoring "+DevBypassEmailVar+", verifying the IAP assertion instead",
			slog.String("why", why))
		return Result{}, false
	}

	if strings.TrimSpace(config.lookup("IAP_AUDIENCE")) != "" {
		return refuse("IAP_AUDIENCE is set")
	}

	for _, marker := range CloudMarkers {
		if strings.TrimSpace(config.lookup(marker)) != "" {
			return refuse(marker + " is set, so this is a managed runtime")
		}
	}

	email := strings.ToLower(raw)
	if !plausibleEmail.MatchString(email) {
		return refuse(DevBypassEmailVar + "=" + raw + " is not an email address")
	}

	// Loud on every activation, deliberately. A bypass that logs once is a
	// bypass someone forgets is on; dev-server request volume makes this
	// affordable.
	config.logger.Warn("[cruiap] DEV BYPASS ACTIVE — the IAP assertion is NOT being verified",
		slog.String("acting_as", email),
		slog.String("to_restore", "unset "+DevBypassEmailVar))

	return Result{
		OK:     true,
		Reason: ReasonDevBypass,
		Email:  email,
		Name:   strings.TrimSpace(config.lookup(DevBypassNameVar)),
	}, true
}
