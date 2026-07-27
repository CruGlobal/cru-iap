package cruiap

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The guards are the whole point, so most of this file is negative controls.
//
// The incident being prevented: dse-portal's AUTH_ENABLED defaulted to the
// insecure value, so forgetting to set it disabled authentication. Every test
// below asserting bypassed == false is a way that cannot happen here.

// envLookup turns a map into the lookup DevBypass takes, so no test needs
// t.Setenv (and so tests stay parallel-safe).
func envLookup(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

func quietBypass(t *testing.T, env map[string]string) (Result, bool) {
	t.Helper()
	return DevBypass(
		WithDevBypassEnv(envLookup(env)),
		WithDevBypassLogger(slog.New(slog.DiscardHandler)),
	)
}

func TestDevBypassIsOffWhenNothingIsSet(t *testing.T) {
	if _, bypassed := quietBypass(t, map[string]string{}); bypassed {
		t.Error("bypass engaged with no configuration — the default must be closed")
	}
}

func TestDevBypassHasNoBooleanToGetBackwards(t *testing.T) {
	// The API surface is the assertion: an identity-carrying variable has no
	// wrong default, where AUTH_ENABLED=false vs =true does. Setting the "enable"
	// flag people reach for by habit does nothing at all.
	for _, env := range []map[string]string{
		{"AUTH_ENABLED": "false"},
		{"CRU_IAP_DEV_BYPASS": "true"},
		{"CRU_IAP_DEV_BYPASS_ENABLED": "1"},
	} {
		if _, bypassed := quietBypass(t, env); bypassed {
			t.Errorf("bypass engaged from %v", env)
		}
	}
}

func TestDevBypassActivatesWhenADeveloperNamesThemselves(t *testing.T) {
	result, bypassed := quietBypass(t, map[string]string{DevBypassEmailVar: "dev@cru.org"})

	if !bypassed {
		t.Fatal("bypass did not engage")
	}
	if !result.OK {
		t.Error("result.OK is false")
	}
	if result.Reason != ReasonDevBypass {
		t.Errorf("reason = %q, want %q", result.Reason, ReasonDevBypass)
	}
	if result.Email != "dev@cru.org" {
		t.Errorf("email = %q", result.Email)
	}
	// So a bypassed request is queryable in Datadog alongside every real one,
	// rather than being invisible.
	if !IsKnownReason(result.Reason) {
		t.Errorf("reason %q is not in the shared vocabulary", result.Reason)
	}
}

func TestDevBypassNormalizesAndCarriesAName(t *testing.T) {
	result, _ := quietBypass(t, map[string]string{
		DevBypassEmailVar: "  Dev@Cru.org  ",
		DevBypassNameVar:  "A Developer",
	})

	if result.Email != "dev@cru.org" {
		t.Errorf("email = %q, want dev@cru.org", result.Email)
	}
	if result.Name != "A Developer" {
		t.Errorf("name = %q", result.Name)
	}
}

func TestDevBypassRefusesWhenIAPAudienceIsSet(t *testing.T) {
	// cru-terraform injects IAP_AUDIENCE into every IAP-fronted container, so the
	// bypass cannot coexist with the config that means "verify for real".
	_, bypassed := quietBypass(t, map[string]string{
		DevBypassEmailVar: "dev@cru.org",
		"IAP_AUDIENCE":    "/projects/1/global/backendServices/2",
	})

	if bypassed {
		t.Error("bypass engaged in an IAP-configured environment")
	}
}

func TestDevBypassIgnoresABlankIAPAudience(t *testing.T) {
	_, bypassed := quietBypass(t, map[string]string{
		DevBypassEmailVar: "dev@cru.org",
		"IAP_AUDIENCE":    "   ",
	})

	if !bypassed {
		t.Error("a blank IAP_AUDIENCE is not a configured one and must not block the bypass")
	}
}

func TestDevBypassRefusesInAManagedRuntime(t *testing.T) {
	// Nobody has to remember to set these — the platform does — which is exactly
	// what makes them trustworthy as a guard.
	for _, marker := range CloudMarkers {
		t.Run(marker, func(t *testing.T) {
			_, bypassed := quietBypass(t, map[string]string{
				DevBypassEmailVar: "dev@cru.org",
				marker:            "anything",
			})
			if bypassed {
				t.Errorf("bypass engaged with %s set", marker)
			}
		})
	}
}

func TestDevBypassRefusesOnCloudRunEvenWithoutIAPAudience(t *testing.T) {
	// The guards are independent on purpose: this is the misconfigured-deploy
	// case, where relying on IAP_AUDIENCE alone would open the bypass.
	_, bypassed := quietBypass(t, map[string]string{
		DevBypassEmailVar: "dev@cru.org",
		"K_SERVICE":       "my-app",
	})

	if bypassed {
		t.Error("bypass engaged on Cloud Run")
	}
}

func TestDevBypassIdentityMustSurviveTheSameShapeGate(t *testing.T) {
	for _, value := range []string{
		"not-an-address",
		"principal://iam.googleapis.com/locations/global/workforcePools/p/subject/dev@cru.org",
		"dev@cru.org/../admin",
		"sts.google.com:dev@cru.org",
		"@cru.org",
	} {
		t.Run(value, func(t *testing.T) {
			if _, bypassed := quietBypass(t, map[string]string{DevBypassEmailVar: value}); bypassed {
				t.Errorf("bypass accepted %q as an identity", value)
			}
		})
	}
}

func TestDevBypassWarnsLoudlyOnEveryActivation(t *testing.T) {
	// A bypass that logs once is a bypass someone forgets is on.
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))
	env := WithDevBypassEnv(envLookup(map[string]string{DevBypassEmailVar: "dev@cru.org"}))

	DevBypass(env, WithDevBypassLogger(logger))
	DevBypass(env, WithDevBypassLogger(logger))

	if got := strings.Count(log.String(), "DEV BYPASS ACTIVE"); got != 2 {
		t.Errorf("logged %d activation warnings, want 2", got)
	}
}

func TestDevBypassExplainsItselfWhenItRefuses(t *testing.T) {
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, nil))

	DevBypass(
		WithDevBypassEnv(envLookup(map[string]string{
			DevBypassEmailVar: "dev@cru.org",
			"K_SERVICE":       "my-app",
		})),
		WithDevBypassLogger(logger),
	)

	if !strings.Contains(log.String(), "K_SERVICE") {
		t.Errorf("refusal did not name the guard that fired: %s", log.String())
	}
}
