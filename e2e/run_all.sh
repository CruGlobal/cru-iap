#!/usr/bin/env bash
# Capture ONE real IAP assertion, then verify it in all five languages.
#
# Four suites driving their own browser login would be ~12 minutes of real
# Okta/SAML/IAP round-trips and five independent chances to flake, for no extra
# coverage: the question each suite asks is "does MY library accept the token
# Google actually minted", and one token answers it five times.
#
#   e2e/run_all.sh                 # capture, then run all five
#   e2e/run_all.sh --no-capture    # reuse an existing e2e/okta/capture.json
#   e2e/run_all.sh --only go,ts    # subset; capture still runs unless --no-capture
#
# Every suite runs even if an earlier one fails, so one command tells you
# whether a claim-shape change broke one language or all of them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

capture=true
only="ruby,python,go,ts,rust"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-capture) capture=false; shift ;;
    --only) only="$2"; shift 2 ;;
    # Two -e rather than one `# \?`: BSD sed (macOS) has no \? BRE quantifier
    # and would silently leave the prefix in place.
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed -e 's/^# //' -e 's/^#//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

selected() { [[ ",$only," == *",$1,"* ]]; }

# The audience is CONFIGURATION and must not be read off the token — deriving it
# from the `aud` claim would make every suite's positive verify vacuous. Prefer
# an explicit env var, else ask terraform. Best-effort: when neither is
# available the loaders skip with an actionable message rather than guessing.
if [[ -z "${CRU_IAP_E2E_AUDIENCE:-}" ]]; then
  # `cd` in a subshell rather than `terraform -chdir=`: the version is pinned by
  # e2e/terraform/.tool-versions, and asdf resolves that from the working
  # directory. With -chdir from the repo root asdf sees no .tool-versions and
  # refuses to run at all ("No version is set for command terraform").
  #
  # The shape check is not paranoia. `terraform output -raw` on a workspace with
  # no outputs exits 0 and prints "Warning: No outputs found" — on STDOUT — so a
  # bare capture of its output yields a non-empty string of diagnostics. Exported
  # blindly, that becomes the audience, the preflight sees a truthy value, and
  # all five suites fail with audience_mismatch against garbage.
  audience_shape='^/projects/[0-9]+/global/backendServices/[0-9]+$'
  if audience="$(cd e2e/terraform && terraform output -raw iap_audience 2>/dev/null)" &&
    [[ "$audience" =~ $audience_shape ]]; then
    export CRU_IAP_E2E_AUDIENCE="$audience"
    echo "audience from terraform: $CRU_IAP_E2E_AUDIENCE"
  else
    echo "note: no CRU_IAP_E2E_AUDIENCE and terraform output unavailable;" \
         "relying on the audience recorded in the capture artifact"
  fi
fi

# Same story for the sign-in URL: no host is hardcoded in the capture script, so
# either the caller supplies one or terraform is asked. The shape check exists for
# the same reason as the audience one above — "Warning: No outputs found" on stdout
# would otherwise be handed to the script as a URL.
if [[ -z "${CRU_IAP_E2E_URL:-}" ]]; then
  if login_url="$(cd e2e/terraform && terraform output -raw login_url 2>/dev/null)" &&
    [[ "$login_url" =~ ^https://[a-zA-Z0-9.-]+/ ]]; then
    export CRU_IAP_E2E_URL="$login_url"
    echo "login url from terraform: $CRU_IAP_E2E_URL"
  fi
fi

if [[ "$capture" == true ]]; then
  if [[ -z "${CRU_IAP_E2E_URL:-}" ]]; then
    echo "cannot capture: no CRU_IAP_E2E_URL and no terraform login_url output." >&2
    echo "Set CRU_IAP_E2E_URL=https://host/?login=true, or run --no-capture." >&2
    exit 2
  fi
  echo
  echo "=== capturing a live assertion (headless Okta -> WIF -> IAP; may take ~3 min) ==="
  node e2e/okta/capture_assertion.mjs --json
fi

# Preflight, and the reason this script is not just five commands in a row.
#
# Every suite SKIPS rather than fails when the capture is missing, stale, or has
# no audience — right for a developer with no stack, and dangerous here: five
# skipped suites would otherwise print five "pass" lines and exit 0, which is
# indistinguishable from five real passes. A green run that verified nothing is
# worse than a red one. So assert the artifact is usable up front and stop if it
# is not.
#
# Mirrors the five loaders (test/support/capture.ts and siblings); kept in step
# with them by e2e/README.md's contract section.
echo
echo "=== preflight: is the capture usable? ==="
node - "$repo_root" <<'PREFLIGHT'
const fs = require("node:fs");
const path = require("node:path");

const root = process.argv[2];
const file = process.env.CRU_IAP_E2E_CAPTURE || path.join(root, "e2e/okta/capture.json");

const die = (why) => {
  console.error(`unusable capture: ${why}`);
  process.exit(1);
};

if (!fs.existsSync(file)) die(`no artifact at ${file}`);

let capture;
try {
  capture = JSON.parse(fs.readFileSync(file, "utf8"));
} catch (error) {
  die(`${file} is not readable JSON: ${error.message}`);
}

if (!capture.assertion || !capture.claims) die(`${file} has no assertion/claims`);

const exp = Number(capture.claims.exp);
const now = Math.floor(Date.now() / 1000);
if (!Number.isFinite(exp)) die(`${file} has no numeric exp claim`);
if (exp <= now + 30) die(`the assertion expired ${now - exp}s ago — re-run without --no-capture`);

if (!(process.env.CRU_IAP_E2E_AUDIENCE || capture.audience)) {
  die(
    'no audience. Set CRU_IAP_E2E_AUDIENCE, or re-capture with\n' +
      '  --audience "$(cd e2e/terraform && terraform output -raw iap_audience)"',
  );
}
if (!(process.env.CRU_IAP_E2E_EMAIL || capture.expected_email)) {
  die("no expected email. Set CRU_IAP_E2E_EMAIL or re-run the capture script");
}

console.log(`  ok   assertion valid for a further ${exp - now}s`);
console.log(`  ok   audience and expected email resolved`);
PREFLIGHT

declare -a names=() outcomes=()
run() {
  local name="$1"; shift
  echo
  echo "=== $name ==="
  if "$@"; then
    names+=("$name"); outcomes+=("pass")
  else
    names+=("$name"); outcomes+=("FAIL")
  fi
}

# `|| true` is deliberately absent: run() already captures the status, and
# set -e must not abort the remaining suites.
set +e
selected ruby   && run "Ruby"       bundle exec rake e2e
selected python && run "Python"     uv run --frozen pytest -m e2e
# -count=1 disables Go's test cache. Without it a re-run against a FRESH
# capture replays the previous run's verdict — including a skip from when there
# was no stack, reported as a pass.
selected go     && run "Go"         go test -tags e2e -count=1 -run TestLive ./cruiap/...
selected ts     && run "TypeScript" npm run test:e2e
selected rust   && run "Rust"       cargo test --manifest-path rust/Cargo.toml --features e2e --test live_iap
set -e

echo
echo "=== summary ==="
failed=0
for i in "${!names[@]}"; do
  printf '  %-11s %s\n' "${names[$i]}" "${outcomes[$i]}"
  [[ "${outcomes[$i]}" == "FAIL" ]] && failed=1
done

exit "$failed"
