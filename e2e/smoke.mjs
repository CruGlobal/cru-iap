// Secret-free, browser-free smoke checks. Node stdlib only, no npm install.
//
//   node e2e/smoke.mjs jwks
//   node e2e/smoke.mjs iap-front --url https://host/ [--provider <substring>]
//
// Two checks, deliberately separate because they have very different
// prerequisites:
//
//   jwks       Google's IAP key endpoint. Needs nothing but egress, so it runs
//              on every PR. This is the one external contract all four
//              libraries depend on — if Google moves the endpoint or switches
//              curves, every one of them breaks at once and no offline suite
//              notices. Cheapest high-value check in the repo.
//
//   iap-front  That a given host really is behind IAP. Needs a standing stack,
//              so it belongs in the e2e job right after `terraform apply` —
//              NOT on PRs, since the e2e stack is created on demand and torn
//              down again (see e2e/terraform/README.md).
//
// The JWKS URL is written out as a literal here rather than imported from
// src/. That is the point: the libraries' constant is the thing under test, so
// this file holds an independent copy to check it against.

const IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";

const args = process.argv.slice(2);
const command = args[0];
const flag = (name, fallback = null) => {
  const at = args.indexOf(`--${name}`);
  return at === -1 ? fallback : args[at + 1];
};

const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};

/**
 * The JWKS check gates every PR, so a transient blip must not read as a broken
 * contract. Retry the fetch; never retry an assertion about its content.
 */
const fetchWithRetry = async (url, init = {}, attempts = 3) => {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        const backoff = 1000 * 2 ** (attempt - 1);
        console.log(`  ..   fetch failed (${error.message}), retrying in ${backoff}ms`);
        await new Promise((resolve) => setTimeout(resolve, backoff));
      }
    }
  }
  throw lastError;
};

const jwks = async () => {
  console.log(`jwks: ${IAP_JWKS_URL}`);
  const response = await fetchWithRetry(IAP_JWKS_URL);
  check("responds 200", response.status === 200, `got ${response.status}`);
  if (response.status !== 200) return;

  const body = await response.json();
  const keys = Array.isArray(body.keys) ? body.keys : [];

  check("has a non-empty keys array", keys.length > 0, `${keys.length} keys`);
  // ES256 / P-256 is why the offline fixtures in all four languages mint EC
  // keys rather than the RSA a generic JWT fixture would reach for. If Google
  // ever adds another curve this fails, and that is the intent: it is a
  // decision for a human, not something to discover from a verify() failure.
  check(
    "every key is EC / P-256",
    keys.length > 0 && keys.every((key) => key.kty === "EC" && key.crv === "P-256"),
    [...new Set(keys.map((key) => `${key.kty}/${key.crv}`))].join(", "),
  );
  check(
    "every key is usable for ES256 verification",
    keys.length > 0 && keys.every((key) => key.kid && key.x && key.y),
    "each needs kid, x, y",
  );
};

const iapFront = async () => {
  const url = flag("url");
  if (!url) {
    console.error("iap-front needs --url https://host/");
    process.exit(2);
  }
  const provider = flag("provider");
  const loginUrl = `${url.replace(/\/$/, "")}/?login=true`;
  console.log(`iap-front: ${loginUrl}`);

  const response = await fetchWithRetry(loginUrl, { redirect: "manual" });
  const location = response.headers.get("location") ?? "";
  // Reported as a fact in both the pass and fail case, so the log never reads
  // as a verdict that contradicts the ok/FAIL column.
  const providerName =
    new URL(location, loginUrl).searchParams.get("provider_name") ?? "(none)";

  check("redirects rather than serving the app", response.status === 302, `status ${response.status}`);
  check(
    "hands off to Google's IAP sign-in",
    location.includes("auth.cloud.google/authorize"),
    location.split("?")[0] || "(no location header)",
  );
  if (provider) {
    check(
      `hands off to the expected workforce provider (${provider})`,
      providerName.includes(provider),
      providerName,
    );
  }

  // A client-supplied assertion header must not buy anything: IAP strips and
  // replaces it. Without this the host could be behind a plain LB that merely
  // forwards whatever the client sent.
  const forged = await fetchWithRetry(loginUrl, {
    redirect: "manual",
    headers: { "x-goog-iap-jwt-assertion": "not.a.real.assertion" },
  });
  check(
    "ignores a client-supplied assertion header and challenges anyway",
    forged.status === 302,
    `status ${forged.status}`,
  );
};

const commands = { jwks, "iap-front": iapFront };

if (!commands[command]) {
  console.error(`usage: node e2e/smoke.mjs <${Object.keys(commands).join("|")}> [options]`);
  process.exit(2);
}

try {
  await commands[command]();
} catch (error) {
  console.error(`\nsmoke check "${command}" could not run: ${error.message}`);
  process.exit(1);
}

const failed = results.filter((result) => !result.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
