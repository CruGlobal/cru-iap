// Drives a real Okta -> Workforce Identity Federation -> IAP sign-in in a
// headless browser and prints the resulting x-goog-iap-jwt-assertion.
//
// Why a browser rather than the HTTP-only okta_login.py next to this file:
// that script drives the OIDC scratch app, which is a token exchange we can do
// with curl. The workforce pool federates over SAML, and the SAML leg is a
// chain of auto-submitting HTML forms (Okta -> auth.cloud.google -> the IAP
// callback) with state carried in cookies. Reimplementing that by hand is
// exactly the sort of thing a browser already does correctly.
//
// The target service runs gcr.io/google-containers/echoserver:1.10, which
// echoes request headers into the page body, so the assertion IAP injected is
// visible once we are through.
//
//   node capture_assertion.mjs [--headed] [--url https://...]
//                              [--json [path]] [--audience <resource path>]
//
// Credentials come from secrets.json (gitignored) and outputs.json.
//
// --json writes the capture to a file (default e2e/okta/capture.json) so that
// all four language suites can verify ONE login rather than each driving its
// own browser: four captures would be ~12 minutes and four independent chances
// to flake. See e2e/README.md.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { totp, msUntilNextStep } from "./totp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const read = (f) => JSON.parse(readFileSync(join(here, f), "utf8"));

const secrets = read("secrets.json");
const outputs = read("outputs.json");

const args = process.argv.slice(2);
const headed = args.includes("--headed");
const urlArg = args.indexOf("--url");
const TARGET =
  urlArg !== -1
    ? args[urlArg + 1]
    : "https://cru-iap-wif.matt-sandbox.ustech.app/?login=true";

// --json, --json <path>, or absent.
const jsonArg = args.indexOf("--json");
const jsonNext = jsonArg === -1 ? null : args[jsonArg + 1];
const JSON_PATH =
  jsonArg === -1
    ? null
    : jsonNext && !jsonNext.startsWith("--")
      ? jsonNext
      : join(here, "capture.json");

// The audience is CONFIGURATION, not something to read off the token. Deriving
// it from the `aud` claim would make every suite's positive verify vacuous —
// the check would be "does aud equal aud". Comes from `terraform output
// iap_audience`; recorded as null when unknown, and each suite then falls back
// to its own env var / default.
const audienceArg = args.indexOf("--audience");
const AUDIENCE =
  audienceArg !== -1
    ? args[audienceArg + 1]
    : (process.env["CRU_IAP_E2E_AUDIENCE"] ?? null);

const USERNAME = outputs.test_user_email ?? outputs.test_user?.email;
const PASSWORD = secrets.test_user_password;
const SECRET_TOTP = secrets.totp_shared_secret;
if (!USERNAME || !PASSWORD) {
  console.error("missing test user email/password in outputs.json / secrets.json");
  process.exit(2);
}
if (!SECRET_TOTP) {
  console.error("no totp_shared_secret in secrets.json — run: OTKA_TOKEN=... node enroll_totp.mjs");
  process.exit(2);
}

const browser = await chromium.launch({ headless: !headed });
const page = await browser.newPage();
const trail = [];
page.on("framenavigated", (f) => {
  if (f === page.mainFrame()) trail.push(f.url().split("?")[0]);
});

const fail = async (why) => {
  console.error(`\nFAILED: ${why}`);
  console.error(`current url: ${page.url()}`);
  console.error(`navigation trail:\n  ${trail.join("\n  ")}`);
  const shot = join(here, "capture-failure.png");
  await page.screenshot({ path: shot, fullPage: true }).catch(() => {});
  console.error(`screenshot: ${shot}`);
  await browser.close();
  process.exit(1);
};

try {
  await page.goto(TARGET, { waitUntil: "domcontentloaded", timeout: 60_000 });

  // Okta's sign-in widget. Identifier-first, so username and password are two
  // steps; the password field may or may not already be on the page.
  await page.waitForSelector('input[name="identifier"], input[name="username"]', {
    timeout: 60_000,
  });
  const userField = (await page.$('input[name="identifier"]')) ?? (await page.$('input[name="username"]'));
  await userField.fill(USERNAME);

  const next = await page.$('input[type="submit"], button[type="submit"]');
  if (next) await next.click();

  // Okta Identity Engine decides the order of factors itself, and it changes
  // with the user's enrolled authenticators: with a TOTP factor present this
  // org goes identifier -> code and never asks for the password at all. So
  // rather than a fixed sequence, loop over whatever screen is in front of us
  // until we land on the app.
  //
  // The Keep-Zero POC app inherits an access policy requiring 2FA, and that
  // policy is shared with real users — so rather than weaken it, the scratch
  // user has its own software TOTP factor (see enroll_totp.mjs).
  const CODE_FIELD =
    'input[name="credentials.totp"], input[name="credentials.passcode"], input[name="answer"], input[autocomplete="one-time-code"]';
  // Every one of these screens can navigate out from under us mid-query --
  // the SAML leg is a chain of auto-submitting forms. A destroyed execution
  // context just means "the page moved on"; re-loop rather than crash.
  const safe = async (fn, fallback = null) => {
    try {
      return await fn();
    } catch (e) {
      if (/Execution context was destroyed|Target closed|navigation/i.test(e.message)) return fallback;
      throw e;
    }
  };

  const submit = async () => {
    const b =
      (await safe(() => page.$('input[type="submit"]'))) ??
      (await safe(() => page.$('button[type="submit"]'))) ??
      (await safe(() => page.$('button:has-text("Verify")'))) ??
      (await safe(() => page.$('button:has-text("Next")')));
    if (b) await safe(() => b.click());
  };

  const deadline = Date.now() + 120_000;
  let lastStep = "";
  let usedCode = null;
  while (Date.now() < deadline) {
    if (/matt-sandbox\.ustech\.app/.test(page.url())) break;

    if (await safe(() => page.$("text=/Set up security methods/i"))) {
      await fail(
        "Okta is demanding MFA *enrollment*, not a challenge — the scratch user has no active " +
          "factor. Run: OTKA_TOKEN=... node enroll_totp.mjs"
      );
    }

    const pw = await safe(() => page.$('input[type="password"]:visible'));
    const code = await safe(() => page.$(CODE_FIELD));

    if (pw) {
      lastStep = "password";
      await safe(() => pw.fill(PASSWORD));
      await submit();
    } else if (code && (await safe(() => code.isVisible(), false))) {
      lastStep = "totp";
      // Never resend a passcode Okta already consumed — wait out the window.
      const fresh = totp(SECRET_TOTP);
      if (fresh === usedCode) {
        await page.waitForTimeout(msUntilNextStep() + 750);
      }
      const wait = msUntilNextStep();
      if (wait < 5_000) await page.waitForTimeout(wait + 750);
      usedCode = totp(SECRET_TOTP);
      await safe(() => code.fill(usedCode));
      await submit();
    } else {
      // An authenticator chooser, or a page still settling.
      const pick =
        (await safe(() => page.$('[data-se="okta_verify"] a, [data-se="okta_verify"] button'))) ??
        (await safe(() => page.$('[data-se="google_otp"] a, [data-se="google_otp"] button'))) ??
        (await safe(() => page.$('a:has-text("Select"), button:has-text("Select")')));
      if (pick) {
        lastStep = "chooser";
        await safe(() => pick.click());
      }
    }
    await page.waitForTimeout(1500);
  }

  if (!/matt-sandbox\.ustech\.app/.test(page.url())) {
    await fail(`auth loop timed out; last step handled = ${lastStep || "none"}`);
  }
  await page.waitForLoadState("domcontentloaded");
} catch (e) {
  await fail(e.message);
}

const body = await page.content();
const text = await page.evaluate(() => document.body.innerText);

const m = text.match(/x-goog-iap-jwt-assertion=([A-Za-z0-9._-]+)/);
if (!m) {
  if (/Sign in|password/i.test(text)) await fail("still on a sign-in page — auth did not complete");
  await fail(
    "reached the app but found no x-goog-iap-jwt-assertion in the echoed headers. " +
      "Is the service still running echoserver?"
  );
}

const jwt = m[1];
const claims = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());

console.log("=== navigation trail ===");
console.log("  " + trail.join("\n  "));
console.log("\n=== decoded claims (signature NOT checked here — that is the gem's job) ===");
console.log(JSON.stringify(claims, null, 2));
console.log("\n=== assertion ===");
console.log(jwt);

// Also surface the two headers IAP sets alongside the JWT, since their prefix
// shapes are part of what the gem's docs claim.
const iapHeaders = {};
for (const h of ["x-goog-authenticated-user-email", "x-goog-authenticated-user-id"]) {
  const hm = text.match(new RegExp(`${h}=([^\\s]+)`));
  if (hm) {
    console.log(`${h}=${hm[1]}`);
    iapHeaders[h] = hm[1];
  }
}

if (JSON_PATH) {
  writeFileSync(
    JSON_PATH,
    JSON.stringify(
      {
        // Seconds, to match the JWT's own units and every language's clock.
        captured_at: Math.floor(Date.now() / 1000),
        url: TARGET,
        assertion: jwt,
        claims,
        audience: AUDIENCE,
        expected_email: USERNAME,
        iap_headers: iapHeaders,
        navigation_trail: trail,
      },
      null,
      2,
    ) + "\n",
    // The assertion is a live credential for ~10 minutes. Same posture as
    // secrets.json next to it.
    { mode: 0o600 },
  );
  console.log(`\nwrote ${JSON_PATH}`);
}

await browser.close();
