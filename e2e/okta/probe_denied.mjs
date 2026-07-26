// Signs in as the scratch user and reports exactly where IAP sends them.
//
// The point is the AUTHORIZATION failure path: run this while the user is
// assigned to the Okta app (so sign-in succeeds) but holds NO
// roles/iap.httpsResourceAccessor binding (so IAP then refuses). That is the
// "authenticated, but not in the right Okta group" case, and it is what
// applicationSettings.accessDeniedPageSettings.accessDeniedPageUri governs.
//
// Sibling of capture_assertion.mjs, which drives the same login but expects to
// land ON the app. This one expects not to, and prints the redirect chain plus
// what a JSON-shaped request gets, since IAP treats both identically.
//
//   node probe_denied.mjs [url]
//
// Setup and findings: ../terraform/README.md, "Access-denied page".
// NB IAP IAM changes take well over five minutes to propagate -- an immediate
// run after revoking the binding will sail straight through to the app.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { totp, msUntilNextStep } from "./totp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const read = (f) => JSON.parse(readFileSync(join(here, f), "utf8"));
const secrets = read("secrets.json");
const outputs = read("outputs.json");
const TARGET = process.argv[2] ?? "https://cru-iap-wif.matt-sandbox.ustech.app/?login=true";
const USERNAME = outputs.test_user_email ?? outputs.test_user?.email;

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const trail = [];
page.on("framenavigated", (f) => { if (f === page.mainFrame()) trail.push(f.url()); });
const responses = [];
page.on("response", (r) => {
  if ([301,302,303,307,308].includes(r.status())) responses.push(`${r.status()} ${r.url()}\n      -> ${r.headers()["location"]}`);
});

const safe = async (fn, fb=null) => { try { return await fn(); } catch (e) { if (/destroyed|Target closed|navigation/i.test(e.message)) return fb; throw e; } };
const submit = async () => {
  const b = (await safe(() => page.$('input[type="submit"]'))) ?? (await safe(() => page.$('button[type="submit"]')))
    ?? (await safe(() => page.$('button:has-text("Verify")'))) ?? (await safe(() => page.$('button:has-text("Next")')));
  if (b) await safe(() => b.click());
};

await page.goto(TARGET, { waitUntil: "domcontentloaded", timeout: 60_000 });
await page.waitForSelector('input[name="identifier"], input[name="username"]', { timeout: 60_000 });
const uf = (await page.$('input[name="identifier"]')) ?? (await page.$('input[name="username"]'));
await uf.fill(USERNAME);
await submit();

const CODE = 'input[name="credentials.totp"], input[name="credentials.passcode"], input[name="answer"], input[autocomplete="one-time-code"]';
const deadline = Date.now() + 120_000;
let usedCode = null;
while (Date.now() < deadline) {
  if (!/oktapreview\.com/.test(page.url())) break;
  const pw = await safe(() => page.$('input[type="password"]:visible'));
  const code = await safe(() => page.$(CODE));
  if (pw) { await safe(() => pw.fill(secrets.test_user_password)); await submit(); }
  else if (code && (await safe(() => code.isVisible(), false))) {
    if (totp(secrets.totp_shared_secret) === usedCode) await page.waitForTimeout(msUntilNextStep() + 750);
    const w = msUntilNextStep(); if (w < 5000) await page.waitForTimeout(w + 750);
    usedCode = totp(secrets.totp_shared_secret);
    await safe(() => code.fill(usedCode)); await submit();
  }
  await page.waitForTimeout(1500);
}
await page.waitForTimeout(6000);

const trim = (u) => (u ?? "").replace(/([?&](state|code_challenge|continueUrl|scope|redirect_uri)=)[^&]{40,}/g, "$1<...>");
console.log("=== last 4 redirects ===");
responses.slice(-4).forEach((r) => console.log("  " + trim(r)));
console.log("\n=== last 4 navigations ===");
trail.slice(-4).forEach((u) => console.log("  " + trim(u)));
console.log("\n=== final url ===\n  " + trim(page.url()));

// What does a NON-browser request get? Same session cookies, but shaped like
// an XHR/API call -- which is what a SPA or a fetch() from the app would send.
for (const accept of ["application/json", "text/html"]) {
  const r = await page.request.get(TARGET, { headers: { accept }, maxRedirects: 0 });
  console.log(`\n=== Accept: ${accept} ===`);
  console.log(`  status ${r.status()}`);
  console.log(`  location ${trim(r.headers()["location"]) ?? "(none)"}`);
  const body = (await r.text()).slice(0, 300).replace(/\s+/g, " ");
  console.log(`  body ${body}`);
}
console.log("\n=== page text (first 1200 chars) ===");
console.log((await page.evaluate(() => document.body.innerText)).slice(0, 1200));
await browser.close();
