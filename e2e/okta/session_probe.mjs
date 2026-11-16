// Probes whether workforce_identity.iam_principal can tell a fresh trip through
// Okta from a replay of the Google pool session. It only means anything when the
// pool provider appends an Okta-issued timestamp to google.subject; see
// e2e/research/wif-session-id.md for that mapping and for the results.
//
//   node session_probe.mjs replay  --url https://host
//   node session_probe.mjs revoke  --url https://host --pool <pool id> --account <gcloud account>
//   node session_probe.mjs two-app --url https://host --url2 https://host2
//
//   [--user <email>]   default outputs.json test_user_email
//   [--secrets <path>] default ./secrets.json (test_user_password, totp_shared_secret)
//
// replay:  fresh sign-in; clear the IAP cookie (Google session replays); drop the
//          Google cookies (silent Okta SSO); Okta sign-out (password again).
// revoke:  fresh sign-in; revokeSessions on that subject; revisit twice.
// two-app: sign in to --url, then visit --url2 in the same browser.
//
// The target must be the echoserver image, which echoes the injected assertion.

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { totp, msUntilNextStep } from "./totp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const mode = args[0];
const opt = (k, d) => (args.includes(k) ? args[args.indexOf(k) + 1] : d);
const origin = (u) => (u ? new URL(u).origin : u);

const URL1 = origin(opt("--url", process.env.CRU_IAP_E2E_URL));
const URL2 = origin(opt("--url2"));
const outputs = JSON.parse(readFileSync(join(here, "outputs.json"), "utf8"));
const secrets = JSON.parse(readFileSync(opt("--secrets", join(here, "secrets.json")), "utf8"));
const USER = opt("--user", outputs.test_user_email);
const OKTA = outputs.okta_org_url.replace(/\/$/, "");

if (!["replay", "revoke", "two-app"].includes(mode) || !URL1 || (mode === "two-app" && !URL2)) {
  console.error("usage: session_probe.mjs replay|revoke|two-app --url https://host [--url2 https://host2]");
  process.exit(2);
}

const browser = await chromium.launch({ headless: !args.includes("--headed") });
const ctx = await browser.newContext();
const page = await ctx.newPage();

// Counted per visit: which layers answered.
let n;
const reset = () => (n = { chooser: 0, okta: 0, password: 0, totp: 0, authenticating: 0 });
reset();
page.on("request", (req) => {
  if (req.resourceType() !== "document" || req.frame() !== page.mainFrame()) return;
  const u = req.url();
  if (u.startsWith(OKTA)) n.okta++;
  if (u.includes("gcp-iap-mode=AUTHENTICATING")) n.authenticating++;
});

const safe = async (fn, fb = null) => { try { return await fn(); } catch { return fb; } };

const visit = async (host, label, deadlineMs = 90_000) => {
  reset();
  await page.goto(`${host}/?probe=${label}`, { waitUntil: "commit" }).catch(() => {});
  const deadline = Date.now() + deadlineMs;
  let used = null;
  while (Date.now() < deadline) {
    const u = page.url();
    const txt = u.startsWith(host) ? await safe(() => page.evaluate(() => document.body?.innerText ?? ""), "") : "";
    const m = txt.match(/x-goog-iap-jwt-assertion=([\w.-]+)/);
    if (m) {
      const claims = JSON.parse(Buffer.from(m[1].split(".")[1], "base64url"));
      const hdr = (txt.match(/x-goog-authenticated-user-email=(\S+)/) || [])[1];
      console.log(`[${label}] ${JSON.stringify(n)}`);
      console.log(`    iam_principal=${claims.workforce_identity?.iam_principal}`);
      console.log(`    email=${claims.email} iat=${claims.iat} aud=${claims.aud} user-email-header=${hdr}`);
      return claims;
    }
    // After a revoke, Google shows its account chooser instead of auto-selecting.
    if (u.includes("auth.cloud.google/select-session")) {
      const acct = await safe(() => page.$(`text=${USER} (`));
      if (acct) { n.chooser++; await safe(() => acct.click()); await page.waitForTimeout(1500); continue; }
    }
    if (u.startsWith(OKTA)) {
      const id = await safe(() => page.$('input[name="identifier"]:visible'));
      const pw = await safe(() => page.$('input[type="password"]:visible'));
      const code = await safe(() => page.$('input[name="credentials.passcode"]:not([type="password"]):visible, input[name="credentials.totp"]:visible, input[autocomplete="one-time-code"]:visible'));
      const submit = async () => { const b = await safe(() => page.$('input[type="submit"], button[type="submit"]')); if (b) await safe(() => b.click()); };
      if (id) { await safe(() => id.fill(USER)); await submit(); }
      else if (pw) { n.password++; await safe(() => pw.fill(secrets.test_user_password)); await submit(); }
      else if (code) {
        let c = totp(secrets.totp_shared_secret);
        if (c === used || msUntilNextStep() < 4000) { await page.waitForTimeout(msUntilNextStep() + 750); c = totp(secrets.totp_shared_secret); }
        used = c; n.totp++; await safe(() => code.fill(c)); await submit();
      } else {
        const pick = await safe(() => page.$('[data-se="google_otp"] a, [data-se="google_otp"] button, a:has-text("Select")'));
        if (pick) await safe(() => pick.click());
      }
    }
    await page.waitForTimeout(700);
  }
  console.log(`[${label}] FAILED at ${page.url().slice(0, 120)}`);
  console.log((await safe(() => page.evaluate(() => document.body.innerText), "")).slice(0, 600));
  return null;
};

const clearIap = async (host) => {
  await page.goto(`${host}/?gcp-iap-mode=CLEAR_LOGIN_COOKIE`, { waitUntil: "load" }).catch(() => {});
  await ctx.clearCookies({ domain: new URL(host).host });
};
const dropGoogleSession = async () => {
  for (const d of ["auth.cloud.google", ".auth.cloud.google", ".cloud.google"]) await ctx.clearCookies({ domain: d });
};
const sub = (c) => c?.workforce_identity?.iam_principal;
const check = (label, ok) => console.log(`${ok ? "PASS" : "FAIL"} ${label}`);

if (mode === "replay") {
  const fresh = await visit(URL1, "1-fresh");
  await clearIap(URL1);
  const replay = await visit(URL1, "2-replay-google-session");
  await clearIap(URL1); await dropGoogleSession();
  const sso = await visit(URL1, "3-silent-okta-sso");
  await page.goto(`${OKTA}/login/signout`, { waitUntil: "load" }).catch(() => {});
  await clearIap(URL1); await dropGoogleSession();
  const password = await visit(URL1, "4-after-okta-signout");
  console.log();
  check("Google-session replay keeps the subject", !!replay && sub(fresh) === sub(replay));
  check("silent Okta SSO changes the subject", !!sso && sub(replay) !== sub(sso));
  check("fresh password changes the subject", !!password && sub(sso) !== sub(password));
}

if (mode === "revoke") {
  const pool = opt("--pool"), account = opt("--account");
  if (!pool || !account) { console.error("revoke needs --pool and --account"); process.exit(2); }
  const fresh = await visit(URL1, "1-fresh");
  const subject = encodeURIComponent(sub(fresh).split("/subject/")[1]);
  const token = execFileSync("gcloud", ["auth", "print-access-token", `--account=${account}`]).toString().trim();
  const out = execFileSync("curl", ["-sS", "-X", "POST", "-H", `Authorization: Bearer ${token}`, "-H", "Content-Type: application/json", "-d", "{}",
    `https://iam.googleapis.com/v1/locations/global/workforcePools/${pool}/subjects/${subject}:revokeSessions`]).toString();
  console.log(`revokeSessions ${subject} -> ${out.replace(/\s+/g, " ").slice(0, 200)}`);
  await page.waitForTimeout(10_000);
  await clearIap(URL1);
  const after = await visit(URL1, "2-after-revoke");
  await clearIap(URL1);
  const replay = await visit(URL1, "3-replay-after-revoke");
  const later = await visit(URL1, "4-plain-revisit");
  console.log();
  check("revoke forces a new subject", !!after && sub(after) !== sub(fresh));
  check("the new subject replays normally", !!replay && sub(replay) === sub(after));
  check("no lockout on a later visit", !!later);
}

if (mode === "two-app") {
  const one = await visit(URL1, "app1-fresh");
  const two = await visit(URL2, "app2-same-browser");
  console.log();
  check("both apps see the same subject", !!two && sub(one) === sub(two));
}

await browser.close();
