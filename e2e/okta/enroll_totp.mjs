// Enrolls a software TOTP factor on the SCRATCH TEST USER ONLY, so the
// headless capture can clear Okta's MFA requirement.
//
// Why this rather than relaxing a policy: the Keep-Zero POC app inherits an
// access policy that requires 2FA, and that policy is shared with real users
// (matt.drees@cru.org is assigned to the same app). Weakening it to let a test
// script through would degrade authentication for someone else. Enrolling a
// factor on our own throwaway user changes nothing for anybody else.
//
// Writes the shared secret into secrets.json (gitignored). Idempotent-ish: if
// the user already has an ACTIVE totp factor it does nothing.
//
//   OKTA_TOKEN=... node enroll_totp.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { totp, msUntilNextStep } from "./totp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const sp = join(here, "secrets.json");
const outputs = JSON.parse(readFileSync(join(here, "outputs.json"), "utf8"));
const secrets = JSON.parse(readFileSync(sp, "utf8"));

const TOKEN = process.env.OKTA_TOKEN;
if (!TOKEN) {
  console.error("OKTA_TOKEN not set — an Okta admin API token with user admin rights");
  process.exit(2);
}
const ORG = outputs.okta_org_url.replace(/\/$/, "");
const USER = outputs.okta_user_id;

const api = async (path, init = {}) => {
  const res = await fetch(`${ORG}/api/v1${path}`, {
    ...init,
    headers: {
      Authorization: `SSWS ${TOKEN}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const body = await res.text();
  let json;
  try {
    json = JSON.parse(body);
  } catch {
    json = body;
  }
  if (!res.ok) throw new Error(`${init.method ?? "GET"} ${path} -> ${res.status}: ${body.slice(0, 400)}`);
  return json;
};

const existing = await api(`/users/${USER}/factors`);
const active = existing.find((f) => f.factorType === "token:software:totp" && f.status === "ACTIVE");
if (active) {
  console.log(`already enrolled: ${active.id} (${active.status})`);
  if (!secrets.totp_shared_secret) {
    console.error("...but secrets.json has no totp_shared_secret. Reset the factor and re-run:");
    console.error(`  curl -X DELETE -H "Authorization: SSWS \\$OKTA_TOKEN" ${ORG}/api/v1/users/${USER}/factors/${active.id}`);
    process.exit(1);
  }
  process.exit(0);
}

console.log("enrolling token:software:totp ...");
const enrolled = await api(`/users/${USER}/factors`, {
  method: "POST",
  body: JSON.stringify({ factorType: "token:software:totp", provider: "OKTA" }),
});

const shared = enrolled._embedded?.activation?.sharedSecret;
if (!shared) throw new Error(`no sharedSecret in enrollment response: ${JSON.stringify(enrolled).slice(0, 400)}`);

// Activate with a freshly generated code. Start of a window, so it does not
// expire mid-request.
const wait = msUntilNextStep();
if (wait < 3000) await new Promise((r) => setTimeout(r, wait + 500));
const code = totp(shared);
const activated = await api(`/users/${USER}/factors/${enrolled.id}/lifecycle/activate`, {
  method: "POST",
  body: JSON.stringify({ passCode: code }),
});

secrets.totp_shared_secret = shared;
secrets.totp_factor_id = activated.id;
writeFileSync(sp, JSON.stringify(secrets, null, 2) + "\n", { mode: 0o600 });

console.log(`factor ${activated.id} status=${activated.status}`);
console.log("shared secret written to secrets.json (gitignored)");
