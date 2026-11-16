# A per-session id in the IAP assertion

Research for [#13](https://github.com/CruGlobal/cru-iap/issues/13), measured live
2026-10-23 on the e2e stack (pool `keepzero-okta-poc`, provider `okta-preview-saml`,
Okta preview app "Keep-Zero POC"). Nothing in the library uses this yet.

## The question

Sign-out can't end the Google pool session (layer 2 in #13). While it lives, IAP
re-signs the browser in without asking Okta. Can the app at least **tell** that replay
apart from a real trip through Okta, so it can refuse the replay?

## What the assertion carries by default: no

- `iat` is the time IAP signed **this request**, not the sign-in. Two requests a second
  apart carry `iat`s a second apart, and `exp` is always `iat + 600`. So
  `x-cru-iap-issued-at` / `issuedAt` says nothing about how fresh the sign-in is.
- There is no `auth_time` under Workforce Identity Federation. (GCIP has
  `gcip.auth_time`; WIF does not.)
- The app never sees the re-sign-in: IAP handles `?gcp-iap-mode=AUTHENTICATING` itself,
  then redirects to the original URL with nothing added.

## The one channel from Okta to the app: `google.subject`

Of the mapped `google.*` attributes, only two reach the assertion:

| Mapping | Lands in |
|---|---|
| `google.email` | `email` |
| `google.subject` | `workforce_identity.iam_principal` (`principal://…/subject/<value>`) |

`google.display_name`, `google.groups` and `attribute.*` don't appear in the assertion.

Okta's expression language has no session id or sign-in time (only `session.amr`). But
an attribute statement can call `Time.now()`, and Okta issues a new SAML assertion each
time Google asks it, with or without a password. A Google-session replay doesn't ask
Okta, so the value stays put.

### Setup

Okta SAML app, extra attribute statement:

| Name | Format | Value |
|---|---|---|
| `okta_issued_at` | Basic | `Time.now("UTC", "yyyyMMddHHmmssSSS")` |

Pool provider mapping (other entries unchanged):

```
google.subject = 'okta_issued_at' in assertion.attributes
                   ? assertion.subject + '#' + assertion.attributes['okta_issued_at'][0]
                   : assertion.subject
```

The subject now changes every session, so IAP access must be granted through
`principalSet://…/attribute.email/<email>` or `…/group/<group>`, not
`principal://…/subject/<email>`.

## Results

`node e2e/okta/session_probe.mjs replay --url <login_url>`, one browser:

| Step | Okta asked | Password | Subject suffix |
|---|---|---|---|
| 1. Fresh sign-in | yes | yes | `#…190144642` |
| 2. Clear the IAP cookie (Google session replays) | **no** | no | `#…190144642` **same** |
| 3. Drop Google cookies, Okta still signed in | yes, silent | no | `#…190150135` new |
| 4. After Okta sign-out | yes | yes | `#…190202359` new |

The suffix changes exactly when the Google session does. The `email` claim and
`x-goog-authenticated-user-email` (`sts.google.com:<email>`) are unchanged.

`two-app`: a second IAP backend on the same pool, same browser, runs its own
`AUTHENTICATING` but gets the **same** subject (Okta not asked). The suffix belongs to
the browser's Google session, not to one app.

`revoke`: `revokeSessions` on the per-session subject ends the Google session. The next
visit goes to Okta (silent SSO), gets a new subject, and IAP keeps working. The
permanent lockout seen on 2026-10-13 is per subject, and the dead subject is never used
again. Side effects: the next sign-in shows Google's account chooser once, and the
chooser shows the raw subject, `#suffix` and all. This is a finding, not a
recommendation.

## What it enables

On sign-out, the app puts the current `iam_principal` on a server-side denylist with a
TTL of the pool `session_duration`, and refuses any request carrying it. A replay is
refused, and clearing cookies doesn't help. A real trip through Okta gets a new subject.
Other browsers and other apps are untouched.

Costs and limits:

- The same browser can't get back into that app until its Google session ends. Nothing
  can force a trip to Okta.
- "New trip through Okta" isn't "typed a password". Step 3 is silent. A promise that the
  next person must type a password still needs the Okta session gone too.
- `google.subject` is capped at 127 bytes: an email up to about 113 bytes still fits.
- Google recommends a stable subject. Everything keyed on the subject (audit logs, the
  account chooser, per-user console state) sees a new principal each session.
- The mapping is per provider, so every app on the pool gets the new subject.

## Reproducing

1. Okta: add the attribute statement above to the pool's SAML app. Make a test user with
   a password and a TOTP factor (`enroll_totp.mjs`), assigned to the app.
2. Patch the provider's `attributeMapping` (REST `PATCH …/providers/<id>?updateMask=attributeMapping`;
   `gcloud --attribute-mapping` splits on the commas inside the CEL).
3. `terraform apply -var-file=wif.tfvars -var 'iap_members=["principalSet://iam.googleapis.com/locations/global/workforcePools/<pool>/attribute.email/<user>"]'`.
4. For `two-app`, a second backend on the same NEG and LB, outside terraform: create the
   backend service with `--iap=enabled`, `gcloud iap settings set` with the same
   `workforce_identity_settings` (pool and OAuth client) as the first, the same
   `principalSet` binding, a second hostname as a url-map path matcher, a managed cert
   for it added to the proxy, and a DNS A record to the same IP. A later
   `terraform apply` reverts the url map and proxy.
5. `node e2e/okta/session_probe.mjs replay|revoke|two-app …` (usage is in the script).

Okta rate-limits TOTP. Back-to-back runs can hit "Too many attempts". Wait about five
minutes.
