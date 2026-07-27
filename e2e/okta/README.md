# Scratch Okta OIDC app for cru-iap e2e

Disposable Okta objects backing a real Okta-federated login into a sandbox Google
Cloud **workforce identity pool**. Everything here is throwaway. If you are reading
this and don't know why it exists, it should probably be deleted — see
[Teardown](#teardown).

Created 2026-07-25. **Torn down 2026-07-27** — every object listed below has been
deleted, verified by the queries under [Teardown](#teardown). The ids are kept as
a record of what existed; none of them resolve any more. `secrets.json` and
`capture.json` are gone too. Recreate from this document if the e2e is ever
needed again.

## Org

| | |
|---|---|
| Okta org | `https://cru.oktapreview.com` (**preview / sandbox org**, not production `signon.okta.com`) |
| Admin console | `https://cru-admin.oktapreview.com` |
| Issuer | `https://cru.oktapreview.com` (org authorization server, `issuer_mode = ORG_URL`) |
| Discovery | `https://cru.oktapreview.com/.well-known/openid-configuration` |
| JWKS | `https://cru.oktapreview.com/oauth2/v1/keys` |

The **org** authorization server is used deliberately, not the `default` custom
authorization server — the org AS needs no configuration, so nothing shared had to be
touched. Its discovery document is public and is what Google's workforce pool provider
consumes.

## Objects created

Every object below was created by this exercise and is safe to delete. Nothing
pre-existing was modified.

| Object | ID | Notes |
|---|---|---|
| OIDC app | `0oa2sr4z1rqhbB3Go0h8` | label `ZZ TEMP cru-iap e2e (delete me)`; also the client id |
| App client secret | `ocs2sr4z1t9Zx0SV10h8` | value in `secrets.json` (gitignored) |
| App scope grant (`openid`) | `oag479511u2PzwxXu0h7` | see [Scopes](#scopes) |
| App sign-on policy | `rst2sr4to4fCkAGMI0h8` | ACCESS_POLICY `ZZ TEMP cru-iap e2e (delete me)` |
| ↳ its catch-all rule | `rul2sr4to4gQb4RzB0h8` | edited to 1FA / password-only |
| ↳ policy→app mapping | `rsm2sr53l0dqnJiwj0h8` | |
| Test user | `00u2sr49f3tpmox7b0h8` | `cru-iap-e2e-test@example.invalid`, status ACTIVE |
| App assignment | (user↔app) | direct `USER`-scope assignment, no group created |

No Okta group was created — the user is assigned to the app directly.

### Why a dedicated app sign-on policy

The org's **Default policy** (`rst26s6zdab6iWUxb0h8`) catch-all rule requires 2FA
(a possession factor), which would block a scripted headless login. Rather than
weaken that shared policy, a brand-new ACCESS_POLICY was created for this app alone
and the app was mapped to it. The org's global session policy already allows
password-only primary auth (`requireFactor: false`), and the MFA-enrollment policies
all use `enroll: self: CHALLENGE` (enroll on demand, not at login), so no enrollment
prompt blocks the flow.

## Google workforce pool wiring

The redirect URI is baked into the Okta app, so terraform **must** use these exact
ids:

| | |
|---|---|
| pool id | `cru-iap-e2e` |
| provider id | `okta` |
| location | `global` |
| redirect URI | `https://auth.cloud.google/signin-callback/locations/global/workforcePools/cru-iap-e2e/providers/okta` |

Provider config:

```hcl
oidc {
  issuer_uri = "https://cru.oktapreview.com"
  client_id  = "0oa2sr4z1rqhbB3Go0h8"

  client_secret {
    value {
      plain_text = var.okta_client_secret # from e2e/okta/secrets.json
    }
  }

  web_sso_config {
    response_type            = "CODE"
    assertion_claims_behavior = "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS"
    additional_scopes        = ["email", "profile"]
  }
}

attribute_mapping = {
  "google.subject"      = "assertion.subject"
  "google.email"        = "assertion.attributes['email'][0]"
  "google.display_name" = "assertion.attributes['name'][0]"
}
```

`additional_scopes = ["email", "profile"]` matters: with `openid` alone Okta's org
authorization server does **not** put `email` in the ID token, and `google.email`
would fail to map — which is the exact failure mode this exercise exists to
reproduce/verify.

## Scopes

`openid` was granted to the app explicitly (grant `oag479511u2PzwxXu0h7`).
`POST /api/v1/apps/{id}/grants` rejected `profile` and `email` with
`Api validation failed: scopeId` on the org authorization server — this turned out
not to matter: the org AS honours those standard OIDC scopes at authorize time
without an explicit grant object. Verified empirically (below).

## Verified

`okta_login.py` drives the whole flow headlessly — Okta primary auth (password) →
`/oauth2/v1/authorize?...&sessionToken=` → authorization-code exchange — and decodes
the resulting ID token:

```
$ python3 okta_login.py
granted scopes: openid email profile
{
  "sub": "00u2sr49f3tpmox7b0h8",
  "name": "ZZTemp CruIapE2E",
  "email": "cru-iap-e2e-test@example.invalid",
  "iss": "https://cru.oktapreview.com",
  "aud": "0oa2sr4z1rqhbB3Go0h8",
  "amr": ["pwd"],
  "preferred_username": "cru-iap-e2e-test@example.invalid",
  ...
}
```

So: **`email` and `name` are confirmed present in the real ID token**, and the login
completes with password only (`amr: ["pwd"]`) — no MFA, no forced password change.

## Files

| File | |
|---|---|
| `outputs.json` | non-secret ids and URLs; consume this from terraform |
| `secrets.json` | client secret + test user password — **gitignored**, mode 0600 |
| `okta_login.py` | headless login driver / ID-token verifier |

## Teardown

Requires an Okta API token for `cru.oktapreview.com` with app + user admin rights.
Run in this order. `$T` is the API token.

```bash
ORG=https://cru.oktapreview.com
APP=0oa2sr4z1rqhbB3Go0h8
USER=00u2sr49f3tpmox7b0h8
POLICY=rst2sr4to4fCkAGMI0h8
auth=(-H "Authorization: SSWS $T" -H 'Accept: application/json')

# 1. unassign the test user from the app
curl -sS "${auth[@]}" -X DELETE "$ORG/api/v1/apps/$APP/users/$USER"

# 2. deactivate then delete the app (delete 404s while the app is ACTIVE)
curl -sS "${auth[@]}" -X POST   "$ORG/api/v1/apps/$APP/lifecycle/deactivate"
curl -sS "${auth[@]}" -X DELETE "$ORG/api/v1/apps/$APP"
#    (this also removes the client secret, the openid grant, and the policy mapping)

# 3. delete the scratch app sign-on policy (only after the app is gone)
curl -sS "${auth[@]}" -X DELETE "$ORG/api/v1/policies/$POLICY"

# 4. deactivate then delete the test user (two DELETEs is the documented flow)
curl -sS "${auth[@]}" -X POST   "$ORG/api/v1/users/$USER/lifecycle/deactivate"
curl -sS "${auth[@]}" -X DELETE "$ORG/api/v1/users/$USER"

# 5. local — only the untracked credential files. Do NOT `rm -rf` this whole
#    directory: the scripts in it are committed, and the terraform README points
#    at probe_denied.mjs as the reproducible access-denied probe.
rm -f secrets.json capture.json
```

Verify nothing is left:

```bash
curl -sS "${auth[@]}" "$ORG/api/v1/apps?q=ZZ+TEMP+cru-iap"        # expect []
curl -sS "${auth[@]}" "$ORG/api/v1/users?q=cru-iap-e2e-test"      # expect []
curl -sS "${auth[@]}" "$ORG/api/v1/policies?type=ACCESS_POLICY" \
  | grep -o 'ZZ TEMP cru-iap e2e' || echo "policy gone"
```

### Console equivalent

1. **Applications → Applications** → `ZZ TEMP cru-iap e2e (delete me)` → *Assignments*
   tab, remove the user → *General* tab → **Deactivate** → **Delete**.
2. **Security → Authentication policies** → `ZZ TEMP cru-iap e2e (delete me)` →
   **Delete** (the policy must have no apps mapped to it).
3. **Directory → People** → search `cru-iap-e2e-test` → **Deactivate**, then
   **Delete**.

Also delete the Google workforce pool provider `okta` and pool `cru-iap-e2e` — a
workforce pool goes into a 30-day soft-delete, so `gcloud iam workforce-pools delete`
leaves a tombstone that blocks reuse of the id until it is undeleted or purged.

## Guardrails observed

- Only the objects listed above were created. **No pre-existing Okta object was
  modified, deactivated, or deleted** — no existing app, user, group, policy,
  authorization server, IdP, or org setting.
- The org-wide Default access policy was **not** edited; a dedicated policy was
  created instead. Same reasoning for using the org authorization server rather than
  configuring the shared `default` custom authorization server.
- Work was done in the **preview** org (`cru.oktapreview.com`), not production
  (`signon.okta.com`).

## Addition 2026-07-25: assignment on the SHARED app

To test the shared org-wide workforce pool (`cru-workforce-preview`) rather than a
dedicated one, the scratch test user was assigned **directly** to the pre-existing,
Terraform-managed shared SAML app:

| | |
|---|---|
| App | `Google Cloud Workforce (Shared)` — `0oa2smcngd9xM71eo0h8` |
| User | `cru-iap-e2e-test@example.invalid` — `00u2sr49f3tpmox7b0h8` |
| Scope | `USER` (direct), not a group |

This app had **zero** user and zero group assignments beforehand (recorded before the
change), so nothing pre-existing was displaced.

**Removed 2026-07-27**, verified — the app now holds only its intended assignments:

```
DELETE /api/v1/apps/0oa2smcngd9xM71eo0h8/users/00u2sr49f3tpmox7b0h8   # 204
```

Note the "zero assignments" line above is a snapshot of 2026-07-25 and is no longer
true: the shared workforce rollout has since populated the app with real users. That
is intended and unrelated to this scratch setup — do not read a populated app as
drift.

Do NOT deactivate or delete app `0oa2smcngd9xM71eo0h8` itself — it is a shared,
Terraform-managed object and is not ours.
