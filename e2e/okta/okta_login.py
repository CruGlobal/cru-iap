#!/usr/bin/env python3
"""Headless Okta login for the scratch cru-iap e2e OIDC app.

Drives Okta primary auth (password only) -> /oauth2/v1/authorize with a
sessionToken -> authorization-code exchange, and prints the ID token claims.
This proves the `email` claim Google's workforce pool maps to google.email.

Reads client id / secret / test-user password from secrets.json (gitignored).

  python3 okta_login.py            # print ID token claims
  python3 okta_login.py --raw      # also print the raw id_token (careful)
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUTS = json.load(open(os.path.join(HERE, "outputs.json")))
SECRETS = json.load(open(os.path.join(HERE, "secrets.json")))

ORG = OUTPUTS["okta_org_url"]
CLIENT_ID = OUTPUTS["client_id"]
REDIRECT = OUTPUTS["redirect_uri"]
LOGIN = OUTPUTS["test_user_login"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _request(url, data=None, headers=None, follow=True):
    hdrs = {"Accept": "application/json", "Content-Type": "application/json"}
    hdrs.update(headers or {})
    body = json.dumps(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=hdrs)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req)
        return resp.getcode(), dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode()


def main():
    # 1. primary authentication -> one-time sessionToken
    status, _, body = _request(
        f"{ORG}/api/v1/authn",
        {"username": LOGIN, "password": SECRETS["test_user_password"]},
    )
    authn = json.loads(body)
    if authn.get("status") != "SUCCESS":
        sys.exit(f"primary auth failed ({status}): {json.dumps(authn)[:500]}")
    session_token = authn["sessionToken"]

    # 2. authorization request -> code (redirect is never followed; Google's
    #    callback host is not reachable and does not need to be)
    query = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "response_mode": "query",
            "scope": "openid email profile",
            "redirect_uri": REDIRECT,
            "state": "cru-iap-e2e",
            "nonce": "cru-iap-e2e-nonce",
            "sessionToken": session_token,
        }
    )
    status, headers, body = _request(f"{ORG}/oauth2/v1/authorize?{query}", follow=False)
    location = next((v for k, v in headers.items() if k.lower() == "location"), "")
    if "code=" not in location:
        sys.exit(f"authorize failed ({status}): {location or body[:500]}")
    auth_code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]

    # 3. token exchange (client_secret_basic)
    basic = base64.b64encode(
        f"{CLIENT_ID}:{SECRETS['client_secret']}".encode()
    ).decode()
    form = urllib.parse.urlencode(
        {"grant_type": "authorization_code", "code": auth_code, "redirect_uri": REDIRECT}
    ).encode()
    status, _, body = _request(
        f"{ORG}/oauth2/v1/token",
        form,
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    tokens = json.loads(body)
    if "id_token" not in tokens:
        sys.exit(f"token exchange failed ({status}): {json.dumps(tokens)[:500]}")

    payload = tokens["id_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))

    print("granted scopes:", tokens.get("scope"))
    print(json.dumps(claims, indent=2))
    if "--raw" in sys.argv:
        print("\nid_token:", tokens["id_token"])
    if "email" not in claims:
        sys.exit("FAIL: no email claim in ID token")


if __name__ == "__main__":
    main()
