/**
 * The two IAP control URLs, which every consumer was re-typing.
 *
 * These are pure string builders — no request, no config, no I/O — because the
 * mistakes they prevent are string mistakes:
 *
 *   - Linking bare `/` for sign-in instead of `/?login=true`. IAP redirects to
 *     the IdP, the IdP redirects back to `/`, and round it goes. An infinite
 *     loop, and the single most-reported IAP footgun at Cru.
 *   - Signing out without `?gcp-iap-mode=CLEAR_LOGIN_COOKIE`. The app's own
 *     session goes away, IAP's federated login cookie does not, and the next
 *     request silently signs the same person straight back in.
 *
 * Both were checklist items in the README, which is to say they were prose that
 * four apps had to re-read correctly. Now they are code.
 *
 * Kept in step with lib/cru_iap/urls.rb, cru_iap/urls.py and cruiap/urls.go by
 * a cross-language test (see cruiap/vocabulary_test.go).
 */

/** Appended to trigger IAP's sign-in redirect. */
export const LOGIN_QUERY = "login=true";

/** Appended to make IAP drop its federated login cookie. */
export const LOGOUT_QUERY = "gcp-iap-mode=CLEAR_LOGIN_COOKIE";

/**
 * Query-string surgery that is easy to get wrong by hand, which is the reason
 * this exists rather than an interpolated template at each call site:
 *
 *   - a fragment must stay LAST — `"/a#b"` with `"?login=true"` appended
 *     naively yields `"/a#b?login=true"`, where the param is part of the
 *     fragment and never reaches the server at all
 *   - the separator depends on whether a query is already present
 *   - idempotent, so `loginUrl(loginUrl(x)) === loginUrl(x)`
 */
const withParam = (target: string, param: string): string => {
  const resolved = target.trim() === "" ? "/" : target;

  const hash = resolved.indexOf("#");
  const base = hash === -1 ? resolved : resolved.slice(0, hash);
  const fragment = hash === -1 ? "" : resolved.slice(hash);

  const query = base.includes("?") ? base.slice(base.indexOf("?") + 1) : "";
  if (query.split("&").includes(param)) return resolved;

  const separator = !base.includes("?") ? "?" : base.endsWith("?") ? "" : "&";
  return `${base}${separator}${param}${fragment}`;
};

/** The same target with IAP's login trigger appended. */
export const loginUrl = (target = "/"): string => withParam(target, LOGIN_QUERY);

/** The same target with IAP's cookie-clear mode appended. */
export const logoutUrl = (target = "/"): string => withParam(target, LOGOUT_QUERY);
