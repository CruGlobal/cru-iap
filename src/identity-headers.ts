import type { DevBypassResult } from "./dev-bypass.js";
import { headerFrom, type HeaderSource } from "./request.js";
import type { VerifyResult } from "./verifier.js";

/**
 * The identity a gate hands downstream, as request headers.
 *
 * Verifying once at the edge and stamping the result is what lets a route
 * handler, a server component, or a Node backend behind the same proxy read one
 * identity instead of re-verifying per route — cru-web-campaign and bills both
 * arrived at this independently, in the same three header names, which is why
 * those names are frozen here rather than made configurable.
 *
 * These are REQUEST headers, set on the request as forwarded onward. What makes
 * them trustworthy is not the naming: it is that the gate STRIPS whatever
 * arrived from the client before setting its own. Code that reads them with no
 * stripping gate in front is trusting
 * `curl -H 'x-cru-iap-email: admin@cru.org'`.
 */
export const IDENTITY_HEADERS = {
  email: "x-cru-iap-email",
  name: "x-cru-iap-name",
  issuedAt: "x-cru-iap-issued-at",
} as const;

/** The `ok` outcome of either identity source — `verify*` or `devBypass`. */
export type Identified = Extract<VerifyResult, { ok: true }> | DevBypassResult;

/** What `identityFrom` recovers from a stamped request. */
export interface Identity {
  email: string;
  name: string | null;
  /** The assertion's `iat`, or null — devBypass verified nothing, so it has none. */
  issuedAt: number | null;
}

/**
 * Remove all three, so nothing a client sent can be mistaken for something we
 * stamped. Must run BEFORE any early return a gate makes — an exempt path that
 * forwards an inbound `x-cru-iap-email` is a full authentication bypass, not a
 * cosmetic leak.
 */
export function stripIdentity(headers: Headers): void {
  for (const name of Object.values(IDENTITY_HEADERS)) headers.delete(name);
}

/**
 * Delete-then-set for name and issued-at, rather than set-only-when-present:
 * the real assertion commonly carries no `name` claim and devBypass has no
 * payload at all, and in neither case may an inbound value survive as the
 * identity. Callers are expected to have stripped already; this does not rely
 * on it.
 */
export function stampIdentity(headers: Headers, result: Identified): void {
  headers.set(IDENTITY_HEADERS.email, result.email);

  headers.delete(IDENTITY_HEADERS.name);
  if (result.name !== null) headers.set(IDENTITY_HEADERS.name, result.name);

  headers.delete(IDENTITY_HEADERS.issuedAt);
  const issuedAt = result.payload?.["iat"];
  if (typeof issuedAt === "number") {
    headers.set(IDENTITY_HEADERS.issuedAt, String(issuedAt));
  }
}

/**
 * Read back what a gate stamped. `email` is the identity, so its absence means
 * "no identity here" — null, never a partial object a caller might destructure
 * an empty string out of.
 */
export function identityFrom(source: HeaderSource): Identity | null {
  const email = (headerFrom(source, IDENTITY_HEADERS.email) ?? "").trim();
  if (email === "") return null;

  const name = (headerFrom(source, IDENTITY_HEADERS.name) ?? "").trim();
  const rawIssuedAt = (headerFrom(source, IDENTITY_HEADERS.issuedAt) ?? "").trim();
  // Number("") is 0, not NaN, so the blank case has to be excluded first or an
  // absent issued-at would read as the epoch.
  const issuedAt = rawIssuedAt === "" ? Number.NaN : Number(rawIssuedAt);

  return {
    email,
    name: name === "" ? null : name,
    issuedAt: Number.isFinite(issuedAt) ? issuedAt : null,
  };
}
