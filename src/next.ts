import { NextResponse, type NextRequest } from "next/server";

import { DEV_BYPASS_EMAIL_VAR, devBypass } from "./dev-bypass.js";
import { stampIdentity, stripIdentity } from "./identity-headers.js";
import { verifyRequest, type Logger, type VerifyOptions } from "./verifier.js";

/**
 * The Next.js IAP gate, as a factory.
 *
 * Three apps hand-rolled this — bills (`src/proxy.ts`), cru-web-campaign
 * (`src/middleware.ts`), pingpong (per-route, no gate yet) — and the diffs
 * between them were not stylistic:
 *
 *   - bills strips the inbound identity headers BEFORE its public-path
 *     early-return. Doing it after is a full authentication bypass: any exempt
 *     path becomes an `x-cru-iap-email: admin@cru.org` injection point for
 *     every downstream reader.
 *   - cru-web-campaign opened the gate entirely when `IAP_AUDIENCE` was unset,
 *     and both apps carried a boolean bypass flag. Those are the exact incident
 *     shapes this package exists to prevent, so this factory FAILS CLOSED: no
 *     assertion and no `CRU_IAP_DEV_BYPASS_EMAIL` is a 401, in every
 *     environment. Local development gets an identity, never an open gate.
 *
 * `config.matcher` stays app-owned. Next requires it to be a statically
 * analyzable literal in the middleware file itself, so a factory could not
 * supply one even in principle — and cru-web-campaign's asset-exemption regex
 * shows the intricacy an app legitimately needs there. `publicPrefixes` handles
 * the flat "these paths are anonymous" case; anything more expressive belongs
 * in the matcher.
 *
 * This is the ONLY module in the package that imports `next/server`. The core
 * stays framework-free so Rails-adjacent Node services, Express, and route
 * handlers can use it without installing Next.
 */

export interface IapProxyOptions {
  /**
   * Paths served without an identity. Matched as
   * `pathname === prefix || pathname.startsWith(prefix)`, which is bills'
   * semantics, and why bills writes directory prefixes with a trailing slash:
   * `"/api/"` gates `/apiary` (as it should) where `"/api"` would not.
   */
  publicPrefixes?: readonly string[] | undefined;
  /** Passed through to `verifyRequest`. Defaults to `IAP_AUDIENCE`. */
  audience?: string | undefined;
  /** Defaults to `console`. Rejections are logged as one-line structured JSON. */
  logger?: Logger | undefined;
  /** Defaults to `process.env`; injectable so tests need no shell. */
  env?: Record<string, string | undefined> | undefined;
  /** Key source override, for tests. See `VerifyOptions.jwks`. */
  jwks?: VerifyOptions["jwks"];
}

/**
 * Deliberately not a redirect. IAP owns sign-in and has already run by the time
 * a request reaches us, so a rejected assertion will not be fixed by bouncing
 * the browser — that just loops. See `loginUrl` for the one link that does
 * trigger IAP's sign-in.
 */
const UNAUTHORIZED = "Unauthorized";

/**
 * Shown only when no audience is configured, which locally means "you have not
 * named yourself yet" far more often than it means a bad assertion.
 */
const LOCAL_HINT = [
  "Unauthorized — no IAP assertion, and no dev bypass.",
  "",
  "This app is gated by Google Identity-Aware Proxy. Running locally there is no",
  "assertion to verify, so name yourself instead:",
  "",
  `  ${DEV_BYPASS_EMAIL_VAR}=you@cru.org npm run dev`,
  "",
].join("\n");

/**
 * Build the gate. The returned function is the whole middleware, and works as
 * either a Next 15 `middleware` or a Next 16 `proxy` default export.
 */
export function createIapProxy(
  options: IapProxyOptions = {},
): (request: NextRequest) => Promise<NextResponse> {
  const publicPrefixes = options.publicPrefixes ?? [];

  return async function iapProxy(request: NextRequest): Promise<NextResponse> {
    const env = options.env ?? (typeof process === "undefined" ? {} : process.env);
    const logger = options.logger ?? console;
    const audience = (options.audience ?? env["IAP_AUDIENCE"] ?? "").trim();
    const path = request.nextUrl.pathname;

    // Unconditionally, and before the public check — see the module comment.
    const headers = new Headers(request.headers);
    stripIdentity(headers);

    const forward = (): NextResponse => NextResponse.next({ request: { headers } });

    if (isPublic(path, publicPrefixes)) return forward();

    // An audience passed in code is as much proof of a real IAP environment as
    // one in the environment, so devBypass has to see it — otherwise
    // `createIapProxy({ audience })` would leave guard 1 unarmed.
    const result =
      devBypass({ env: audience === "" ? env : { ...env, IAP_AUDIENCE: audience }, log: logger }) ??
      (await verifyRequest(request, { audience, logger, jwks: options.jwks }));

    if (!result.ok) {
      // Structured on one line so Cloud Logging and Datadog both parse it, with
      // a reason drawn from the cross-language vocabulary so a Next.js
      // rejection is queryable alongside a Rails one.
      logger.warn(
        JSON.stringify({
          severity: "WARNING",
          message: "iap_rejected",
          reason: result.reason,
          path,
        }),
      );
      return new NextResponse(audience === "" ? LOCAL_HINT : UNAUTHORIZED, { status: 401 });
    }

    stampIdentity(headers, result);
    return forward();
  };
}

const isPublic = (path: string, prefixes: readonly string[]): boolean =>
  prefixes.some((prefix) => path === prefix || path.startsWith(prefix));
