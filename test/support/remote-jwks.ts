import { IAP_JWKS_URL } from "../../src/verifier.js";
import { jwks, type Keypair } from "./iap-jwt.js";

/**
 * Installs a `globalThis.fetch` stub that answers Google's IAP JWKS URL from
 * an in-process key set, and refuses every other URL loudly.
 *
 * Used by the tests that must exercise the REAL `createRemoteJWKSet` — its
 * caching, its cooldown, and its failure modes — rather than the offline
 * `createLocalJWKSet`. That HTTP layer is what produces
 * `verification_error:KeySourceError` in production, so it stays in the
 * blast radius of at least a few tests. This is the TS analogue of the
 * WebMock seam in spec/support/iap_jwt.rb.
 */
export interface JwksStub {
  /** How many times the JWKS endpoint was actually fetched. */
  readonly calls: () => number;
  /** Serve a different key set from now on (key rotation). */
  publish: (...keypairs: Keypair[]) => Promise<void>;
  /** Serve an HTTP error from now on. */
  fail: (status: number) => void;
  /** Make fetch itself reject, as a DNS/connect failure would. */
  failTransport: () => void;
  restore: () => void;
}

export async function stubIapJwks(...keypairs: Keypair[]): Promise<JwksStub> {
  const realFetch = globalThis.fetch;
  let body = JSON.stringify(await jwks(...keypairs));
  let status = 200;
  let transportError = false;
  let calls = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url !== IAP_JWKS_URL) {
      throw new Error(`unexpected fetch in test: ${url}`);
    }
    calls += 1;
    if (transportError) throw new TypeError("fetch failed");
    void init;
    return new Response(status === 200 ? body : "upstream error", {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  return {
    calls: () => calls,
    publish: async (...next: Keypair[]) => {
      body = JSON.stringify(await jwks(...next));
      status = 200;
      transportError = false;
    },
    fail: (nextStatus: number) => {
      status = nextStatus;
    },
    failTransport: () => {
      transportError = true;
    },
    restore: () => {
      globalThis.fetch = realFetch;
    },
  };
}
