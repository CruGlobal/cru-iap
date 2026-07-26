import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HEADER, verifyRequest, type VerifyOptions } from "../../src/index.js";
import { AUDIENCE, iapToken, localJwks, rogueKey, signingKey } from "../support/iap-jwt.js";

/**
 * The verifier in a real request path, over a real socket.
 *
 * The unit tests hand it hand-built header carriers; these prove the whole
 * thing survives an actual HTTP hop — header casing as the wire delivers it,
 * a ~1KB assertion in the header block, and the fail-closed behaviour a
 * caller is expected to build on top.
 *
 * Two handlers, because Cru's Node apps have two request shapes:
 *
 *   * `IncomingMessage` — Node's `http`, Express, a custom server
 *   * Web `Request`     — Next.js route handlers and middleware, and anything
 *                         on the Edge runtime
 */

let options: VerifyOptions;

beforeAll(async () => {
  options = { audience: AUDIENCE, jwks: await localJwks(await signingKey()) };
});

/** The reference wiring: verify, or fail closed. Never a fallback identity. */
async function gate(source: Parameters<typeof verifyRequest>[0]): Promise<{
  status: number;
  body: { email?: string; reason?: string };
}> {
  const result = await verifyRequest(source, options);
  if (!result.ok) return { status: 401, body: { reason: result.reason } };
  return { status: 200, body: { email: result.email } };
}

describe("behind a Node http server", () => {
  let server: Server;
  let origin: string;

  beforeAll(async () => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      void gate(req).then(({ status, body }) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const get = async (headers: Record<string, string> = {}) => {
    const response = await fetch(`${origin}/`, { headers });
    return { status: response.status, body: await response.json() };
  };

  it("admits a request carrying a genuine assertion", async () => {
    const response = await get({ [HEADER]: await iapToken() });

    expect(response).toEqual({ status: 200, body: { email: "alice@cru.org" } });
  });

  it("survives the real header casing the wire delivers", async () => {
    // Node lowercases incoming header names; this proves we do not depend on
    // the caller having sent them lowercased.
    const response = await get({ "X-Goog-IAP-JWT-Assertion": await iapToken() });

    expect(response.status).toBe(200);
  });

  it("rejects a request with no assertion — the direct-hit case", async () => {
    // What a request that bypassed IAP looks like. There is no fallback
    // identity: no header means no user, in every environment.
    expect(await get()).toEqual({ status: 401, body: { reason: "missing_token" } });
  });

  it("rejects a client-forged assertion", async () => {
    const response = await get({ [HEADER]: "not.a.jwt" });

    expect(response.status).toBe(401);
    expect(response.body.reason).toMatch(/^signature_error:/);
  });

  it("rejects an assertion signed by a key Google never published", async () => {
    const response = await get({ [HEADER]: await iapToken({ key: await rogueKey() }) });

    expect(response.status).toBe(401);
    expect(response.body.reason).toBe("signature_error:no_matching_key");
  });

  it("carries a full-size assertion without truncation", async () => {
    // Real IAP assertions run ~700-1000 bytes; a WIF one is longer still
    // because of the opaque STS sub. Worth proving the header survives intact
    // rather than assuming.
    const token = await iapToken({
      sub: `sts.google.com:${"A".repeat(600)}`,
    });
    expect(token.length).toBeGreaterThan(800);

    expect((await get({ [HEADER]: token })).status).toBe(200);
  });
});

describe("behind a Web Request handler (Next.js route handler / middleware / Edge)", () => {
  const handler = async (request: Request): Promise<Response> => {
    const { status, body } = await gate(request);
    return Response.json(body, { status });
  };

  it("admits a request carrying a genuine assertion", async () => {
    const response = await handler(
      new Request("https://bills.cru.org/api/me", { headers: { [HEADER]: await iapToken() } }),
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ email: "alice@cru.org" });
  });

  it("fails closed with no assertion", async () => {
    const response = await handler(new Request("https://bills.cru.org/api/me"));

    expect(response.status).toBe(401);
  });

  it("works from a cloned request, as middleware chaining produces", async () => {
    const original = new Request("https://bills.cru.org/", {
      headers: { [HEADER]: await iapToken() },
    });

    expect((await handler(original.clone())).status).toBe(200);
  });
});
