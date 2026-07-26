import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { beforeAll, describe, expect, it } from "vitest";

import { HEADER, assertionFrom, verifyRequest } from "../../src/index.js";
import { AUDIENCE, iapToken, localJwks, signingKey } from "../support/iap-jwt.js";

let jwks: Awaited<ReturnType<typeof localJwks>>;

beforeAll(async () => {
  jwks = await localJwks(await signingKey());
});

describe("assertionFrom", () => {
  it("reads a Web Request — the Next.js App Router / Edge shape", () => {
    const request = new Request("https://bills.cru.org/", {
      headers: { [HEADER]: "the-jwt" },
    });

    expect(assertionFrom(request)).toBe("the-jwt");
  });

  it("reads a bare Headers object", () => {
    // What `await headers()` hands back in a Next.js server component.
    expect(assertionFrom(new Headers({ [HEADER]: "the-jwt" }))).toBe("the-jwt");
  });

  it("is case-insensitive on a Web Request, since HTTP/2 lowercases anyway", () => {
    const request = new Request("https://bills.cru.org/", {
      headers: { "X-Goog-IAP-JWT-Assertion": "the-jwt" },
    });

    expect(assertionFrom(request)).toBe("the-jwt");
  });

  it("reads a Node IncomingMessage", () => {
    const message = new IncomingMessage(new Socket());
    message.headers[HEADER] = "the-jwt";

    expect(assertionFrom(message)).toBe("the-jwt");
  });

  it("reads a plain header record", () => {
    expect(assertionFrom({ [HEADER]: "the-jwt" })).toBe("the-jwt");
  });

  it("reads a plain header record with non-lowercase keys", () => {
    // Node lowercases and so does Object.fromEntries(headers), but a
    // hand-built literal in a test or an adapter may not.
    expect(assertionFrom({ "X-Goog-Iap-Jwt-Assertion": "the-jwt" })).toBe("the-jwt");
  });

  it("returns undefined when the header is absent", () => {
    expect(assertionFrom(new Request("https://bills.cru.org/"))).toBeUndefined();
    expect(assertionFrom({})).toBeUndefined();
  });

  it("treats a repeated header as absent rather than picking one", () => {
    // Node surfaces a duplicated header as an array. Two assertions is not a
    // shape IAP produces, so refuse to guess — the verifier then reports
    // missing_token and the request fails closed.
    const message = new IncomingMessage(new Socket());
    message.headers[HEADER] = ["jwt-one", "jwt-two"];

    expect(assertionFrom(message)).toBeUndefined();
  });

  it("unwraps a single-element array", () => {
    const message = new IncomingMessage(new Socket());
    message.headers[HEADER] = ["the-jwt"];

    expect(assertionFrom(message)).toBe("the-jwt");
  });
});

describe("verifyRequest", () => {
  it("verifies straight off a Web Request", async () => {
    const request = new Request("https://bills.cru.org/", {
      headers: { [HEADER]: await iapToken() },
    });

    const result = await verifyRequest(request, { audience: AUDIENCE, jwks });

    expect(result).toMatchObject({ ok: true, email: "alice@cru.org" });
  });

  it("fails closed on a request with no assertion header", async () => {
    const request = new Request("https://bills.cru.org/");

    const result = await verifyRequest(request, { audience: AUDIENCE, jwks });

    expect(result).toMatchObject({ ok: false, reason: "missing_token", email: null });
  });

  it("fails closed on a duplicated assertion header", async () => {
    const message = new IncomingMessage(new Socket());
    message.headers[HEADER] = [await iapToken(), await iapToken()];

    const result = await verifyRequest(message, { audience: AUDIENCE, jwks });

    expect(result.reason).toBe("missing_token");
  });
});
