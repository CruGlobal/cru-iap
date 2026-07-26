import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { isKnownReason, verify, type Logger, type VerifyResult } from "../../src/index.js";
import {
  AUDIENCE,
  iapToken,
  localJwks,
  rogueKey,
  signingKey,
  type Keypair,
} from "../support/iap-jwt.js";

let jwks: Awaited<ReturnType<typeof localJwks>>;
let good: Keypair;
let rogue: Keypair;

beforeAll(async () => {
  good = await signingKey();
  rogue = await rogueKey();
  // Publish only the good key: the rogue one is a real signer whose public
  // half Google never advertised.
  jwks = await localJwks(good);
});

afterEach(() => {
  delete process.env["IAP_AUDIENCE"];
});

const collector = (): Logger & { messages: string[] } => {
  const messages: string[] = [];
  return { messages, warn: (m) => messages.push(m) };
};

function run(token: string | null | undefined, opts: Record<string, unknown> = {}) {
  return verify(token, { audience: AUDIENCE, jwks, ...opts });
}

/** Narrow to the rejection arm without repeating the assertion everywhere. */
function rejected(result: VerifyResult): string {
  expect(result.ok).toBe(false);
  expect(result.email).toBeNull();
  return result.reason;
}

describe("happy path", () => {
  it("accepts a genuine assertion and returns the email identity", async () => {
    const result = await run(await iapToken());

    expect(result).toMatchObject({
      ok: true,
      reason: "iap_jwt",
      email: "alice@cru.org",
      name: "Alice A",
    });
  });

  it("downcases the email, matching the citext columns apps store it in", async () => {
    const result = await run(await iapToken({ email: "Alice.A@CRU.org" }));

    expect(result.email).toBe("alice.a@cru.org");
  });

  it("returns null rather than an empty string when there is no name claim", async () => {
    // The live workforce capture has NO `name` claim at all, so this is the
    // production path for federated identities, not the exception.
    const result = await run(await iapToken({ name: null }));

    expect(result.ok).toBe(true);
    expect(result.name).toBeNull();
  });

  it("trims a whitespace-only name to null", async () => {
    const result = await run(await iapToken({ name: "   " }));

    expect(result.name).toBeNull();
  });

  it("exposes the full payload so callers can read claims we do not model", async () => {
    const result = await run(await iapToken());

    expect(result.ok).toBe(true);
    expect(result.payload).toMatchObject({ hd: "cru.org", azp: AUDIENCE });
  });
});

describe("fail-closed preconditions", () => {
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["empty string", ""],
    ["whitespace", "   "],
  ])("rejects a %s assertion as missing_token", async (_label, token) => {
    expect(rejected(await run(token))).toBe("missing_token");
  });

  it("rejects when no audience is configured, rather than skipping the check", async () => {
    const result = await verify(await iapToken(), { audience: "", jwks });

    expect(rejected(result)).toBe("missing_audience_config");
  });

  it("treats a whitespace-only IAP_AUDIENCE as unset", async () => {
    process.env["IAP_AUDIENCE"] = "   ";

    expect(rejected(await verify(await iapToken(), { jwks }))).toBe("missing_audience_config");
  });

  it("falls back to process.env.IAP_AUDIENCE when no audience is passed", async () => {
    process.env["IAP_AUDIENCE"] = AUDIENCE;

    const result = await verify(await iapToken(), { jwks });

    expect(result.ok).toBe(true);
  });

  it("reads IAP_AUDIENCE at call time, not at import time", async () => {
    process.env["IAP_AUDIENCE"] = "/projects/1/global/backendServices/wrong";
    expect(rejected(await verify(await iapToken(), { jwks }))).toBe("audience_mismatch");

    process.env["IAP_AUDIENCE"] = AUDIENCE;
    expect((await verify(await iapToken(), { jwks })).ok).toBe(true);
  });
});

describe("cryptographic verification", () => {
  it("rejects a token signed by a key that is not in the JWKS", async () => {
    const result = await run(await iapToken({ key: rogue }));

    // The rogue key's kid is absent from the published set, so no key even
    // matches — the same bucket as a bad signature on the Ruby side.
    expect(rejected(result)).toBe("signature_error:no_matching_key");
  });

  it("rejects a token whose payload was edited after signing", async () => {
    const token = await iapToken({ email: "alice@cru.org" });
    const [header, payload, signature] = token.split(".");
    const tampered = JSON.parse(Buffer.from(payload!, "base64url").toString());
    tampered.email = "attacker@evil.example";
    const forged = [
      header,
      Buffer.from(JSON.stringify(tampered)).toString("base64url"),
      signature,
    ].join(".");

    expect(rejected(await run(forged))).toMatch(/^signature_error:/);
  });

  it("rejects an unsigned (alg=none) token", async () => {
    const claims = Buffer.from(
      JSON.stringify({
        iss: "https://cloud.google.com/iap",
        aud: AUDIENCE,
        email: "alice@cru.org",
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ).toString("base64url");
    const header = Buffer.from(JSON.stringify({ alg: "none", kid: good.kid })).toString(
      "base64url",
    );

    expect(rejected(await run(`${header}.${claims}.`))).toMatch(
      /^(signature_error:|verification_error:)/,
    );
  });

  it.each([["not-a-jwt"], ["a.b"], ["a.b.c.d"], ["...."]])(
    "rejects the structurally invalid token %j",
    async (garbage) => {
      expect(rejected(await run(garbage))).toMatch(/^signature_error:/);
    },
  );
});

describe("registered claims", () => {
  it("rejects an expired token", async () => {
    const result = await run(await iapToken({ now: Math.floor(Date.now() / 1000) - 3600 }));

    expect(rejected(result)).toBe("expired_token");
  });

  it("accepts a just-expired token when the caller allows clock tolerance", async () => {
    const token = await iapToken({ now: Math.floor(Date.now() / 1000) - 605 });

    expect(rejected(await run(token))).toBe("expired_token");
    expect((await run(token, { clockToleranceSeconds: 60 })).ok).toBe(true);
  });

  it("rejects a signed token that carries no exp claim at all", async () => {
    // The trap this guards: jose (like Ruby's jwt gem) SKIPS the expiry check
    // when exp is absent rather than failing, so without requiredClaims a
    // validly signed assertion with no expiry would be accepted forever.
    const result = await run(await iapToken({ exp: null }));

    expect(rejected(result)).toBe("missing_exp");
  });

  it("rejects a token minted for a different backend service", async () => {
    const result = await run(await iapToken({ aud: "/projects/1/global/backendServices/999" }));

    expect(rejected(result)).toBe("audience_mismatch");
  });

  it("accepts a multi-audience token that includes our backend", async () => {
    // Documenting jose's (and googleauth's) semantics: `aud` is an
    // intersection check, not equality. IAP does not emit multi-audience
    // tokens, so this is a property of the library rather than a decision.
    const result = await run(await iapToken({ aud: ["https://elsewhere.example", AUDIENCE] }));

    expect(result.ok).toBe(true);
  });

  it("rejects a token from an issuer other than IAP", async () => {
    const result = await run(await iapToken({ iss: "https://accounts.google.com" }));

    expect(rejected(result)).toBe("issuer_mismatch");
  });

  it("rejects a token with no iss claim", async () => {
    expect(rejected(await run(await iapToken({ iss: null })))).toBe("issuer_mismatch");
  });
});

describe("identity extraction", () => {
  it("rejects when the email claim is absent, naming the pool misconfiguration", async () => {
    const result = await run(await iapToken({ email: null }));

    expect(rejected(result)).toBe("missing_email");
  });

  it("rejects an empty email claim as missing rather than malformed", async () => {
    expect(rejected(await run(await iapToken({ email: "   " })))).toBe("missing_email");
  });

  it.each([
    ["accounts.google.com:", "accounts.google.com:alice@cru.org"],
    ["sts.google.com:", "sts.google.com:alice@cru.org"],
    ["securetoken.google.com/proj/tenant:", "securetoken.google.com/p/t:alice@cru.org"],
  ])("strips the %s namespace prefix", async (_label, claim) => {
    const result = await run(await iapToken({ email: claim }));

    expect(result.ok).toBe(true);
    expect(result.email).toBe("alice@cru.org");
  });

  it.each([
    ["a principal URI", "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org"],
    ["a principalSet URI", "principalSet://iam.googleapis.com/locations/global/workforcePools/p/group/eng"],
    ["a percent-encoded address", "alice%40cru.org"],
    ["an opaque subject", "104291823410293841029"],
    ["two addresses", "alice@cru.org,bob@cru.org"],
    ["an address with a backslash", "cru\\alice@cru.org"],
  ])("rejects %s as malformed_subject", async (_label, claim) => {
    expect(rejected(await run(await iapToken({ email: claim })))).toBe("malformed_subject");
  });

  it("rejects a principal URI that the email regexp alone would accept", async () => {
    // Why NEVER_IN_AN_EMAIL exists. The raw principal fails the regexp only
    // because of its "principal:" scheme colon — and the verifier strips
    // everything up to the first colon before validating, since that is how
    // it removes IAP's "accounts.google.com:" namespace. What is left DOES
    // pass RFC 5322, because a local part may contain "/". So the regexp is
    // not the thing rejecting this; the slash check is.
    const principal =
      "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/alice@cru.org";
    const afterPrefixStrip = principal.slice(principal.indexOf(":") + 1).toLowerCase();
    const emailRegexp =
      /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

    // Negative control: without the slash check this would be accepted, and
    // persisted as a user whose email is that entire string.
    expect(emailRegexp.test(afterPrefixStrip)).toBe(true);
    expect(rejected(await run(await iapToken({ email: principal })))).toBe("malformed_subject");
  });

  it.each([
    ["a number", 42],
    ["a boolean", true],
    ["an object", { address: "alice@cru.org" }],
    ["an array of one address", ["alice@cru.org"]],
  ])("rejects a non-string email claim (%s) as malformed_subject", async (_label, claim) => {
    // The array case is load-bearing: String(["alice@cru.org"]) is
    // "alice@cru.org", so coercing would turn a list into an accepted single
    // identity. Ruby's Array#to_s renders the brackets and rejects; JS would
    // not, so the verifier refuses non-strings outright.
    expect(rejected(await run(await iapToken({ email: claim })))).toBe("malformed_subject");
  });

  it("never falls back to sub, even when sub is well formed", async () => {
    const result = await run(
      await iapToken({ email: null, sub: "accounts.google.com:alice@cru.org" }),
    );

    expect(rejected(result)).toBe("missing_email");
  });

  it("ignores the nested workforce principal, even when it names a real address", async () => {
    const result = await run(
      await iapToken({
        email: null,
        workforce_identity: {
          iam_principal:
            "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/bob@cru.org",
        },
      }),
    );

    expect(rejected(result)).toBe("missing_email");
  });
});

describe("logging", () => {
  it("logs the payload on malformed_subject so the shape is diagnosable", async () => {
    const logger = collector();

    await run(await iapToken({ email: "not-an-address" }), { logger });

    expect(logger.messages).toHaveLength(1);
    expect(logger.messages[0]).toContain("malformed subject");
    expect(logger.messages[0]).toContain("accounts.google.com:104291823410293841029");
  });

  it("is silent on the happy path and on ordinary rejections", async () => {
    const logger = collector();

    await run(await iapToken(), { logger });
    await run(await iapToken({ email: null }), { logger });
    await run(await iapToken({ now: Math.floor(Date.now() / 1000) - 3600 }), { logger });
    await run("", { logger });

    expect(logger.messages).toEqual([]);
  });

  it("does not require a logger", async () => {
    await expect(run(await iapToken({ email: "not-an-address" }))).resolves.toMatchObject({
      reason: "malformed_subject",
    });
  });
});

describe("failure containment", () => {
  it("returns unexpected_error rather than throwing when the key source misbehaves", async () => {
    const logger = collector();
    const exploding = vi.fn().mockRejectedValue(new RangeError("boom"));

    const result = await verify(await iapToken(), {
      audience: AUDIENCE,
      jwks: exploding,
      logger,
    });

    expect(rejected(result)).toBe("unexpected_error");
    expect(logger.messages[0]).toContain("RangeError: boom");
  });

  it("never throws, whatever it is handed", async () => {
    const inputs = [null, undefined, "", "garbage", "a.b.c", await iapToken()];

    for (const input of inputs) {
      await expect(run(input)).resolves.toHaveProperty("ok");
    }
  });
});

describe("the shared reason vocabulary", () => {
  it("only ever emits reasons that are in REASONS", async () => {
    const now = Math.floor(Date.now() / 1000);
    const results = await Promise.all([
      run(null),
      verify(await iapToken(), { audience: "", jwks }),
      run(await iapToken({ exp: null })),
      run(await iapToken({ email: null })),
      run(await iapToken({ email: "nope" })),
      run(await iapToken({ key: rogue })),
      run(await iapToken({ aud: "/projects/1/global/backendServices/9" })),
      run(await iapToken({ now: now - 3600 })),
      run(await iapToken({ iss: "https://accounts.google.com" })),
      run("garbage"),
      run(await iapToken()),
      verify(await iapToken(), { audience: AUDIENCE, jwks: vi.fn().mockRejectedValue(new Error()) }),
    ]);

    for (const result of results) {
      expect(isKnownReason(result.reason), `unlisted reason: ${result.reason}`).toBe(true);
    }
    // Sanity: the batch above really did exercise a spread of reasons rather
    // than collapsing into one.
    expect(new Set(results.map((r) => r.reason.split(":")[0])).size).toBeGreaterThanOrEqual(9);
  });
});
