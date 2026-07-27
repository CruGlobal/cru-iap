import { describe, expect, it, vi } from "vitest";

import { DEV_BYPASS_EMAIL_VAR, devBypass } from "../../src/dev-bypass.js";
import { isKnownReason } from "../../src/reasons.js";

/**
 * The guards are the whole point, so most of this file is negative controls.
 *
 * The incident being prevented: dse-portal's `AUTH_ENABLED` defaulted to the
 * insecure value, so forgetting to set it disabled authentication. Every test
 * below that ends in `toBeNull()` is a way that cannot happen here.
 */

const silent = { warn: () => {}, error: () => {} };
const dev = (env: Record<string, string | undefined>) => devBypass({ env, log: silent });

describe("devBypass", () => {
  it("is off when nothing is set — the default is closed", () => {
    expect(dev({})).toBeNull();
  });

  it("has no boolean to get backwards", () => {
    // The API surface is the assertion here: an identity-carrying variable has
    // no wrong default, where AUTH_ENABLED=false vs =true does. Setting the
    // "enable" flag people reach for by habit does nothing at all.
    expect(dev({ AUTH_ENABLED: "false" })).toBeNull();
    expect(dev({ CRU_IAP_DEV_BYPASS: "true" })).toBeNull();
    expect(dev({ CRU_IAP_DEV_BYPASS_ENABLED: "1" })).toBeNull();
  });

  it("activates when a developer names themselves", () => {
    const result = dev({ [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" });

    expect(result).toMatchObject({
      ok: true,
      reason: "dev_bypass",
      email: "dev@cru.org",
      name: null,
      payload: null,
    });
  });

  it("emits a reason from the shared vocabulary", () => {
    // So a bypassed request is queryable in Datadog alongside every real one,
    // rather than being invisible.
    const result = dev({ [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" });

    expect(isKnownReason(result!.reason)).toBe(true);
  });

  it("normalises the address and carries an optional display name", () => {
    const result = dev({
      [DEV_BYPASS_EMAIL_VAR]: "  Dev@Cru.org  ",
      CRU_IAP_DEV_BYPASS_NAME: "A Developer",
    });

    expect(result?.email).toBe("dev@cru.org");
    expect(result?.name).toBe("A Developer");
  });

  describe("guard 1: IAP_AUDIENCE means this is a real IAP environment", () => {
    it("refuses when IAP_AUDIENCE is set", () => {
      // cru-terraform injects IAP_AUDIENCE into every IAP-fronted container, so
      // the bypass cannot coexist with the config that means "verify for real".
      expect(
        dev({
          [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org",
          IAP_AUDIENCE: "/projects/1/global/backendServices/2",
        }),
      ).toBeNull();
    });

    it("ignores a blank IAP_AUDIENCE, which is not a configured one", () => {
      expect(dev({ [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org", IAP_AUDIENCE: "   " })?.ok).toBe(true);
    });
  });

  describe("guard 2: a managed runtime is never a dev machine", () => {
    // Nobody has to remember to set these — the platform does — which is
    // exactly what makes them trustworthy as a guard.
    it.each(["K_SERVICE", "K_REVISION", "GAE_ENV", "FUNCTION_TARGET"])(
      "refuses when %s is present",
      (marker) => {
        expect(dev({ [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org", [marker]: "anything" })).toBeNull();
      },
    );

    it("refuses on Cloud Run even with IAP_AUDIENCE somehow missing", () => {
      // The guards are independent on purpose: this is the misconfigured-deploy
      // case, where relying on IAP_AUDIENCE alone would open the bypass.
      expect(dev({ [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org", K_SERVICE: "my-app" })).toBeNull();
    });
  });

  describe("the identity must survive the same shape gate as a real one", () => {
    it.each([
      "not-an-address",
      "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/dev@cru.org",
      "dev@cru.org/../admin",
      "sts.google.com:dev@cru.org",
      "@cru.org",
    ])("refuses %s", (value) => {
      expect(dev({ [DEV_BYPASS_EMAIL_VAR]: value })).toBeNull();
    });
  });

  it("warns loudly on every activation", () => {
    // A bypass that logs once is a bypass someone forgets is on.
    const log = { warn: vi.fn(), error: vi.fn() };

    devBypass({ env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" }, log });
    devBypass({ env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org" }, log });

    expect(log.warn).toHaveBeenCalledTimes(2);
    expect(log.warn.mock.calls[0]?.[0]).toContain("DEV BYPASS ACTIVE");
  });

  it("explains itself when it refuses", () => {
    const log = { warn: vi.fn(), error: vi.fn() };

    devBypass({
      env: { [DEV_BYPASS_EMAIL_VAR]: "dev@cru.org", K_SERVICE: "my-app" },
      log,
    });

    expect(log.warn.mock.calls[0]?.[0]).toContain("K_SERVICE");
  });
});
