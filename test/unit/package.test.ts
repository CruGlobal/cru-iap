import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Packaging guards. Everything else in the suite imports `src/`; a consumer
 * imports the built `dist/` through the exports map, and those can drift apart
 * silently — a broken exports field or a missing build produces a package that
 * passes its own tests and fails on `npm install`.
 */

const root = new URL("../../", import.meta.url);
const pkg = JSON.parse(readFileSync(new URL("package.json", root), "utf8")) as {
  name: string;
  exports: Record<string, Record<string, string>>;
  files: string[];
  dependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  peerDependenciesMeta: Record<string, { optional?: boolean }>;
};

describe("the published package", () => {
  it("has a built dist (run `npm run build`)", () => {
    expect(existsSync(new URL("dist/index.js", root))).toBe(true);
    expect(existsSync(new URL("dist/index.d.ts", root))).toBe(true);
  });

  it("exposes the whole public API through the exports map", async () => {
    const entry = new URL(pkg.exports["."]!["default"]!, root).href;
    const api = (await import(entry)) as Record<string, unknown>;

    expect(Object.keys(api).sort()).toEqual([
      "CLOUD_MARKERS",
      "DEV_BYPASS_EMAIL_VAR",
      "DEV_BYPASS_NAME_VAR",
      "HEADER",
      "IAP_ISSUER",
      "IAP_JWKS_URL",
      "IDENTITY_HEADERS",
      "LOGIN_QUERY",
      "LOGOUT_QUERY",
      "REASONS",
      "assertionFrom",
      "devBypass",
      "identityFrom",
      "isKnownReason",
      "loginUrl",
      "logoutUrl",
      "resetJwksCache",
      "stampIdentity",
      "stripIdentity",
      "verify",
      "verifyRequest",
    ]);
  });

  it("keeps next out of the main entry point", async () => {
    // The core has to stay importable from Rails-adjacent Node services, route
    // handlers and Express, none of which install next. Only the ./next subpath
    // may reach for it — and it is not imported here for exactly that reason:
    // `next/server` resolves through Next's bundler only, never bare Node.
    const leaking = readdirSync(new URL("dist", root))
      .filter((file) => file.endsWith(".js") && file !== "next.js")
      .filter((file) => readFileSync(new URL(`dist/${file}`, root), "utf8").includes("next/server"));

    expect(leaking).toEqual([]);
    expect(existsSync(new URL(pkg.exports["./next"]!["default"]!, root))).toBe(true);
    expect(existsSync(new URL(pkg.exports["./next"]!["types"]!, root))).toBe(true);
  });

  it("declares next as an OPTIONAL peer", () => {
    expect(pkg.peerDependencies["next"]).toBe(">=15.3.0");
    expect(pkg.peerDependenciesMeta["next"]?.optional).toBe(true);
  });

  it("depends only on jose at runtime", () => {
    // The Ruby gem's equivalent promise is "googleauth only, no Rails". Here
    // it matters for Edge-runtime compatibility: jose is WebCrypto-based, so
    // anything we added that reached for node: builtins would break Next.js
    // middleware.
    expect(Object.keys(pkg.dependencies)).toEqual(["jose"]);
  });

  it("imports without touching the network", () => {
    // Constructing the remote key set at import time would fire a request
    // from any module that merely imports us, and would break bundlers that
    // evaluate modules during a build. Asserted in a fresh process, because
    // by the time this file runs the module is long since imported.
    const script = `
      const realFetch = globalThis.fetch;
      let calls = 0;
      globalThis.fetch = (...args) => { calls += 1; return realFetch(...args); };
      await import(${JSON.stringify(new URL("dist/index.js", root).href)});
      if (calls !== 0) { console.error("fetched " + calls + " time(s) on import"); process.exit(1); }
    `;
    expect(() =>
      execFileSync(process.execPath, ["--input-type=module", "-e", script], { stdio: "pipe" }),
    ).not.toThrow();
  });

  it("ships dist and src but not the test suite", () => {
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("!src/**/*.test.ts");
  });
});
