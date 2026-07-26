import { defineConfig } from "vitest/config";

// Two projects, mirroring the Ruby side's `rake unit` / `rake integration`
// split. `npm test` runs unit only; e2e needs live GCP/Okta credentials and a
// standing IAP stack, so it never runs by accident.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          environment: "node",
          include: ["test/unit/**/*.test.ts"],
        },
      },
      {
        test: {
          name: "e2e",
          environment: "node",
          include: ["test/e2e/**/*.test.ts"],
          testTimeout: 120_000,
          hookTimeout: 180_000,
        },
      },
    ],
  },
});
