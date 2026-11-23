import { describe, expect, it } from "vitest";
import path from "node:path";
import { loadProject } from "../src/config.js";
import { runStaticChecks } from "../src/static/checks.js";
import { sourceCovers, validateAllowedSource, validateNavigationHost } from "../src/static/network.js";
import { isEndOfLife } from "../src/api-versions.js";

const fixture = (name: string) => path.join(__dirname, "fixtures", name);
const TODAY = "2026-11-23";

async function run(name: string, distribution: "public" | "custom" = "public") {
  return runStaticChecks(await loadProject(fixture(name)), distribution, TODAY);
}
const byId = (findings: Awaited<ReturnType<typeof run>>, id: string) => findings.filter((f) => f.id === id);

describe("vulnerable app", async () => {
  const findings = await run("vulnerable-app");
  const failed = (id: string) => byId(findings, id).some((f) => f.status === "fail");
  const warned = (id: string) => byId(findings, id).some((f) => f.status === "warn");

  it("flags disabled expiring tokens", () => expect(failed("EXPIRING_OFFLINE_TOKENS")).toBe(true));
  it("flags the missing network_access declaration", () => expect(failed("NETWORK_ACCESS")).toBe(true));
  it("lists undeclared storefront origins", () => {
    const f = byId(findings, "NETWORK_ACCESS").find((x) => x.status === "warn")!;
    expect(f.details?.join("\n")).toContain("https://api.reviewsdemo.io");
    expect(f.details?.join("\n")).toContain("http://tracking.reviewsdemo.io");
  });
  it("flags script tags", () => expect(failed("SCRIPT_TAGS")).toBe(true));
  it("flags http redirect urls", () => expect(failed("HTTPS_URLS")).toBe(true));
  it("flags missing compliance webhooks", () => expect(failed("COMPLIANCE_WEBHOOKS")).toBe(true));
  it("warns on abandonedCheckoutUrl", () => expect(warned("ABANDONED_CHECKOUT_URL")).toBe(true));
  it("warns on end-of-life API versions", () => expect(warned("EOL_API_VERSION")).toBe(true));
  it("warns on remote code in storefront code", () => expect(warned("STOREFRONT_REMOTE_CODE")).toBe(true));
  it("reminds about bulk operations", () => expect(byId(findings, "BULK_OPERATIONS")).toHaveLength(1));
});

describe("compliant app", async () => {
  const findings = await run("compliant-app");
  it("has no fail or warn findings", () => {
    expect(findings.filter((f) => f.status === "fail" || f.status === "warn")).toEqual([]);
  });
  it("still lists the manual checks", () => {
    expect(findings.map((f) => f.id)).toEqual(expect.arrayContaining(["IP_ALLOWLIST", "PARTNER_MFA"]));
  });
});

describe("custom distribution", async () => {
  const findings = await run("compliant-app", "custom");
  it("skips public-only compliance webhook check", () => expect(byId(findings, "COMPLIANCE_WEBHOOKS")).toEqual([]));
});

describe("network_access helpers", () => {
  it("validates allowed_sources", () => {
    expect(validateAllowedSource("https://api.example.com")).toBeUndefined();
    expect(validateAllowedSource("https://*.example.com")).toBeUndefined();
    expect(validateAllowedSource("http://api.example.com")).toBeDefined();
    expect(validateAllowedSource("*")).toBeDefined();
  });
  it("validates navigation hosts", () => {
    expect(validateNavigationHost("example.com")).toBeUndefined();
    expect(validateNavigationHost("https://example.com")).toBeDefined();
  });
  it("matches wildcards", () => {
    expect(sourceCovers("https://*.example.com", "https://cdn.example.com")).toBe(true);
    expect(sourceCovers("https://*.example.com", "https://example.com")).toBe(false);
    expect(sourceCovers("https://api.example.com", "https://cdn.example.com")).toBe(false);
  });
});

describe("api versions", () => {
  it("knows what's end of life", () => {
    expect(isEndOfLife("2025-01", TODAY)).toBe(true);
    expect(isEndOfLife("2026-10", TODAY)).toBe(false);
  });
});
