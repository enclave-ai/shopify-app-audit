import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
// @ts-expect-error plain JS example
import { createDemoServer } from "../examples/demo-app-server.mjs";
import { runProbe, type ProbeOptions } from "../src/probe/checks.js";
import { appProxySignature, webhookHmac } from "../src/probe/http.js";

async function start(secure: boolean): Promise<{ server: Server; url: string }> {
  const server: Server = createDemoServer({ secure });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

const options = (target: string): ProbeOptions => ({
  target,
  webhookPaths: ["/webhooks/app/uninstalled"],
  proxyPaths: ["/proxy"],
  appPaths: ["/app"],
  shop: "shopify-app-audit-probe.myshopify.com",
  otherShop: "shopify-app-audit-other.myshopify.com",
  clientSecret: "demo-secret",
  timeoutMs: 3000,
});

describe("probe against a vulnerable app", () => {
  let ctx: { server: Server; url: string };
  beforeAll(async () => (ctx = await start(false)));
  afterAll(() => ctx.server.close());

  it("fails every runtime check", async () => {
    const findings = await runProbe(options(ctx.url));
    const status = (id: string) => findings.find((f) => f.id === id)?.status;
    expect(status("WEBHOOK_HMAC")).toBe("fail");
    expect(status("APP_PROXY_SIGNATURE")).toBe("fail");
    expect(status("SHOP_PARAM_TRUST")).toBe("fail");
    expect(status("FRAME_ANCESTORS")).toBe("fail");
  });
});

describe("probe against a secure app", () => {
  let ctx: { server: Server; url: string };
  beforeAll(async () => (ctx = await start(true)));
  afterAll(() => ctx.server.close());

  it("passes every runtime check", async () => {
    const findings = await runProbe(options(ctx.url));
    const status = (id: string) => findings.find((f) => f.id === id)?.status;
    expect(status("WEBHOOK_HMAC")).toBe("pass");
    expect(status("APP_PROXY_SIGNATURE")).toBe("pass");
    expect(status("SHOP_PARAM_TRUST")).toBe("pass");
    expect(status("FRAME_ANCESTORS")).toBe("pass");
    expect(findings.find((f) => f.id === "WEBHOOK_HMAC_VALID")).toBeUndefined();
  });

  it("skips routes that don't exist", async () => {
    const findings = await runProbe({ ...options(ctx.url), webhookPaths: ["/nope"], proxyPaths: ["/nope"] });
    expect(findings.find((f) => f.id === "WEBHOOK_HMAC")?.status).toBe("skip");
  });
});

describe("signing helpers", () => {
  it("matches Shopify's documented formats", () => {
    expect(webhookHmac("s", "{}")).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(appProxySignature("s", { b: "2", a: "1", signature: "x" })).toHaveLength(64);
  });
});

describe("joinUrl", async () => {
  const { joinUrl } = await import("../src/probe/http.js");
  it("resolves routes from the origin and keeps queries", () => {
    expect(joinUrl("https://x.example.com/app", "/webhooks")).toBe("https://x.example.com/webhooks");
    expect(joinUrl("https://x.example.com", "/webhooks?source=shopify", "a=1")).toBe(
      "https://x.example.com/webhooks?source=shopify&a=1",
    );
  });
});

describe("probe against a broken gateway", () => {
  let server: Server;
  let url: string;
  beforeAll(async () => {
    const { createServer } = await import("node:http");
    server = createServer((_req, res) => res.writeHead(503).end());
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => server.close());

  it("reports 5xx as inconclusive, not as a pass", async () => {
    const findings = await runProbe(options(url));
    expect(findings.filter((f) => f.status === "pass")).toEqual([]);
  });
});

describe("joinUrl origin pinning", async () => {
  const { joinUrl } = await import("../src/probe/http.js");
  it("never leaves the target origin", () => {
    expect(joinUrl("https://x.example.com", "//evil.example.net/hook")).toBe("https://x.example.com/hook");
  });
});
