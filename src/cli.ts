#!/usr/bin/env node
import { writeFile, appendFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import path from "node:path";
import { loadProject } from "./config.js";
import { deadlinesFor } from "./deadlines.js";
import { runStaticChecks } from "./static/checks.js";
import { runProbe } from "./probe/checks.js";
import { SHOP_DOMAIN_RE, verifyIpAllowlist } from "./probe/ip-allowlist.js";
import { oldestSupportedVersion } from "./api-versions.js";
import { toBadge, toJson, toMarkdown, toSarif, toText } from "./report/format.js";
import type { Distribution, Finding, Report } from "./types.js";

const VERSION = "0.2.0";
const DEFAULT_SHOP = "shopify-app-audit-probe.myshopify.com";

const HELP = `shopify-app-audit ${VERSION}

Check a Shopify app against Shopify's security deadlines, and probe the running
app for the attacks Shopify ranks highest.

Usage
  shopify-app-audit [check] [dir]        Static checks on the app's code and shopify.app.toml
  shopify-app-audit probe --url <url>    Send a few requests to a running app you own
  shopify-app-audit all [dir] --url <url>

Options
  --distribution <public|custom>  How the app is distributed (default: public)
  --config <file>                 App config file (default: shopify.app.toml)
  --format <text|json|markdown|sarif>  Output format (default: text)
  --output <file>                 Write the report to a file instead of stdout
  --badge <file>                  Also write a shields.io endpoint badge JSON
  --fail-on <fail|warn|none>      Exit 1 at this level or worse (default: fail)
  --today <YYYY-MM-DD>            Evaluate deadlines as of this date

Probe options
  --url <url>                     Base URL of the running app (default: application_url)
  --webhook-path <path>           Webhook route to test (repeatable; default: from shopify.app.toml)
  --proxy-path <path>             App proxy route to test (repeatable; default: from app_proxy.url)
  --app-path <path>               App route to test with a bare ?shop= (repeatable; default: /app)
  --shop <domain>                 Shop domain to put in probe requests (default: shopify-app-audit-probe.myshopify.com)
  --client-secret-env <name>      Env var holding the client secret, to also send one correctly signed webhook
  --timeout <ms>                  Per-request timeout (default: 10000)

IP allowlist check (any command)
  --admin-token-env <name>        Env var holding an Admin API access token for --shop. Calls the
                                  Admin API from this machine and passes only if Shopify returns 403

Only probe apps you own or have permission to test.
`;

function fail(message: string): never {
  process.stderr.write(`shopify-app-audit: ${message}\n`);
  process.exit(2);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      distribution: { type: "string", default: "public" },
      config: { type: "string" },
      format: { type: "string", default: "text" },
      output: { type: "string" },
      badge: { type: "string" },
      "fail-on": { type: "string", default: "fail" },
      today: { type: "string" },
      url: { type: "string" },
      "webhook-path": { type: "string", multiple: true },
      "proxy-path": { type: "string", multiple: true },
      "app-path": { type: "string", multiple: true },
      shop: { type: "string", default: DEFAULT_SHOP },
      "client-secret-env": { type: "string" },
      "admin-token-env": { type: "string" },
      timeout: { type: "string", default: "10000" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });
  if (values.help) return void process.stdout.write(HELP);
  if (values.version) return void process.stdout.write(`${VERSION}\n`);

  let [command, dir] = positionals;
  if (command && !["check", "probe", "all"].includes(command)) {
    dir = command;
    command = "check";
  }
  command ??= "check";
  dir ??= ".";

  const distribution = values.distribution as Distribution;
  if (!["public", "custom"].includes(distribution)) fail("--distribution must be public or custom");
  if (!["text", "json", "markdown", "sarif"].includes(values.format!)) fail("--format must be text, json, markdown or sarif");
  if (!["fail", "warn", "none"].includes(values["fail-on"]!)) fail("--fail-on must be fail, warn or none");
  const today = values.today ?? new Date().toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(today) || Number.isNaN(Date.parse(today))) fail("--today must be YYYY-MM-DD");
  const timeoutMs = Number(values.timeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) fail("--timeout must be a positive number of milliseconds");
  const shop = values.shop!.toLowerCase();
  if (!SHOP_DOMAIN_RE.test(shop)) fail("--shop must be a *.myshopify.com domain");
  const tokenEnv = values["admin-token-env"];
  const adminToken = tokenEnv ? process.env[tokenEnv] : undefined;
  if (tokenEnv && !adminToken) fail(`--admin-token-env ${tokenEnv} is not set`);
  if (adminToken && values.shop === DEFAULT_SHOP) fail("--admin-token-env needs --shop set to the store the token belongs to");

  const project = await loadProject(dir, values.config);
  const findings: Finding[] = [];
  if (command === "check" || command === "all") {
    findings.push(...(await runStaticChecks(project, distribution, today)));
  }

  let target: string | undefined;
  if (command === "probe" || command === "all") {
    target = values.url ?? project.config?.applicationUrl;
    if (!target) fail("probe needs --url (or application_url in shopify.app.toml)");
    let parsed: URL | undefined;
    try {
      parsed = new URL(target);
    } catch {
      fail(`--url is not a valid URL: ${target}`);
    }
    if (!/^https?:$/.test(parsed.protocol)) fail("--url must be an http or https URL");
    const webhookPaths =
      values["webhook-path"] ??
      [...new Set((project.config?.webhooks ?? []).map((w) => toPath(w.uri)).filter((p): p is string => Boolean(p)))];
    const proxyPaths =
      values["proxy-path"] ?? (project.config?.appProxy ? [toPath(project.config.appProxy.url) ?? "/"] : []);
    const secretEnv = values["client-secret-env"];
    findings.push(
      ...(await runProbe({
        target,
        webhookPaths: webhookPaths.length ? webhookPaths : ["/webhooks"],
        proxyPaths,
        appPaths: values["app-path"] ?? ["/app"],
        shop,
        otherShop: "shopify-app-audit-other.myshopify.com",
        clientSecret: secretEnv ? process.env[secretEnv] : undefined,
        timeoutMs,
      })),
    );
  }

  if (adminToken) {
    const verified = await verifyIpAllowlist({
      shop,
      accessToken: adminToken,
      apiVersion: oldestSupportedVersion(today),
      distribution,
      timeoutMs,
    });
    const manual = findings.findIndex((f) => f.id === "IP_ALLOWLIST");
    if (manual >= 0) findings.splice(manual, 1, verified);
    else findings.push(verified);
  }

  const report: Report = {
    tool: "shopify-app-audit",
    version: VERSION,
    generatedAt: new Date().toISOString(),
    today,
    distribution,
    appDir: command === "probe" ? undefined : path.relative(process.cwd(), project.dir) || ".",
    target,
    findings,
    deadlines: deadlinesFor(distribution),
  };

  const rendered =
    values.format === "json"
      ? toJson(report)
      : values.format === "markdown"
        ? toMarkdown(report)
        : values.format === "sarif"
          ? toSarif(report)
          : toText(report);
  if (values.output) await writeFile(values.output, `${rendered}\n`);
  else process.stdout.write(`${rendered}\n`);
  if (values.badge) await writeFile(values.badge, `${toBadge(report)}\n`);
  if (process.env.GITHUB_STEP_SUMMARY && values.format !== "markdown") {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, `${toMarkdown(report)}\n`).catch(() => undefined);
  }

  const failOn = values["fail-on"];
  const blocking = findings.some((f) => f.status === "fail" || (failOn === "warn" && f.status === "warn"));
  process.exitCode = failOn !== "none" && blocking ? 1 : 0;
}

function toPath(uri: string): string | undefined {
  if (!uri) return undefined;
  if (uri.startsWith("/")) return uri;
  try {
    const u = new URL(uri);
    if (!/^https?:$/.test(u.protocol)) return undefined;
    return `${u.pathname}${u.search}`;
  } catch {
    return undefined;
  }
}

main().catch((err) => fail(err instanceof Error ? err.stack ?? err.message : String(err)));
