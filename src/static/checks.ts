import type { AppProject } from "../config.js";
import type { Distribution, Finding, Location } from "../types.js";
import { isInEffect } from "../deadlines.js";
import { enumToVersion, isEndOfLife, oldestSupportedVersion, versionEndOfLife } from "../api-versions.js";
import { SourceIndex, notTest, uniqueByFile, type Match } from "./scan.js";
import {
  isIgnoredHost,
  sourceCovers,
  validateAllowedSource,
  validateNavigationHost,
} from "./network.js";

export interface StaticContext {
  project: AppProject;
  index: SourceIndex;
  distribution: Distribution;
  today: string;
}

type Check = (ctx: StaticContext) => Promise<Finding[]>;

const DOCS = {
  hub: "https://shopify.dev/docs/apps/build/security",
  tokens: "https://shopify.dev/docs/apps/build/authentication-authorization/migrate-to-expiring-offline-access-tokens",
  network: "https://shopify.dev/docs/apps/build/security/storefront/declare-network-access",
  networkRef: "https://shopify.dev/docs/apps/build/cli-for-apps/app-configuration",
  versions: "https://shopify.dev/docs/api/usage/versioning",
  abandoned: "https://shopify.dev/changelog/posts/abandonedcheckouturl-now-requires-level-2-protected-customer-data-access",
  bulk: "https://shopify.dev/changelog/blog/app-security-updates-thank-you-plus-what-s-required-next",
  compliance: "https://shopify.dev/docs/apps/build/compliance/privacy-law-compliance",
  webhooks: "https://shopify.dev/docs/apps/build/webhooks/subscribe/https",
  mfa: "https://shopify.dev/changelog/blog/app-security-updates-ip-allowlist-due-tomorrow",
};

const configLocation = (ctx: StaticContext, needle?: string): Location[] => {
  const config = ctx.project.config;
  if (!config) return [];
  if (!needle) return [{ file: config.file }];
  const idx = config.raw.indexOf(needle);
  return [{ file: config.file, line: idx < 0 ? undefined : config.raw.slice(0, idx).split("\n").length }];
};

const codeFile = (f: string) => notTest(f) && !f.endsWith(".liquid");

export const checkConfigPresent: Check = async (ctx) => {
  if (ctx.project.config) return [];
  return [
    {
      id: "APP_CONFIG",
      title: "No shopify.app.toml found",
      status: "warn",
      message:
        "Config-based checks (network access, webhooks, scopes, HTTPS URLs) were skipped. Run from the app root or pass --config.",
      docs: DOCS.networkRef,
    },
  ];
};

export const checkExpiringTokens: Check = async (ctx) => {
  const { index, distribution } = ctx;
  const deadlineId = distribution === "public" ? "expiring-tokens-public" : "expiring-tokens-new-custom";
  const base = {
    id: "EXPIRING_OFFLINE_TOKENS",
    title: "Expiring offline access tokens",
    docs: DOCS.tokens,
    deadlineId,
  };
  const missStatus = distribution === "public" ? "fail" : "warn";
  const disabled = await index.search(/expiringOfflineAccessTokens\s*:\s*false/, codeFile);
  if (disabled.length) {
    return [
      {
        ...base,
        status: missStatus,
        message: "expiringOfflineAccessTokens is explicitly set to false.",
        fix: "Set future: { expiringOfflineAccessTokens: true } and persist the refresh token in session storage.",
        locations: uniqueByFile(disabled),
      },
    ];
  }

  const findings: Finding[] = [];
  const manualExchange = await index.search(/\/admin\/oauth\/access_token/, codeFile);
  const nonExpiringExchange: Match[] = [];
  for (const m of manualExchange) {
    const text = await index.read(m.file);
    if (!/expiring/.test(text)) nonExpiringExchange.push(m);
  }
  if (nonExpiringExchange.length) {
    findings.push({
      ...base,
      status: missStatus,
      message: "Your own OAuth code requests /admin/oauth/access_token without expiring=1, so it gets a non-expiring offline token.",
      fix: "Add expiring=1 to the token request, store the refresh_token and refresh before expires_in runs out.",
      locations: uniqueByFile(nonExpiringExchange),
    });
  }

  const enabled = await index.search(/expiringOfflineAccessTokens\s*:\s*true/, codeFile);
  if (enabled.length) {
    const prismaFiles = ctx.project.files.filter((f) => f.endsWith(".prisma"));
    for (const file of prismaFiles) {
      const text = await index.read(file);
      const model = /model\s+Session\s*\{([\s\S]*?)\n\}/.exec(text);
      if (model && !/\brefreshToken\b/.test(model[1])) {
        findings.push({
          ...base,
          status: "fail",
          message: "Expiring tokens are on, but the Prisma Session model has no refreshToken field, so tokens expire with nothing to renew them.",
          fix: "Add expires DateTime?, refreshToken String? and refreshTokenExpires DateTime? to model Session and migrate.",
          locations: [{ file, line: text.slice(0, model.index).split("\n").length }],
        });
      }
    }
    if (!findings.length) {
      findings.push({ ...base, status: "pass", message: "expiringOfflineAccessTokens is enabled.", locations: uniqueByFile(enabled, 3) });
    }
    return findings;
  }

  if (!findings.length) {
    const shopifyApp = await index.search(/\bshopifyApp\s*\(/, codeFile);
    if (shopifyApp.length) {
      findings.push({
        ...base,
        status: "warn",
        message: "shopifyApp() doesn't set expiringOfflineAccessTokens. Confirm your library version requests expiring tokens by default.",
        fix: "Set future: { expiringOfflineAccessTokens: true } explicitly so the intent is visible and enforced.",
        locations: uniqueByFile(shopifyApp, 3),
      });
    } else {
      findings.push({
        ...base,
        status: "info",
        manual: true,
        message: "Couldn't find token code to check. Confirm the app only uses expiring offline tokens, then turn on the Admin API token expiry card in Dev Dashboard settings.",
      });
    }
  }
  return findings;
};

const STOREFRONT_SCOPES = ["write_themes", "write_open_pixels"];
const SCRIPT_TAG_SCOPES = ["write_script_tags", "read_script_tags"];

const URL_RE = /(href\s*=\s*["']?)?\b(https?):\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(:\d+)?/gi;
const COMMENT_LINE = /^\s*(\/\/|\*|#|<!--|\{%-?\s*comment)/;

async function collectStorefrontUrls(ctx: StaticContext, files: string[]) {
  const sources = new Map<string, Location[]>();
  const navigation = new Map<string, Location[]>();
  for (const file of files) {
    const raw = await ctx.index.read(file);
    const text = !/\.s?css$/.test(file) ? raw : raw.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, " "));
    const lines = text.split("\n");
    lines.forEach((lineText, i) => {
      if (COMMENT_LINE.test(lineText)) return;
      for (const m of lineText.matchAll(URL_RE)) {
        const [, href, scheme, hostRaw] = m;
        let port = m[4] ?? "";
        const host = hostRaw.toLowerCase();
        if (isIgnoredHost(host)) continue;
        const loc = { file, line: i + 1 };
        const before = lineText.slice(0, m.index);
        const linkStart = before.search(/<link\b[^>]*$/i);
        if (linkStart >= 0) {
          const tag = lineText.slice(linkStart, lineText.indexOf(">", m.index) + 1 || undefined);
          if (/\brel\s*=\s*["']?(alternate|canonical|author|help|license|next|prev|search|me|shortlink)["'\s>]/i.test(tag)) continue;
        }
        const defaultPort = (scheme.toLowerCase() === "https" && port === ":443") || (scheme.toLowerCase() === "http" && port === ":80");
        if (defaultPort) port = "";
        if (href && linkStart < 0) {
          const list = navigation.get(host) ?? [];
          list.push(loc);
          navigation.set(host, list);
        } else {
          const origin = `${scheme.toLowerCase()}://${host}${port}`;
          const list = sources.get(origin) ?? [];
          list.push(loc);
          sources.set(origin, list);
        }
      }
    });
  }
  return { sources, navigation };
}

export const checkNetworkAccess: Check = async (ctx) => {
  const { project, index } = ctx;
  const config = project.config;
  if (!config) return [];
  const triggers: string[] = [];
  const themeExts = project.extensions.filter((e) => e.types.includes("theme"));
  const pixelExts = project.extensions.filter((e) => e.types.some((t) => t.includes("pixel")));
  if (themeExts.length) triggers.push(`theme app extension (${themeExts.map((e) => e.dir).join(", ")})`);
  if (config.appProxy) triggers.push("app proxy");
  for (const s of STOREFRONT_SCOPES) if (config.scopes.includes(s)) triggers.push(`${s} scope`);
  const scriptTagScope = config.scopes.find((s) => SCRIPT_TAG_SCOPES.includes(s));
  if (scriptTagScope) triggers.push(`${scriptTagScope} scope`);
  const scriptTagCode = await index.search(/\bscriptTagCreate\b/, codeFile);
  if (scriptTagCode.length && !scriptTagScope) triggers.push("script tags");

  const base = {
    id: "NETWORK_ACCESS",
    title: "Network access declaration",
    docs: DOCS.network,
    deadlineId: "network-access-deploy",
  };

  if (!triggers.length) {
    return [{ ...base, status: "pass", message: "The app doesn't run code on the online store, so no declaration is required.", deadlineId: undefined }];
  }

  const findings: Finding[] = [];
  const na = config.networkAccess;
  const sources = na?.allowedSources;
  if (!Array.isArray(sources)) {
    findings.push({
      ...base,
      status: "fail",
      message: `The app runs on the online store (${triggers.join("; ")}) but shopify.app.toml has no [network_access] allowed_sources.`,
      fix: 'Add [network_access] with allowed_sources listing every external HTTPS origin your storefront code loads from or calls. Use allowed_sources = [] if there are none.',
      locations: configLocation(ctx),
    });
  }

  const sourceList = Array.isArray(sources) ? sources : [];
  const navList = Array.isArray(na?.allowedNavigationHosts) ? (na!.allowedNavigationHosts as unknown[]) : [];
  const invalid: string[] = [];
  if (sourceList.length > 30) invalid.push(`allowed_sources has ${sourceList.length} entries; the limit is 30.`);
  if (navList.length > 30) invalid.push(`allowed_navigation_hosts has ${navList.length} entries; the limit is 30.`);
  for (const e of sourceList) {
    const err = typeof e === "string" ? validateAllowedSource(e) : "is not a string";
    if (err) invalid.push(`allowed_sources "${String(e)}" ${err}.`);
  }
  for (const e of navList) {
    const err = typeof e === "string" ? validateNavigationHost(e) : "is not a string";
    if (err) invalid.push(`allowed_navigation_hosts "${String(e)}" ${err}.`);
  }
  if (invalid.length) {
    findings.push({
      ...base,
      status: "fail",
      message: "Some [network_access] entries break Shopify's rules, so `shopify app deploy` will reject them.",
      details: invalid,
      docs: DOCS.networkRef,
      locations: configLocation(ctx, "[network_access]"),
    });
  }

  const extDirs = [...themeExts, ...pixelExts].map((e) => `${e.dir}/`);
  const proxyFiles = (await index.search(/\bappProxy\s*\(/, codeFile)).map((m) => m.file);
  const storefrontFiles = project.files.filter(
    (f) => notTest(f) && (extDirs.some((d) => f.startsWith(d)) || proxyFiles.includes(f)),
  );
  const { sources: used, navigation } = await collectStorefrontUrls(ctx, storefrontFiles);
  const declared = sourceList.filter((s): s is string => typeof s === "string");
  const undeclared = [...used.entries()].filter(([origin]) => !declared.some((d) => sourceCovers(d, origin)));
  if (undeclared.length) {
    findings.push({
      ...base,
      status: Array.isArray(sources) ? "fail" : "warn",
      title: "Storefront code calls hosts that aren't declared",
      message: `Found ${undeclared.length} external origin${undeclared.length === 1 ? "" : "s"} in storefront code that ${undeclared.length === 1 ? "isn't" : "aren't"} in allowed_sources. Shopify flags requests to undeclared hosts.`,
      details: undeclared.map(([origin, locs]) => `${origin}  (${locs[0].file}:${locs[0].line})${origin.startsWith("http://") ? "  plain HTTP, switch to HTTPS" : ""}`),
      fix: "Add each origin to [network_access] allowed_sources, or stop loading it on the storefront.",
      locations: undeclared.flatMap(([, locs]) => locs.slice(0, 1)).slice(0, 10),
    });
  }
  const navDeclared = navList.filter((s): s is string => typeof s === "string");
  const navMissing = [...navigation.entries()].filter(([host]) => !navDeclared.includes(host));
  if (navMissing.length) {
    findings.push({
      ...base,
      id: "NETWORK_ACCESS",
      status: "info",
      title: "Storefront links to hosts not in allowed_navigation_hosts",
      message: "Customers see an exit interstitial for these links. Optional, but list hosts you control.",
      details: navMissing.map(([host, locs]) => `${host}  (${locs[0].file}:${locs[0].line})`),
      deadlineId: undefined,
    });
  }

  if (!findings.length) {
    findings.push({
      ...base,
      status: "pass",
      message: `Declared ${declared.length} allowed source${declared.length === 1 ? "" : "s"}, and every external origin found in storefront code is covered.`,
    });
  }
  return findings;
};

export const checkScriptTags: Check = async (ctx) => {
  const { index, project } = ctx;
  const code = await index.search(/\b(scriptTagCreate|scriptTagUpdate|scriptTags\s*\(|ScriptTag\b|script_tags(\.json)?\b)/, codeFile);
  const scope = project.config?.scopes.filter((s) => SCRIPT_TAG_SCOPES.includes(s)) ?? [];
  if (!code.length && !scope.length) return [];
  return [
    {
      id: "SCRIPT_TAGS",
      title: "Script tags stop loading on March 1, 2027",
      status: "fail",
      message: [
        scope.length ? `Requests ${scope.join(", ")}.` : "",
        code.length ? `Uses the ScriptTag API in ${new Set(code.map((m) => m.file)).size} file(s).` : "",
      ]
        .filter(Boolean)
        .join(" "),
      fix: "Move storefront JavaScript to an app embed block in a theme app extension, or a web pixel for analytics. Then drop the script tag scopes.",
      docs: DOCS.hub,
      deadlineId: "script-tags-off",
      locations: [...(scope.length ? configLocation(ctx, scope[0]) : []), ...uniqueByFile(code)],
    },
  ];
};

export const checkApiVersions: Check = async (ctx) => {
  const { index, project, today } = ctx;
  const found = new Map<string, Location[]>();
  const add = (version: string, loc: Location) => {
    const list = found.get(version) ?? [];
    list.push(loc);
    found.set(version, list);
  };
  const config = project.config;
  if (config?.webhooksApiVersion) add(config.webhooksApiVersion, configLocation(ctx, config.webhooksApiVersion)[0]);
  for (const m of await index.search(/ApiVersion\.((?:January|April|July|October)\d{2})\b/, codeFile)) {
    const v = enumToVersion(m.groups[0]);
    if (v) add(v, m);
  }
  for (const m of await index.search(/\/admin\/api\/(\d{4}-\d{2})\//, codeFile)) add(m.groups[0], m);
  for (const m of await index.search(/\bapi_?[vV]ersion["']?\s*[:=]>?\s*["'](\d{4}-\d{2})["']/, codeFile)) add(m.groups[0], m);

  const eol = [...found.entries()].filter(([v]) => isEndOfLife(v, today));
  if (!eol.length) return [];
  return [
    {
      id: "EOL_API_VERSION",
      title: "End-of-life Admin API version",
      status: "warn",
      message: `Pins ${eol.map(([v]) => v).join(", ")}. Shopify silently falls forward to the oldest supported version (${oldestSupportedVersion(today)}), so behavior can change under you.`,
      details: eol.map(([v]) => `${v} reached end of life around ${versionEndOfLife(v)}`),
      fix: "Upgrade to a supported stable version and test against its release notes.",
      docs: DOCS.versions,
      locations: eol.flatMap(([, locs]) => locs).slice(0, 10),
    },
  ];
};

export const checkAbandonedCheckoutUrl: Check = async (ctx) => {
  const matches = await ctx.index.search(/\b(abandonedCheckoutUrl|abandoned_checkout_url)\b/, codeFile);
  if (!matches.length) return [];
  return [
    {
      id: "ABANDONED_CHECKOUT_URL",
      title: "Reads the abandoned checkout recovery URL",
      status: "warn",
      message:
        "The recovery URL now needs approval for all four protected customer fields (name, email, phone, address). Without it, GraphQL queries selecting the field fail.",
      fix:
        ctx.distribution === "public"
          ? "Request level 2 protected customer data access (data protection review), or stop reading the field."
          : "Enable read_customer_name, email, phone and address in the Dev Dashboard, or stop reading the field.",
      docs: DOCS.abandoned,
      deadlineId: ctx.distribution === "public" ? "abandoned-checkout-url-public" : "abandoned-checkout-url-custom",
      locations: uniqueByFile(matches),
    },
  ];
};

export const checkBulkOperations: Check = async (ctx) => {
  const matches = await ctx.index.search(/\b(bulkOperationRunQuery|bulkOperationRunMutation)\b/, codeFile);
  if (!matches.length) return [];
  return [
    {
      id: "BULK_OPERATIONS",
      title: "Uses bulk operations",
      status: "info",
      manual: true,
      message:
        "Bulk operations need an IP allowlist, and must be enabled under API access requests. If the app doesn't start one for 31 days, enable it again.",
      docs: DOCS.bulk,
      deadlineId: ctx.distribution === "public" ? "ip-allowlist-bulk" : undefined,
      locations: uniqueByFile(matches, 5),
    },
  ];
};

export const checkHttpsUrls: Check = async (ctx) => {
  const config = ctx.project.config;
  if (!config) return [];
  const urls: Array<[string, string]> = [];
  if (config.applicationUrl) urls.push(["application_url", config.applicationUrl]);
  config.redirectUrls.forEach((u) => urls.push(["auth.redirect_urls", u]));
  config.webhooks.forEach((w) => urls.push(["webhooks.subscriptions.uri", w.uri]));
  if (config.appProxy) urls.push(["app_proxy.url", config.appProxy.url]);
  const insecure = urls.filter(([, u]) => /^http:\/\//i.test(u));
  if (!insecure.length) return [];
  return [
    {
      id: "HTTPS_URLS",
      title: "Configured URL isn't HTTPS",
      status: "fail",
      message: "Shopify sends tokens, webhooks and proxy requests to these URLs. They must use HTTPS.",
      details: insecure.map(([k, u]) => `${k} = ${u}`),
      docs: DOCS.webhooks,
      locations: insecure.map(([, u]) => configLocation(ctx, u)[0]),
    },
  ];
};

const COMPLIANCE_TOPICS = ["customers/data_request", "customers/redact", "shop/redact"];

export const checkComplianceWebhooks: Check = async (ctx) => {
  const config = ctx.project.config;
  if (!config || ctx.distribution !== "public") return [];
  const subscribed = new Set(config.webhooks.flatMap((w) => w.complianceTopics));
  const missing = COMPLIANCE_TOPICS.filter((t) => !subscribed.has(t));
  if (!missing.length) return [];
  const handledInCode = await ctx.index.search(/(CUSTOMERS_DATA_REQUEST|CUSTOMERS_REDACT|SHOP_REDACT)/, codeFile);
  return [
    {
      id: "COMPLIANCE_WEBHOOKS",
      title: "Missing mandatory compliance webhooks",
      status: handledInCode.length ? "warn" : "fail",
      message: `shopify.app.toml doesn't subscribe to ${missing.join(", ")}. Public apps must handle all three to pass App Store review.`,
      fix: 'Add a [[webhooks.subscriptions]] entry with compliance_topics = ["customers/data_request", "customers/redact", "shop/redact"] and verify their HMAC.',
      docs: DOCS.compliance,
      locations: configLocation(ctx, "[webhooks]"),
    },
  ];
};

export const checkManual: Check = async (ctx) => {
  const findings: Finding[] = [
    {
      id: "IP_ALLOWLIST",
      title: "IP allowlist",
      status: "info",
      manual: true,
      message: `${
        ctx.distribution === "public"
          ? `${isInEffect("2026-11-20", ctx.today) ? "Required now" : "Required from November 20, 2026"}: public apps without an IP allowlist are delisted and blocked from new installs.`
          : `${isInEffect("2026-11-20", ctx.today) ? "Required now" : "Required from November 20, 2026"} to install a custom app outside your organization, and for every installed app from January 1, 2027.`
      } Verify it with --shop <your-dev-store>.myshopify.com --admin-token-env <VAR>, which calls the Admin API from this machine and expects a 403.`,
      fix: "Dev Dashboard > your app > Settings > IP allowlist. List your servers' egress IPs (NAT gateway), or your host's ASNs if they change.",
      docs: "https://shopify.dev/docs/apps/build/security/credentials-and-data/restrict-api-access-to-your-ip-addresses",
      deadlineId: ctx.distribution === "public" ? "ip-allowlist-public" : "ip-allowlist-custom-new",
    },
    {
      id: "PARTNER_MFA",
      title: "MFA on every account that can change the app",
      status: "info",
      manual: true,
      message: `${isInEffect("2026-11-19", ctx.today) ? "Required now" : "Required from November 19, 2026"} on partner accounts, and can't be checked from code. Also cover hosting, CDN, code repos and email.`,
      fix: "Use passkeys where supported, MFA elsewhere, and remove people who left.",
      docs: DOCS.mfa,
      deadlineId: "partner-mfa",
    },
  ];
  return findings;
};

async function checkRemoteCode(ctx: StaticContext): Promise<Finding[]> {
  const storefront = (f: string) => notTest(f) && f.startsWith("extensions/");
  const matches = await ctx.index.search(
    /\b(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[a-zA-Z_$][\w$.]*\s*[,)]|insertAdjacentHTML\s*\(|document\.write\s*\(|\.innerHTML\s*=|\.outerHTML\s*=)/,
    storefront,
  );
  const liquidRaw = await ctx.index.search(/\{\{[^}]*\|\s*(json|raw)\s*\}\}|\{\{[^}|]*(block|app)\.settings\.[^}|]*\}\}\s*<\/script>/, (f) => storefront(f) && f.endsWith(".liquid"));
  const all = [...matches, ...liquidRaw];
  if (!all.length) return [];
  return [
    {
      id: "STOREFRONT_REMOTE_CODE",
      title: "Storefront code turns strings into code or HTML",
      status: "warn",
      message: `Found ${all.length} place(s) in extensions that run strings as code or write raw HTML (eval, new Function, innerHTML, document.write). If any of those strings come from your servers or merchant settings, whoever controls them controls the checkout page. That is the pattern behind the October 2026 fake-checkout redirects.`,
      fix: "Ship code only in extension assets. Treat fetched config as data: use textContent, build DOM nodes, and allowlist URLs. Escape merchant settings in Liquid.",
      docs: DOCS.hub,
      details: all.slice(0, 8).map((m) => `${m.file}:${m.line}  ${m.text.trim().slice(0, 100)}`),
      locations: uniqueByFile(all),
    },
  ];
}

export const STATIC_CHECKS: Check[] = [
  checkRemoteCode,
  checkConfigPresent,
  checkExpiringTokens,
  checkNetworkAccess,
  checkScriptTags,
  checkAbandonedCheckoutUrl,
  checkApiVersions,
  checkHttpsUrls,
  checkComplianceWebhooks,
  checkBulkOperations,
  checkManual,
];

export async function runStaticChecks(
  project: AppProject,
  distribution: Distribution,
  today: string,
): Promise<Finding[]> {
  const ctx: StaticContext = { project, index: new SourceIndex(project), distribution, today };
  const out: Finding[] = [];
  for (const check of STATIC_CHECKS) out.push(...(await check(ctx)));
  return out;
}
