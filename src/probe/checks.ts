import type { Finding } from "../types.js";
import { appProxySignature, isLocalHost, joinUrl, request, webhookHmac, type ProbeResponse } from "./http.js";

export interface ProbeOptions {
  target: string;
  webhookPaths: string[];
  proxyPaths: string[];
  appPaths: string[];
  shop: string;
  otherShop: string;
  clientSecret?: string;
  timeoutMs: number;
}

const DOCS = {
  webhooks: "https://shopify.dev/docs/apps/build/webhooks/subscribe/https",
  proxy: "https://shopify.dev/docs/apps/build/online-store/app-proxies/authenticate-app-proxies",
  iframe: "https://shopify.dev/docs/apps/build/security/app-security-checks/static-frame-ancestors",
  shopParam: "https://shopify.dev/docs/apps/build/security",
};

const accepted = (res: ProbeResponse): boolean => res.status >= 200 && res.status < 300;
const rejected = (res: ProbeResponse): boolean =>
  res.status >= 400 && res.status < 500 && res.status !== 404 && res.status !== 405;
const missingRoute = (res: ProbeResponse): boolean => res.status === 404 || res.status === 405;

const describe = (res: ProbeResponse): string =>
  res.error ? `request failed: ${res.error}` : `HTTP ${res.status}`;

const WEBHOOK_BODY = JSON.stringify({ id: 9_999_999_999, note: "shopify-app-audit probe, not a real order" });

function webhookHeaders(shop: string, hmac: string): Record<string, string> {
  return {
    "content-type": "application/json",
    "x-shopify-topic": "orders/create",
    "x-shopify-shop-domain": shop,
    "x-shopify-api-version": "2026-10",
    "x-shopify-webhook-id": "00000000-0000-4000-8000-000000000000",
    "x-shopify-hmac-sha256": hmac,
  };
}

export async function probeWebhookHmac(options: ProbeOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const path of options.webhookPaths) {
    const url = joinUrl(options.target, path);
    const forged = await request(url, {
      method: "POST",
      headers: webhookHeaders(options.shop, webhookHmac("shopify-app-audit-wrong-secret", WEBHOOK_BODY)),
      body: WEBHOOK_BODY,
      timeoutMs: options.timeoutMs,
    });
    const missing = await request(url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-shopify-topic": "orders/create", "x-shopify-shop-domain": options.shop },
      body: WEBHOOK_BODY,
      timeoutMs: options.timeoutMs,
    });
    if (missingRoute(forged) && missingRoute(missing)) {
      findings.push({
        id: "WEBHOOK_HMAC",
        title: "Webhook endpoint not found",
        status: "skip",
        message: `${path} returned ${forged.status}, so no webhook handler took the request. Pass the real path with --webhook-path.`,
      });
      continue;
    }
    const bad = [
      accepted(forged) ? `a forged HMAC was accepted (${describe(forged)})` : "",
      accepted(missing) ? `a request with no HMAC header was accepted (${describe(missing)})` : "",
    ].filter(Boolean);
    if (bad.length) {
      findings.push({
        id: "WEBHOOK_HMAC",
        title: "Webhook accepted without a valid HMAC",
        status: "fail",
        message: `${path}: ${bad.join(", and ")}. Anyone who knows this URL can feed your app fake webhook payloads.`,
        fix: "Verify X-Shopify-Hmac-SHA256 against the raw request body with your client secret, using a timing-safe compare, before you read the payload.",
        docs: DOCS.webhooks,
        details: [`forged HMAC: ${describe(forged)}`, `no HMAC header: ${describe(missing)}`],
      });
    } else if (!rejected(forged) || !rejected(missing)) {
      findings.push({
        id: "WEBHOOK_HMAC",
        title: "Webhook probe inconclusive",
        status: "skip",
        message: `${path} didn't clearly reject the requests (forged HMAC: ${describe(forged)}, no HMAC: ${describe(missing)}). Expected a 4xx.`,
      });
    } else {
      findings.push({
        id: "WEBHOOK_HMAC",
        title: "Webhook HMAC verification",
        status: "pass",
        message: `${path} rejected both a forged HMAC (${describe(forged)}) and a missing one (${describe(missing)}).`,
      });
    }
    if (options.clientSecret && (url.startsWith("https://") || isLocalHost(url))) {
      const valid = await request(url, {
        method: "POST",
        headers: webhookHeaders(options.shop, webhookHmac(options.clientSecret, WEBHOOK_BODY)),
        body: WEBHOOK_BODY,
        timeoutMs: options.timeoutMs,
      });
      if (!accepted(valid) && !valid.error) {
        findings.push({
          id: "WEBHOOK_HMAC_VALID",
          title: "Correctly signed webhook was rejected",
          status: "info",
          message: `${path} returned ${valid.status} for a webhook signed with the client secret you passed. Expected if the shop isn't installed; otherwise check your raw-body handling.`,
          docs: DOCS.webhooks,
        });
      }
    }
  }
  return findings;
}

export async function probeAppProxy(options: ProbeOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const path of options.proxyPaths) {
    const params: Record<string, string> = {
      shop: options.shop,
      logged_in_customer_id: "",
      path_prefix: "/apps/audit",
      timestamp: String(Math.floor(Date.now() / 1000)),
    };
    const query = new URLSearchParams(params).toString();
    const unsigned = await request(joinUrl(options.target, path, query), { timeoutMs: options.timeoutMs });
    const forged = await request(
      joinUrl(options.target, path, `${query}&signature=${appProxySignature("shopify-app-audit-wrong-secret", params)}`),
      { timeoutMs: options.timeoutMs },
    );
    if (missingRoute(unsigned) && missingRoute(forged)) {
      findings.push({
        id: "APP_PROXY_SIGNATURE",
        title: "App proxy route not found",
        status: "skip",
        message: `${path} returned ${unsigned.status}. Pass the real path with --proxy-path.`,
      });
      continue;
    }
    if (accepted(unsigned) || accepted(forged)) {
      findings.push({
        id: "APP_PROXY_SIGNATURE",
        title: "App proxy route served without a valid signature",
        status: "fail",
        message: `${path} answered a request Shopify never signed (unsigned: ${describe(unsigned)}, forged signature: ${describe(forged)}), and it trusted the shop from the query string.`,
        fix: "Verify the signature parameter (sorted params, HMAC-SHA256 with the client secret) before responding, and check logged_in_customer_id owns the data you return.",
        docs: DOCS.proxy,
      });
    } else if (!rejected(unsigned) || !rejected(forged)) {
      findings.push({
        id: "APP_PROXY_SIGNATURE",
        title: "App proxy probe inconclusive",
        status: "skip",
        message: `${path} didn't clearly reject the requests (unsigned: ${describe(unsigned)}, forged: ${describe(forged)}). Expected a 4xx.`,
      });
    } else {
      findings.push({
        id: "APP_PROXY_SIGNATURE",
        title: "App proxy signature verification",
        status: "pass",
        message: `${path} rejected unsigned (${describe(unsigned)}) and forged (${describe(forged)}) requests.`,
      });
    }
  }
  return findings;
}

export async function probeShopParameter(options: ProbeOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const path of options.appPaths) {
    const own = await request(joinUrl(options.target, path, `shop=${encodeURIComponent(options.shop)}&embedded=1`), { timeoutMs: options.timeoutMs });
    const other = await request(joinUrl(options.target, path, `shop=${encodeURIComponent(options.otherShop)}&embedded=1`), { timeoutMs: options.timeoutMs });
    if (own.status === 404 && other.status === 404) continue;
    const looksLikeData = (res: ProbeResponse) =>
      accepted(res) && !/<title>\s*(login|install|authenticate)/i.test(res.body);
    if (looksLikeData(own) || looksLikeData(other)) {
      const jsonish = [own, other].some((r) => looksLikeData(r) && (r.headers["content-type"] ?? "").includes("json"));
      findings.push({
        id: "SHOP_PARAM_TRUST",
        title: "Route answered a request whose only identity was ?shop=",
        status: jsonish ? "fail" : "warn",
        message: `${path} returned ${describe(own)} for ${options.shop} and ${describe(other)} for ${options.otherShop}, with no session token, ID token or HMAC. ${jsonish ? "It returned JSON, so check what data it exposes." : "If the body is only an app-bridge bootstrap this is expected."}`,
        fix: "Take the shop from a verified session token, ID token, app proxy signature or webhook HMAC. Never from a request parameter, and scope every query by the authenticated shop.",
        docs: DOCS.shopParam,
        details: [
          `${options.shop}: ${describe(own)} ${own.headers["content-type"] ?? ""} ${own.body.length} bytes`,
          `${options.otherShop}: ${describe(other)} ${other.headers["content-type"] ?? ""} ${other.body.length} bytes`,
        ],
      });
    } else if ([own, other].some((r) => r.status === 0 || r.status >= 500)) {
      findings.push({
        id: "SHOP_PARAM_TRUST",
        title: "?shop= probe inconclusive",
        status: "skip",
        message: `${path} errored (${describe(own)}, ${describe(other)}), so it's unclear how it handles a bare ?shop=.`,
      });
    } else {
      findings.push({
        id: "SHOP_PARAM_TRUST",
        title: "Unauthenticated request with ?shop=",
        status: "pass",
        message: `${path} did not serve content for a bare ?shop= request (${describe(own)}).`,
      });
    }
  }
  return findings;
}

export async function probeHeaders(options: ProbeOptions): Promise<Finding[]> {
  const url = joinUrl(options.target, options.appPaths[0] ?? "/", `shop=${encodeURIComponent(options.shop)}&embedded=1`);
  const res = await request(url, { timeoutMs: options.timeoutMs, followRedirects: true });
  if (res.error || res.status >= 400) {
    return [
      {
        id: "FRAME_ANCESTORS",
        title: "Response headers",
        status: "skip",
        message: `${url} returned ${describe(res)}. Pass the embedded app's page with --app-path.`,
      },
    ];
  }
  const findings: Finding[] = [];
  const csp = res.headers["content-security-policy"] ?? "";
  const directive = /frame-ancestors([^;]*)/i.exec(csp)?.[1]?.trim();
  const permissive = directive !== undefined && /(^|\s)(\*|https:|http:)(\s|$)|https:\/\/\*\.myshopify\.com/.test(directive);
  if (!directive) {
    findings.push({
      id: "FRAME_ANCESTORS",
      title: "No frame-ancestors directive",
      status: "fail",
      message: `${url} responded without a Content-Security-Policy frame-ancestors directive${res.headers["x-frame-options"] ? ` (X-Frame-Options: ${res.headers["x-frame-options"]} is set, but Shopify requires frame-ancestors)` : ""}. An embedded app without it can be framed by any site.`,
      fix: "Call addDocumentResponseHeaders (React Router template) or send frame-ancestors https://admin.shopify.com https://<shop>.myshopify.com. Use 'none' for a standalone app.",
      docs: DOCS.iframe,
    });
  } else if (permissive) {
    findings.push({
      id: "FRAME_ANCESTORS",
      title: "frame-ancestors is permissive",
      status: "fail",
      message: `frame-ancestors ${directive} lets origins other than the authenticated shop's admin frame the app, which is what clickjacking needs.`,
      fix: "Name both origins explicitly: frame-ancestors https://admin.shopify.com https://<shop>.myshopify.com.",
      docs: DOCS.iframe,
    });
  } else {
    findings.push({
      id: "FRAME_ANCESTORS",
      title: "frame-ancestors directive",
      status: "pass",
      message: `frame-ancestors ${directive}`,
    });
  }

  if (res.url.startsWith("https://") && !res.headers["strict-transport-security"]) {
    findings.push({
      id: "HSTS",
      title: "No Strict-Transport-Security header",
      status: "warn",
      message: "The app serves over HTTPS but doesn't send HSTS, so a first request over HTTP isn't protected.",
      fix: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
      docs: "https://shopify.dev/docs/apps/launch/app-requirements-checklist",
    });
  }

  const target = new URL(options.target);
  if (target.protocol === "https:") {
    const plain = new URL(options.target);
    plain.protocol = "http:";
    const res2 = await request(plain.toString(), { timeoutMs: options.timeoutMs });
    if (accepted(res2)) {
      findings.push({
        id: "HTTP_PLAINTEXT",
        title: "App answers over plain HTTP",
        status: "fail",
        message: `${plain.toString()} returned ${res2.status} instead of redirecting to HTTPS.`,
        fix: "Redirect every HTTP request to HTTPS, or stop listening on port 80.",
        docs: "https://shopify.dev/docs/apps/launch/app-requirements-checklist",
      });
    }
  }
  return findings;
}

export async function runProbe(options: ProbeOptions): Promise<Finding[]> {
  const groups = await Promise.all([
    probeWebhookHmac(options),
    probeAppProxy(options),
    probeShopParameter(options),
    probeHeaders(options),
  ]);
  return groups.flat();
}
