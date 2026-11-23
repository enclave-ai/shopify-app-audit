import type { Distribution, Finding } from "../types.js";
import { request } from "./http.js";

const DOCS = "https://shopify.dev/docs/apps/build/security/credentials-and-data/restrict-api-access-to-your-ip-addresses";
export const SHOP_DOMAIN_RE = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;

export interface IpAllowlistOptions {
  shop: string;
  accessToken: string;
  apiVersion: string;
  distribution: Distribution;
  timeoutMs: number;
  endpoint?: string;
}

// Shopify's documented check: call the Admin API with one of the app's tokens
// from outside the allowed ranges and expect a 403.
export async function verifyIpAllowlist(options: IpAllowlistOptions): Promise<Finding> {
  if (!SHOP_DOMAIN_RE.test(options.shop)) throw new Error(`--shop must be a *.myshopify.com domain, got ${options.shop}`);
  const url = options.endpoint ?? `https://${options.shop}/admin/api/${options.apiVersion}/graphql.json`;
  const res = await request(url, {
    method: "POST",
    headers: { "content-type": "application/json", "x-shopify-access-token": options.accessToken },
    body: JSON.stringify({ query: "{ shop { id } }" }),
    timeoutMs: options.timeoutMs,
  });
  const base = { id: "IP_ALLOWLIST", title: "IP allowlist", docs: DOCS } as const;
  if (res.status === 403 && /access token|expir/i.test(res.body)) {
    return {
      ...base,
      status: "info",
      message: `Shopify rejected the token itself (403), not the IP, so the allowlist couldn't be tested. Use a current expiring access token for this shop.`,
    };
  }
  if (res.status === 403) {
    return {
      ...base,
      status: "pass",
      message: `Shopify rejected the app's token from this machine with 403, so an IP allowlist is enforced. This only proves it if this machine is outside your allowed ranges.`,
    };
  }
  if (res.status >= 200 && res.status < 300 && /"shop"\s*:\s*\{\s*"id"/.test(res.body)) {
    return {
      ...base,
      status: options.distribution === "public" ? "fail" : "warn",
      message: `The app's token called the Admin API from this machine. Either the app has no IP allowlist, or this machine's IP is in it. Run this from a laptop or CI runner outside your servers' ranges.`,
      fix: "Dev Dashboard > your app > Settings > IP allowlist. List your servers' egress IPs (NAT gateway), or your host's ASNs if they change.",
      deadlineId: options.distribution === "public" ? "ip-allowlist-public" : "ip-allowlist-custom-new",
    };
  }
  return {
    ...base,
    status: "info",
    message:
      res.status === 401
        ? "Shopify rejected the token itself (401), so the allowlist couldn't be tested. Use a current access token for this shop."
        : `Couldn't test the allowlist: ${res.error ? `request failed: ${res.error}` : `HTTP ${res.status}`}. Check it by hand in the Dev Dashboard.`,
  };
}
