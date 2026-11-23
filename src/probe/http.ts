import { createHmac } from "node:crypto";

export interface ProbeResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  redirected: boolean;
  url: string;
  error?: string;
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  followRedirects?: boolean;
}

export async function request(url: string, options: RequestOptions = {}): Promise<ProbeResponse> {
  const { method = "GET", headers = {}, body, timeoutMs = 10_000, followRedirects = false } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers: { "user-agent": "shopify-app-audit (+https://github.com/enclave-ai/shopify-app-audit)", ...headers },
      body,
      redirect: followRedirects ? "follow" : "manual",
      signal: controller.signal,
    });
    const text = await res.text().catch(() => "");
    return {
      status: res.status,
      headers: Object.fromEntries([...res.headers.entries()].map(([k, v]) => [k.toLowerCase(), v])),
      body: text.slice(0, 20_000),
      redirected: res.status >= 300 && res.status < 400,
      url,
    };
  } catch (err) {
    return {
      status: 0,
      headers: {},
      body: "",
      redirected: false,
      url,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

export function webhookHmac(secret: string, rawBody: string): string {
  return createHmac("sha256", secret).update(rawBody, "utf8").digest("base64");
}

export function appProxySignature(secret: string, params: Record<string, string>): string {
  const sorted = Object.keys(params)
    .filter((k) => k !== "signature")
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("");
  return createHmac("sha256", secret).update(sorted, "utf8").digest("hex");
}

export function joinUrl(base: string, pathname: string): string {
  const url = new URL(base);
  const prefix = url.pathname.replace(/\/$/, "");
  url.pathname = `${prefix}${pathname.startsWith("/") ? pathname : `/${pathname}`}`;
  return url.toString();
}
