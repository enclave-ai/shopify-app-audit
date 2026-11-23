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
    const text = await readCapped(res, MAX_BODY_BYTES);
    return {
      status: res.status,
      headers: Object.fromEntries([...res.headers.entries()].map(([k, v]) => [k.toLowerCase(), v])),
      body: text,
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

const MAX_BODY_BYTES = 64 * 1024;

async function readCapped(res: Response, max: number): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (size < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.byteLength;
    }
  } catch {
    // keep what we have
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).subarray(0, max).toString("utf8");
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

export function joinUrl(base: string, route: string, extraQuery?: string): string {
  const origin = new URL(base).origin;
  const resolved = new URL(route.startsWith("/") ? route : `/${route}`, origin);
  const url = new URL(`${resolved.pathname}${resolved.search}`, origin);
  if (extraQuery) url.search = url.search ? `${url.search}&${extraQuery}` : `?${extraQuery}`;
  return url.toString();
}

export const isLocalHost = (target: string): boolean =>
  ["localhost", "127.0.0.1", "[::1]"].includes(new URL(target).hostname);
