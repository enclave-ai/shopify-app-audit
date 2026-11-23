export const SHOPIFY_SERVED = [
  /(^|\.)shopify\.com$/,
  /(^|\.)myshopify\.com$/,
  /(^|\.)shopifycdn\.com$/,
  /(^|\.)shopifysvc\.com$/,
  /(^|\.)shopifycloud\.com$/,
  /(^|\.)shop\.app$/,
];

export const NON_NETWORK_HOSTS = [
  /^www\.w3\.org$/,
  /^schema\.org$/,
  /^json-schema\.org$/,
  /^example\.(com|org|net)$/,
  /\.example\.(com|org|net)$/,
  /^localhost$/,
  /^127\.0\.0\.1$/,
  /^github\.com$/,
  /^reactjs\.org$/,
  /^react\.dev$/,
  /^developer\.mozilla\.org$/,
];

export function validateAllowedSource(entry: string): string | undefined {
  let url: URL;
  const probe = entry.replace("://*.", "://wildcard-placeholder.");
  try {
    url = new URL(probe);
  } catch {
    return "is not a valid URL";
  }
  if (url.protocol !== "https:") return "must use https://";
  if (url.pathname !== "/" || entry.endsWith("/")) return "must be an origin with no path or trailing slash";
  if (url.search || url.hash) return "must not include a query or fragment";
  if (entry.includes("*") && !entry.startsWith("https://*.")) return "wildcards are only allowed as the first label (https://*.example.com)";
  return undefined;
}

export function validateNavigationHost(entry: string): string | undefined {
  if (entry !== entry.toLowerCase()) return "must be lowercase";
  if (entry.includes("://")) return "must not include a scheme";
  if (entry.includes("*")) return "must not include a wildcard";
  if (/[:/?#]/.test(entry)) return "must be a bare host with no port or path";
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(entry)) return "is not a valid host";
  return undefined;
}

export function sourceCovers(entry: string, origin: string): boolean {
  if (entry === origin) return true;
  if (entry.startsWith("https://*.")) {
    const suffix = entry.slice("https://*".length);
    return (
      origin.startsWith("https://") &&
      origin.endsWith(suffix) &&
      origin.length > "https://".length + suffix.length
    );
  }
  return false;
}

export function isIgnoredHost(host: string): boolean {
  return [...SHOPIFY_SERVED, ...NON_NETWORK_HOSTS].some((re) => re.test(host));
}
