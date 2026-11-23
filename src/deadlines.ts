import type { Deadline, Distribution } from "./types.js";

const HUB = "https://shopify.dev/docs/apps/build/security";

export const DEADLINES: Deadline[] = [
  {
    id: "ip-allowlist-bulk",
    date: "2026-11-12",
    scope: ["public"],
    feature: "IP allowlist (bulk operations)",
    consequence: "Bulk queries and bulk mutations are blocked for apps without an IP allowlist.",
    source: HUB,
  },
  {
    id: "ip-allowlist-public",
    date: "2026-11-20",
    scope: ["public"],
    feature: "IP allowlist",
    consequence: "Delisted from the App Store, blocked from new installs, flagged to merchants.",
    source: HUB,
  },
  {
    id: "ip-allowlist-custom-new",
    date: "2026-11-20",
    scope: ["custom"],
    feature: "IP allowlist",
    consequence: "Can't install the app on a store outside your organization without an IP allowlist.",
    source: HUB,
  },
  {
    id: "partner-mfa",
    date: "2026-11-19",
    scope: ["public", "custom"],
    feature: "MFA on every partner account",
    consequence: "Required on all partner accounts. Shopify recommends passkeys.",
    source: "https://shopify.dev/changelog/blog/app-security-updates-ip-allowlist-due-tomorrow",
  },
  {
    id: "network-access-deploy",
    date: "2026-12-01",
    scope: ["public", "custom"],
    feature: "Network access declaration",
    consequence: "Deploys (and App Store submissions) are rejected for storefront apps without [network_access] allowed_sources.",
    source: "https://shopify.dev/docs/apps/build/security/storefront/declare-network-access",
  },
  {
    id: "expiring-tokens-new-custom",
    date: "2026-12-01",
    scope: ["custom"],
    feature: "Expiring offline access tokens",
    consequence: "Custom and merchant-created apps created on or after this date must use expiring offline tokens.",
    source: "https://shopify.dev/docs/apps/build/authentication-authorization/migrate-to-expiring-offline-access-tokens",
  },
  {
    id: "abandoned-checkout-url-public",
    date: "2026-12-01",
    scope: ["public"],
    feature: "abandonedCheckoutUrl needs level 2 protected customer data",
    consequence: "Queries selecting the recovery URL fail without approval for name, email, phone and address.",
    source: "https://shopify.dev/changelog/posts/abandonedcheckouturl-now-requires-level-2-protected-customer-data-access",
  },
  {
    id: "expiring-tokens-public",
    date: "2027-01-01",
    scope: ["public"],
    feature: "Expiring offline access tokens",
    consequence: "Apps on non-expiring offline tokens are delisted and blocked from new installs.",
    source: "https://shopify.dev/docs/apps/build/authentication-authorization/migrate-to-expiring-offline-access-tokens",
  },
  {
    id: "ip-allowlist-custom-all",
    date: "2027-01-01",
    scope: ["custom"],
    feature: "IP allowlist (existing installs)",
    consequence: "One app without an allowlist blocks installing any of your apps outside your organization.",
    source: HUB,
  },
  {
    id: "network-access-delist",
    date: "2027-01-01",
    scope: ["public", "custom"],
    feature: "Network access declaration",
    consequence: "Public storefront apps without a declaration are delisted. Custom apps can't be installed outside your organization.",
    source: "https://shopify.dev/docs/apps/build/security/storefront/declare-network-access",
  },
  {
    id: "abandoned-checkout-url-custom",
    date: "2027-01-01",
    scope: ["custom"],
    feature: "abandonedCheckoutUrl needs level 2 protected customer data",
    consequence: "Enable name, email, phone and address in the Dev Dashboard, or the field fails.",
    source: "https://shopify.dev/changelog/posts/abandonedcheckouturl-now-requires-level-2-protected-customer-data-access",
  },
  {
    id: "script-tags-off",
    date: "2027-03-01",
    scope: ["public", "custom"],
    feature: "Script tags stop loading",
    consequence: "Shopify stops injecting script tags. Move to theme app extension embeds or a web pixel.",
    source: HUB,
  },
  {
    id: "expiring-tokens-403",
    date: "2027-04-01",
    scope: ["public"],
    feature: "Expiring offline access tokens",
    consequence: "Admin API requests with a non-expiring offline token return 403.",
    source: "https://shopify.dev/docs/apps/build/authentication-authorization/migrate-to-expiring-offline-access-tokens",
  },
];

export function deadlinesFor(distribution: Distribution): Deadline[] {
  return DEADLINES.filter((d) => d.scope.includes(distribution)).sort((a, b) =>
    a.date.localeCompare(b.date),
  );
}

export function deadlineById(id: string | undefined): Deadline | undefined {
  return DEADLINES.find((d) => d.id === id);
}

export function daysUntil(date: string, today: string): number {
  const ms = Date.parse(`${date}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`);
  return Math.round(ms / 86_400_000);
}

export function relativeDay(date: string, today: string): string {
  const days = daysUntil(date, today);
  if (days === 0) return "today";
  if (days > 0) return `in ${days} day${days === 1 ? "" : "s"}`;
  return `${-days} day${days === -1 ? "" : "s"} ago`;
}
