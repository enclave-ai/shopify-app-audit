const QUARTER_MONTHS = ["01", "04", "07", "10"];

const ENUM_MONTHS: Record<string, string> = {
  January: "01",
  April: "04",
  July: "07",
  October: "10",
};

// Each stable version is supported for at least 12 months after release.
// Shopify publishes the exact cutoff per version; 2026-10 is accessible until
// 2027-10-16, so we treat a version as supported until 12 months + 15 days.
export function versionEndOfLife(version: string): string | undefined {
  const match = /^(\d{4})-(\d{2})$/.exec(version);
  if (!match || !QUARTER_MONTHS.includes(match[2])) return undefined;
  const year = Number(match[1]) + 1;
  return `${year}-${match[2]}-16`;
}

export function isEndOfLife(version: string, today: string): boolean {
  const eol = versionEndOfLife(version);
  return eol !== undefined && eol <= today;
}

export function enumToVersion(name: string): string | undefined {
  const match = /^(January|April|July|October)(\d{2})$/.exec(name);
  if (!match) return undefined;
  return `20${match[2]}-${ENUM_MONTHS[match[1]]}`;
}

export function oldestSupportedVersion(today: string): string {
  const [y] = today.split("-").map(Number);
  for (let year = y - 2; year <= y + 1; year++) {
    for (const month of QUARTER_MONTHS) {
      const v = `${year}-${month}`;
      if (!isEndOfLife(v, today)) return v;
    }
  }
  return `${y}-01`;
}
