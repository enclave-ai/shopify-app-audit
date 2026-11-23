import pc from "picocolors";
import { daysUntil, deadlineById, deadlinePhrase, relativeDay } from "../deadlines.js";

import type { Finding, Report, Status } from "../types.js";

export const ENCLAVE_SCAN_URL = "https://app.enclave.ai/login?utm_source=shopify-app-audit&utm_campaign=shopify-app-audit";

const ORDER: Status[] = ["fail", "warn", "info", "pass", "skip"];

export const sortFindings = (findings: Finding[]): Finding[] =>
  [...findings].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));

export const counts = (findings: Finding[]) =>
  Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => f.status === s).length])) as Record<Status, number>;

const color = (status: Status, text: string) =>
  ({ fail: pc.red, warn: pc.yellow, info: pc.cyan, pass: pc.green, skip: pc.dim })[status](text);

const loc = (f: Finding) =>
  (f.locations ?? []).map((l) => (l.line ? `${l.file}:${l.line}` : l.file));

const ICON: Record<Status, string> = { fail: "✖", warn: "▲", info: "○", pass: "✔", skip: "–" };
const SECTION: Record<Status, string> = {
  fail: "Blocking",
  warn: "Warnings",
  info: "To do by hand",
  pass: "Passed",
  skip: "Skipped",
};

function verdict(report: Report): string {
  const c = counts(report.findings);
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (c.fail) return pc.red(pc.bold(`✖ ${plural(c.fail, "blocking issue")}`)) + pc.dim(`  ${plural(c.warn, "warning")}, ${c.info} to do by hand`);
  if (c.warn) return pc.yellow(pc.bold(`▲ ${plural(c.warn, "warning")}`)) + pc.dim(`  nothing blocking, ${c.info} to do by hand`);
  return pc.green(pc.bold("✔ Nothing blocking")) + pc.dim(`  ${c.info} to do by hand`);
}

export function toText(report: Report): string {
  const out: string[] = [];
  const indent = "    ";
  out.push(`${pc.bold("shopify-app-audit")} ${pc.dim(`${report.version} · ${report.distribution} app · ${report.today}`)}`);
  if (report.appDir) out.push(pc.dim(`app     ${report.appDir}`));
  if (report.target) out.push(pc.dim(`target  ${report.target}`));
  out.push("");
  out.push(verdict(report));
  out.push("");

  out.push(pc.bold("Shopify deadlines"));
  for (const d of report.deadlines) {
    const days = daysUntil(d.date, report.today);
    const when = days <= 0 ? pc.red("in effect".padEnd(11)) : days <= 14 ? pc.yellow(`${days}d`.padEnd(11)) : pc.dim(`${days}d`.padEnd(11));
    out.push(`  ${days <= 0 ? pc.red("●") : pc.dim("○")} ${pc.dim(d.date)}  ${when}${days <= 0 ? d.feature : pc.dim(d.feature)}`);
  }

  const sorted = sortFindings(report.findings);
  for (const status of ["fail", "warn", "info"] as Status[]) {
    const group = sorted.filter((f) => f.status === status);
    if (!group.length) continue;
    out.push("");
    out.push(pc.bold(`${SECTION[status]} (${group.length})`));
    group.forEach((f, i) => {
      if (i) out.push("");
      out.push(`${color(f.status, ICON[f.status])} ${pc.bold(f.title)} ${pc.dim(f.id)}`);
      out.push(`${indent}${f.message}`);
      const deadline = deadlineById(f.deadlineId);
      if (deadline) {
        const label = daysUntil(deadline.date, report.today) <= 0 ? "enforced:" : "deadline:";
        out.push(`${indent}${color(f.status, label)} ${deadlinePhrase(deadline.date, report.today)}. ${deadline.consequence}`);
      }
      for (const d of f.details ?? []) out.push(`${indent}${pc.dim("·")} ${d}`);
      const locations = loc(f);
      if (locations.length) out.push(`${indent}${pc.dim("at")} ${locations.join(", ")}`);
      if (f.fix) out.push(`${indent}${pc.green("fix:")} ${f.fix}`);
      if (f.docs) out.push(`${indent}${pc.dim(f.docs)}`);
    });
  }
  for (const status of ["pass", "skip"] as Status[]) {
    const group = sorted.filter((f) => f.status === status);
    if (!group.length) continue;
    out.push("");
    out.push(pc.bold(`${SECTION[status]} (${group.length})`));
    for (const f of group) out.push(`${color(status, ICON[status])} ${f.title} ${pc.dim(`· ${f.message}`)}`);
  }

  const next: string[] = [];
  if (counts(report.findings).fail) next.push("Fix the blocking items above, then run this again.");
  if (!report.target) next.push(`Test the running app:  ${pc.cyan("npx shopify-app-audit probe --url https://staging.your-app.com")}`);
  if (report.findings.some((f) => f.id === "IP_ALLOWLIST" && f.status === "info")) {
    next.push(`Prove the IP allowlist works:  ${pc.cyan("--shop <dev-store>.myshopify.com --admin-token-env SHOPIFY_ADMIN_TOKEN")}`);
  }
  if (!process.env.GITHUB_ACTIONS) next.push(`Run it on every PR:  ${pc.cyan("uses: enclave-ai/shopify-app-audit@v0")}`);
  out.push("");
  out.push(pc.bold("Next"));
  for (const n of next) out.push(`  → ${n}`);

  out.push("");
  const bar = pc.magenta("┃");
  out.push(`${bar} ${pc.bold("Want the bugs Shopify's rules don't cover?")}`);
  out.push(`${bar} Enclave's AI finds what attackers exploit in Shopify apps: cross-shop data leaks,`);
  out.push(`${bar} broken auth and injection, and opens the fix as a PR.`);
  out.push(`${bar} ${pc.bold("Free AI vulnerability scan of your repo:")} ${pc.cyan(`${ENCLAVE_SCAN_URL}&utm_medium=cli`)}`);
  out.push("");
  out.push(pc.dim("Static checks read your code and config, and the probe sends a few requests. Neither proves the app is secure."));
  return out.join("\n");
}

const md = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const mdLiteral = (s: string) => s.replace(/\r?\n/g, " ").replace(/[&<>|_*`~[\]\\]/g, (c) => `&#${c.charCodeAt(0)};`);

function headline(report: Report): string {
  const c = counts(report.findings);
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const rest = [c.fail ? plural(c.warn, "warning") : "", `${c.info} to do by hand`].filter(Boolean).join(" · ");
  if (c.fail) return `❌ ${plural(c.fail, "blocking issue")} · ${rest}`;
  if (c.warn) return `⚠️ ${plural(c.warn, "warning")} · nothing blocking · ${rest}`;
  return `✅ Nothing blocking · ${rest}`;
}

const MD_ICON: Record<Status, string> = { fail: "❌", warn: "⚠️", info: "📝", pass: "✅", skip: "➖" };

export function toMarkdown(report: Report): string {
  const out: string[] = [];
  out.push(`## ${headline(report)}`);
  out.push("");
  out.push(`<sub>shopify-app-audit ${report.version} · ${report.distribution} app · ${report.today}${report.target ? ` · probed ${md(report.target)}` : ""}</sub>`);
  const sorted = sortFindings(report.findings);
  for (const status of ["fail", "warn", "info"] as Status[]) {
    const group = sorted.filter((f) => f.status === status);
    if (!group.length) continue;
    out.push("");
    out.push(`### ${SECTION[status]} (${group.length})`);
    out.push("");
    for (const f of group) {
      out.push(`- ${MD_ICON[status]} **${md(f.title)}** — ${md(f.message)}`);
      const d = deadlineById(f.deadlineId);
      if (d) out.push(`  <br>**${daysUntil(d.date, report.today) <= 0 ? "Enforced" : "Deadline"}:** ${deadlinePhrase(d.date, report.today)}. ${md(d.consequence)}`);
      for (const x of (f.details ?? []).slice(0, 8)) out.push(`  <br>· ${md(x)}`);
      const where = loc(f).slice(0, 3).map((l) => `<code>${mdLiteral(l)}</code>`).join(", ");
      const tail = [where, f.fix ? `**Fix:** ${md(f.fix)}` : "", f.docs ? `[docs](${f.docs})` : ""].filter(Boolean).join(" · ");
      if (tail) out.push(`  <br>${tail}`);
    }
  }
  const quiet = sorted.filter((f) => f.status === "pass" || f.status === "skip");
  if (quiet.length) {
    out.push("");
    out.push(`<details><summary>Passed and skipped (${quiet.length})</summary>`);
    out.push("");
    for (const f of quiet) out.push(`- ${MD_ICON[f.status]} **${md(f.title)}** — ${md(f.message)}`);
    out.push("");
    out.push("</details>");
  }
  out.push("");
  out.push("<details><summary>Shopify security deadlines</summary>");
  out.push("");
  out.push("| Date | Feature | What happens |");
  out.push("| --- | --- | --- |");
  for (const d of report.deadlines) {
    const when = daysUntil(d.date, report.today) <= 0 ? `${d.date} (in effect)` : `${d.date} (${relativeDay(d.date, report.today)})`;
    out.push(`| ${when} | ${md(d.feature)} | ${md(d.consequence)} [source](${d.source}) |`);
  }
  out.push("");
  out.push("</details>");
  out.push("");
  out.push(`> [!TIP]`);
  out.push(`> **Want the bugs Shopify's rules don't cover?** Enclave's AI finds cross-shop data leaks, broken auth and injection in Shopify apps, and opens the fix as a PR. [Get a free AI vulnerability scan of your repo →](${ENCLAVE_SCAN_URL}&utm_medium=github-summary)`);
  out.push("");
  out.push("<sub>Static checks and a light probe don't prove an app is secure.</sub>");
  return out.join("\n");
}

export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

const repoPath = (report: Report, file: string): string => {
  const full = !report.appDir || report.appDir === "." ? file : `${report.appDir.replace(/\\/g, "/").replace(/\/$/, "")}/${file}`;
  return full.split("/").map(encodeURIComponent).join("/");
};

export function toSarif(report: Report): string {
  const level = (s: Status) => (s === "fail" ? "error" : s === "warn" ? "warning" : "note");
  const findings = report.findings.filter((f) => f.status === "fail" || f.status === "warn");
  const ruleIds = [...new Set(findings.map((f) => f.id))];
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "shopify-app-audit",
              version: report.version,
              informationUri: "https://github.com/enclave-ai/shopify-app-audit",
              rules: ruleIds.map((id) => {
                const f = findings.find((x) => x.id === id)!;
                return { id, shortDescription: { text: f.title }, helpUri: f.docs };
              }),
            },
          },
          results: findings.map((f) => {
            const d = deadlineById(f.deadlineId);
            return {
              ruleId: f.id,
              level: level(f.status),
              message: {
                text: [f.message, ...(f.details ?? []), d ? `Deadline ${d.date}: ${d.consequence}` : "", f.fix ? `Fix: ${f.fix}` : ""]
                  .filter(Boolean)
                  .join(" "),
              },
              locations: (f.locations?.length ? f.locations : [{ file: "shopify.app.toml" }]).map((l) => ({
                physicalLocation: {
                  artifactLocation: { uri: repoPath(report, l.file) },
                  ...(l.line ? { region: { startLine: l.line } } : {}),
                },
              })),
            };
          }),
        },
      ],
    },
    null,
    2,
  );
}

export function toBadge(report: Report): string {
  const c = counts(report.findings);
  const message = c.fail ? `${c.fail} blocking` : c.warn ? `${c.warn} warning${c.warn === 1 ? "" : "s"}` : "ready";
  const color = c.fail ? "red" : c.warn ? "yellow" : "brightgreen";
  return JSON.stringify({ schemaVersion: 1, label: "shopify deadlines", message, color });
}
