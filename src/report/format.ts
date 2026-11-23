import pc from "picocolors";
import { daysUntil, deadlineById, relativeDay } from "../deadlines.js";
import type { Finding, Report, Status } from "../types.js";

const ORDER: Status[] = ["fail", "warn", "info", "pass", "skip"];
const LABEL: Record<Status, string> = { fail: "FAIL", warn: "WARN", info: "TODO", pass: "PASS", skip: "SKIP" };

export const sortFindings = (findings: Finding[]): Finding[] =>
  [...findings].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));

export const counts = (findings: Finding[]) =>
  Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => f.status === s).length])) as Record<Status, number>;

const color = (status: Status, text: string) =>
  ({ fail: pc.red, warn: pc.yellow, info: pc.cyan, pass: pc.green, skip: pc.dim })[status](text);

const loc = (f: Finding) =>
  (f.locations ?? []).map((l) => (l.line ? `${l.file}:${l.line}` : l.file));

export function toText(report: Report): string {
  const out: string[] = [];
  out.push(pc.bold("shopify-app-audit") + pc.dim(` v${report.version}  ${report.distribution} app  ${report.today}`));
  if (report.appDir) out.push(pc.dim(`app: ${report.appDir}`));
  if (report.target) out.push(pc.dim(`probe target: ${report.target}`));
  out.push("");
  out.push(pc.bold("Shopify security deadlines"));
  for (const d of report.deadlines) {
    const days = daysUntil(d.date, report.today);
    const when = relativeDay(d.date, report.today);
    const mark = days < 0 ? pc.dim("past ") : days <= 14 ? pc.red("soon ") : pc.dim("     ");
    out.push(`  ${mark}${d.date}  ${pc.dim(when.padEnd(13))} ${d.feature}`);
  }
  out.push("");
  for (const f of sortFindings(report.findings)) {
    out.push(`${color(f.status, LABEL[f.status].padEnd(4))}  ${pc.bold(f.title)} ${pc.dim(`[${f.id}]`)}`);
    out.push(`      ${f.message}`);
    const deadline = deadlineById(f.deadlineId);
    if (deadline && f.status !== "pass") {
      out.push(`      ${pc.dim("deadline:")} ${deadline.date} (${relativeDay(deadline.date, report.today)}). ${deadline.consequence}`);
    }
    for (const d of f.details ?? []) out.push(`      ${pc.dim("-")} ${d}`);
    const locations = loc(f);
    if (locations.length) out.push(`      ${pc.dim("at")} ${locations.join(", ")}`);
    if (f.fix && f.status !== "pass") out.push(`      ${pc.dim("fix:")} ${f.fix}`);
    if (f.docs && f.status !== "pass") out.push(`      ${pc.dim(f.docs)}`);
    out.push("");
  }
  const c = counts(report.findings);
  out.push(
    `${pc.red(`${c.fail} fail`)}  ${pc.yellow(`${c.warn} warn`)}  ${pc.cyan(`${c.info} todo`)}  ${pc.green(`${c.pass} pass`)}`,
  );
  out.push(
    pc.dim(
      "Static checks read your code and config. The probe sends a few requests to the URL you give it. Neither proves the app is secure.",
    ),
  );
  out.push(pc.dim("Made by Enclave. AI pentesting for your whole app: https://enclave.ai"));
  return out.join("\n");
}

const md = (s: string) => s.replace(/\|/g, "\\|");

export function toMarkdown(report: Report): string {
  const c = counts(report.findings);
  const out: string[] = [];
  out.push(`## shopify-app-audit`);
  out.push("");
  out.push(`**${c.fail} fail, ${c.warn} warn, ${c.info} to do, ${c.pass} pass** (${report.distribution} app, ${report.today})`);
  out.push("");
  const open = sortFindings(report.findings).filter((f) => f.status !== "skip");
  if (open.length) {
    out.push("| Status | Check | Deadline | Where |");
    out.push("| --- | --- | --- | --- |");
    for (const f of open) {
      const d = deadlineById(f.deadlineId);
      const deadline = d && f.status !== "pass" ? `${d.date} (${relativeDay(d.date, report.today)})` : "";
      const details = (f.details ?? []).slice(0, 8).map((x) => `<br>- ${md(x)}`).join("");
      out.push(`| ${LABEL[f.status]} | **${md(f.title)}**<br>${md(f.message)}${details} | ${deadline} | ${md(loc(f).slice(0, 3).join(", "))} |`);
    }
    out.push("");
  }
  out.push("<details><summary>Shopify security deadlines</summary>");
  out.push("");
  out.push("| Date | Feature | What happens |");
  out.push("| --- | --- | --- |");
  for (const d of report.deadlines) out.push(`| ${d.date} | ${md(d.feature)} | ${md(d.consequence)} [source](${d.source}) |`);
  out.push("");
  out.push("</details>");
  out.push("");
  out.push("_Made by [Enclave](https://enclave.ai). Static checks and a light probe don't prove an app is secure._");
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
