import type { AppProject } from "../config.js";
import { readProjectFile } from "../config.js";
import type { Location } from "../types.js";

export interface Match extends Location {
  text: string;
  groups: string[];
}

export class SourceIndex {
  private cache = new Map<string, string>();
  constructor(readonly project: AppProject) {}

  async read(file: string): Promise<string> {
    let text = this.cache.get(file);
    if (text === undefined) {
      text = await readProjectFile(this.project, file).catch(() => "");
      this.cache.set(file, text);
    }
    return text;
  }

  async search(pattern: RegExp, filter: (file: string) => boolean = () => true): Promise<Match[]> {
    const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
    const re = new RegExp(pattern.source, flags);
    const matches: Match[] = [];
    for (const file of this.project.files.filter(filter)) {
      const text = await this.read(file);
      if (!text) continue;
      const starts = lineStarts(text);
      for (const m of text.matchAll(re)) {
        const line = lineOf(starts, m.index ?? 0);
        matches.push({ file, line, text: m[0], groups: m.slice(1) });
      }
    }
    return matches;
  }
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

function lineOf(starts: number[], index: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export const isTestFile = (file: string): boolean =>
  /(^|\/)(__tests__|tests?|spec|fixtures?|mocks?)\//.test(file) || /\.(test|spec)\.[a-z]+$/.test(file);

export const notTest = (file: string): boolean => !isTestFile(file);

export const uniqueByFile = (matches: Match[], max = 10): Location[] => {
  const seen = new Set<string>();
  const out: Location[] = [];
  for (const m of matches) {
    const key = `${m.file}:${m.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ file: m.file, line: m.line });
    if (out.length >= max) break;
  }
  return out;
};
