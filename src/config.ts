import { readFile, realpath, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parse } from "smol-toml";
import { glob } from "tinyglobby";

export interface WebhookSubscription {
  topics: string[];
  complianceTopics: string[];
  uri: string;
}

export interface Extension {
  dir: string;
  configFile: string;
  types: string[];
}

export interface AppConfig {
  file: string;
  raw: string;
  name?: string;
  clientId?: string;
  applicationUrl?: string;
  embedded: boolean;
  scopes: string[];
  redirectUrls: string[];
  webhooksApiVersion?: string;
  webhooks: WebhookSubscription[];
  appProxy?: { url: string; prefix?: string; subpath?: string };
  networkAccess?: {
    allowedSources?: unknown;
    allowedNavigationHosts?: unknown;
  };
}

export interface AppProject {
  dir: string;
  config?: AppConfig;
  extensions: Extension[];
  files: string[];
}

type Table = Record<string, unknown>;

const asTable = (v: unknown): Table =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Table) : {};
const asString = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const asStrings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

export function parseAppConfig(file: string, raw: string): AppConfig {
  const doc = asTable(parse(raw));
  const scopesRaw = asTable(doc.access_scopes).scopes;
  const scopes = (typeof scopesRaw === "string" ? scopesRaw.split(",") : asStrings(scopesRaw))
    .map((s) => s.trim())
    .filter(Boolean);
  const webhooksTable = asTable(doc.webhooks);
  const subs = Array.isArray(webhooksTable.subscriptions) ? webhooksTable.subscriptions : [];
  const proxy = asTable(doc.app_proxy);
  const network = doc.network_access === undefined ? undefined : asTable(doc.network_access);
  return {
    file,
    raw,
    name: asString(doc.name),
    clientId: asString(doc.client_id),
    applicationUrl: asString(doc.application_url),
    embedded: doc.embedded !== false,
    scopes,
    redirectUrls: asStrings(asTable(doc.auth).redirect_urls),
    webhooksApiVersion: asString(webhooksTable.api_version),
    webhooks: subs.map((s) => {
      const t = asTable(s);
      return {
        topics: asStrings(t.topics),
        complianceTopics: asStrings(t.compliance_topics),
        uri: asString(t.uri) ?? "",
      };
    }),
    appProxy: asString(proxy.url)
      ? { url: asString(proxy.url)!, prefix: asString(proxy.prefix), subpath: asString(proxy.subpath) }
      : undefined,
    networkAccess: network
      ? {
          allowedSources: network.allowed_sources,
          allowedNavigationHosts: network.allowed_navigation_hosts,
        }
      : undefined,
  };
}

const IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.shopify/**",
  "**/.cache/**",
  "**/coverage/**",
  "**/vendor/**",
  "**/public/build/**",
  "**/*.min.js",
];

export const CODE_GLOB = "**/*.{js,jsx,ts,tsx,mjs,cjs,rb,py,php,go,liquid,css,scss,graphql,gql,erb,prisma}";

export const MAX_FILE_BYTES = 2 * 1024 * 1024;

async function readInside(root: string, file: string): Promise<string> {
  const real = await realpath(path.resolve(root, file));
  const realRoot = await realpath(root);
  if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
    throw new Error(`${file} points outside the app directory`);
  }
  if ((await stat(real)).size > MAX_FILE_BYTES) throw new Error(`${file} is larger than ${MAX_FILE_BYTES} bytes`);
  return readFile(real, "utf8");
}

function tomlError(file: string, err: unknown): Error {
  const first = (err instanceof Error ? err.message : String(err)).split("\n")[0];
  return new Error(`Can't parse ${file}: ${first}`);
}

export async function loadProject(dir: string, configName?: string): Promise<AppProject> {
  const abs = path.resolve(dir);
  const candidates = configName
    ? [configName]
    : (await glob(["shopify.app.toml", "shopify.app.*.toml"], { cwd: abs, followSymbolicLinks: false })).sort((a, b) =>
        a === "shopify.app.toml" ? -1 : b === "shopify.app.toml" ? 1 : a.localeCompare(b),
      );
  let config: AppConfig | undefined;
  const first = candidates.find((c) => existsSync(path.resolve(abs, c)));
  if (first) {
    const rel = path.relative(abs, path.resolve(abs, first));
    const raw = configName && path.isAbsolute(configName)
      ? await readFile(configName, "utf8")
      : await readInside(abs, first);
    try {
      config = parseAppConfig(rel, raw);
    } catch (err) {
      throw tomlError(rel, err);
    }
  }
  const extConfigs = await glob(["extensions/*/shopify.extension.toml"], { cwd: abs, followSymbolicLinks: false });
  const extensions: Extension[] = [];
  for (const file of extConfigs.sort()) {
    const raw = await readInside(abs, file).catch(() => "");
    let types: string[] = [];
    try {
      const doc = asTable(parse(raw));
      const top = asString(doc.type);
      const nested = (Array.isArray(doc.extensions) ? doc.extensions : [])
        .map((e) => asString(asTable(e).type))
        .filter((t): t is string => Boolean(t));
      types = [...(top ? [top] : []), ...nested];
    } catch {
      types = [];
    }
    extensions.push({ dir: path.dirname(file), configFile: file, types });
  }
  const files = (await glob([CODE_GLOB], { cwd: abs, ignore: IGNORE, dot: false, followSymbolicLinks: false })).sort();
  return { dir: abs, config, extensions, files };
}

export async function readProjectFile(project: AppProject, file: string): Promise<string> {
  return readInside(project.dir, file);
}
