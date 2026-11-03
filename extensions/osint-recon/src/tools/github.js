import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { assertGithubInScope } from "../scope.js";
import { UserError, parseGithubOwner, parseGithubRepo } from "../validate.js";
import { finding } from "./recon.js";

const execFileAsync = promisify(execFile);
const API = "https://api.github.com";
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
const LOCAL_READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

export function createGithubTools({ getScope, env = process.env, fetchImpl = fetch }) {
  async function api(pathname) {
    const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "rea-osint-recon/0.1" };
    if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
    const res = await fetchImpl(`${API}${pathname}`, { headers, signal: AbortSignal.timeout(20000) });
    if (res.status === 404) throw new UserError(`GitHub returned 404 for ${pathname} (not found, or not public)`);
    if (res.status === 403 || res.status === 429) {
      throw new UserError(`GitHub rate limit or access denied (HTTP ${res.status}). Set GITHUB_TOKEN to raise the limit.`);
    }
    if (!res.ok) throw new UserError(`GitHub API error: HTTP ${res.status}`);
    return res.json();
  }

  const orgOverview = {
    name: "github_org_overview",
    description:
      "Public footprint of an in-scope GitHub organization: repositories, languages, activity, archived and stale repos. " +
      "Lists repositories only, never individual members or their personal data.",
    annotations: READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["org"],
      properties: { org: { type: "string", maxLength: 39 }, max_repos: { type: "integer", minimum: 1, maximum: 300 } },
    },
    async handler({ org, max_repos = 100 }) {
      const owner = parseGithubOwner(org);
      assertGithubInScope(getScope(), owner);
      const info = await api(`/orgs/${owner}`);
      const repos = [];
      for (let page = 1; repos.length < max_repos; page++) {
        const batch = await api(`/orgs/${owner}/repos?type=public&per_page=100&page=${page}`);
        repos.push(...batch);
        if (batch.length < 100) break;
      }
      const data = summarizeOrg(info, repos.slice(0, max_repos));
      const findings = [];
      if (data.stale_repos.length) findings.push(finding("info", "Stale public repositories", `${data.stale_repos.length} public repos with no push in over a year: ${data.stale_repos.slice(0, 10).join(", ")}`, owner));
      return { summary: `${owner}: ${data.public_repos_examined} public repos examined, top language ${data.top_languages[0]?.[0] ?? "n/a"}`, data, findings };
    },
  };

  const repoOverview = {
    name: "github_repo_overview",
    description:
      "Public metadata of an in-scope GitHub repository: languages, size, activity, license, security policy, " +
      "dependency manifests and CI workflow files (technology-stack exposure).",
    annotations: READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["owner", "repo"],
      properties: { owner: { type: "string", maxLength: 39 }, repo: { type: "string", maxLength: 100 } },
    },
    async handler({ owner, repo }) {
      const o = parseGithubOwner(owner);
      const r = parseGithubRepo(repo);
      assertGithubInScope(getScope(), o, r);
      const info = await api(`/repos/${o}/${r}`);
      const [languages, profile, tree] = await Promise.all([
        api(`/repos/${o}/${r}/languages`),
        api(`/repos/${o}/${r}/community/profile`).catch(() => undefined),
        api(`/repos/${o}/${r}/git/trees/${encodeURIComponent(info.default_branch)}?recursive=1`).catch(() => undefined),
      ]);
      const paths = (tree?.tree ?? []).filter((t) => t.type === "blob").map((t) => t.path);
      const data = {
        full_name: info.full_name, description: info.description, default_branch: info.default_branch,
        visibility: info.visibility, archived: info.archived, fork: info.fork, license: info.license?.spdx_id,
        created_at: info.created_at, pushed_at: info.pushed_at, size_kb: info.size, stars: info.stargazers_count,
        forks: info.forks_count, open_issues: info.open_issues_count, topics: info.topics ?? [], languages,
        has_security_policy: profile ? Boolean(profile.files?.security_policy) : undefined,
        community_health_percentage: profile?.health_percentage,
        dependency_manifests: paths.filter((p) => MANIFEST_RE.test(path.posix.basename(p))).slice(0, 100),
        workflow_files: paths.filter((p) => /^\.github\/workflows\/.+\.ya?ml$/.test(p)),
        tree_truncated: tree?.truncated ?? undefined,
        limitations: ["Only public data is read. Branch protection and secret-scanning settings need admin access and are not checked."],
      };
      const findings = [];
      if (profile && !profile.files?.security_policy) findings.push(finding("low", "No security policy", `${info.full_name} has no SECURITY.md / reporting channel.`, info.full_name));
      return { summary: `${info.full_name}: ${Object.keys(languages).slice(0, 3).join(", ") || "no languages"}, ${data.dependency_manifests.length} manifest(s), ${data.workflow_files.length} workflow(s)`, data, findings };
    },
  };

  const exposureScan = {
    name: "github_exposure_scan",
    description:
      "Defensive secret-exposure scan of a LOCAL checkout of a repository you own or are authorized to review " +
      "(clone it first). Detects common credential formats in the working tree and, optionally, recent git history. " +
      "Matched values are masked and fingerprinted, never returned in full.",
    annotations: LOCAL_READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", maxLength: 1024, description: "Path to a local git checkout" },
        history_commits: { type: "integer", minimum: 0, maximum: 500, description: "Also scan added lines of the last N commits (default 0)" },
      },
    },
    async handler({ path: dir, history_commits = 0 }) {
      const root = resolveDir(dir);
      const findings = [];
      let filesScanned = 0, skipped = 0;
      for (const file of walk(root)) {
        const text = readTextFile(file);
        if (text === undefined) { skipped++; continue; }
        filesScanned++;
        findings.push(...scanText(text, path.relative(root, file)));
      }
      let commitsScanned = 0;
      if (history_commits > 0) {
        const { stdout } = await execFileAsync("git", ["-C", root, "log", `-n${history_commits}`, "--all", "-p", "--no-color", "--no-ext-diff", "--format=@@commit %H"], { maxBuffer: 64 * 1024 * 1024 })
          .catch(() => { throw new UserError("git history could not be read (is this a git checkout with git installed?)"); });
        const hist = scanDiff(stdout);
        commitsScanned = hist.commits;
        findings.push(...hist.findings);
      }
      const deduped = dedupeFindings(findings);
      const high = deduped.filter((f) => f.confidence === "high");
      return {
        summary: `Scanned ${filesScanned} files${commitsScanned ? ` and ${commitsScanned} commits` : ""}: ${deduped.length} potential secret(s), ${high.length} high confidence`,
        data: {
          root: path.basename(root), files_scanned: filesScanned, files_skipped: skipped, commits_scanned: commitsScanned, matches: deduped.slice(0, 200),
          limitations: ["Pattern based: expect false positives (confidence is noted) and misses for unknown formats.", "A secret found in history stays compromised after deletion; rotate it."],
        },
        findings: high.slice(0, 50).map((m) => finding("high", `Possible ${m.type}`, `${m.file}:${m.line}${m.commit ? ` (commit ${m.commit.slice(0, 8)})` : ""} fingerprint ${m.fingerprint}`, path.basename(root))),
      };
    },
  };

  const workflowAudit = {
    name: "github_workflow_audit",
    description:
      "Heuristic security audit of GitHub Actions workflows in a LOCAL checkout: pull_request_target misuse, script injection " +
      "from untrusted event fields, actions not pinned to a commit SHA, and over-broad permissions.",
    annotations: LOCAL_READ_ONLY,
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", maxLength: 1024 } } },
    async handler({ path: dir }) {
      const root = resolveDir(dir);
      const wfDir = path.join(root, ".github", "workflows");
      if (!fs.existsSync(wfDir)) return { summary: "No .github/workflows directory found.", data: { workflows: 0, issues: [] } };
      const files = fs.readdirSync(wfDir).filter((f) => /\.ya?ml$/.test(f)).sort();
      const issues = files.flatMap((f) => auditWorkflow(fs.readFileSync(path.join(wfDir, f), "utf8"), `.github/workflows/${f}`));
      return {
        summary: `${files.length} workflow(s) audited: ${issues.length} issue(s)`,
        data: { workflows: files.length, issues, limitations: ["Line-based heuristics, not a full YAML/expression analysis; review each hit manually."] },
        findings: issues.filter((i) => i.severity !== "info").map((i) => finding(i.severity, i.title, `${i.file}:${i.line} ${i.detail}`, path.basename(root))),
      };
    },
  };

  return [orgOverview, repoOverview, exposureScan, workflowAudit];
}

/* ======================= helpers (exported for tests) ======================= */

const MANIFEST_RE = /^(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements.*\.txt|Pipfile(\.lock)?|pyproject\.toml|poetry\.lock|go\.(mod|sum)|Cargo\.(toml|lock)|Gemfile(\.lock)?|pom\.xml|build\.gradle(\.kts)?|composer\.(json|lock)|Dockerfile|docker-compose\.ya?ml|.*\.csproj)$/;

export function summarizeOrg(info, repos) {
  const langs = new Map();
  const yearAgo = Date.now() - 365 * 86_400_000;
  const stale = [];
  for (const r of repos) {
    if (r.language) langs.set(r.language, (langs.get(r.language) ?? 0) + 1);
    if (!r.archived && r.pushed_at && Date.parse(r.pushed_at) < yearAgo) stale.push(r.name);
  }
  return {
    login: info.login, name: info.name, description: info.description, created_at: info.created_at,
    public_repos_reported: info.public_repos, public_repos_examined: repos.length,
    archived_repos: repos.filter((r) => r.archived).length, forks: repos.filter((r) => r.fork).length,
    top_languages: [...langs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
    stale_repos: stale,
    repositories: repos.map((r) => ({ name: r.name, language: r.language, stars: r.stargazers_count, pushed_at: r.pushed_at, archived: r.archived, fork: r.fork, license: r.license?.spdx_id, topics: r.topics })),
    limitations: ["Public repositories only; private and internal repositories are not visible."],
  };
}

function resolveDir(dir) {
  const resolved = path.resolve(dir);
  let stat;
  try { stat = fs.statSync(resolved); } catch { throw new UserError(`"${dir}" does not exist`); }
  if (!stat.isDirectory()) throw new UserError(`"${dir}" is not a directory`);
  return fs.realpathSync(resolved);
}

const SKIP_DIRS = new Set([".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"]);
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 20_000;

function* walk(root) {
  let count = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue; // never follow links out of the checkout
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(full); }
      else if (e.isFile()) { if (++count > MAX_FILES) return; yield full; }
    }
  }
}

function readTextFile(file) {
  try {
    const stat = fs.statSync(file);
    if (stat.size === 0 || stat.size > MAX_FILE_BYTES) return undefined;
    const buf = fs.readFileSync(file);
    if (buf.subarray(0, 8000).includes(0)) return undefined; // binary
    return buf.toString("utf8");
  } catch { return undefined; }
}

const PATTERNS = [
  { type: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, confidence: "high" },
  { type: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, confidence: "high" },
  { type: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, confidence: "high" },
  { type: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, confidence: "high" },
  { type: "Private key block", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, confidence: "high" },
  { type: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: "high" },
  { type: "Stripe live key", re: /\b[sr]k_live_[0-9a-zA-Z]{24,}\b/g, confidence: "high" },
  { type: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, confidence: "medium" },
  { type: "Hard-coded credential assignment", re: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi, confidence: "low", group: 1 },
];
const PLACEHOLDER_RE = /(example|changeme|change_me|placeholder|your[_-]|<.*>|\$\{|\{\{|x{6,}|\*{4,}|dummy|sample|test|redacted)/i;

export function fingerprint(value) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 12);
}

export function mask(value) {
  return value.length <= 8 ? "****" : `${value.slice(0, 4)}…(${value.length} chars)`;
}

export function scanText(text, file, extra = {}) {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 2000) continue;
    for (const p of PATTERNS) {
      p.re.lastIndex = 0;
      for (let m; (m = p.re.exec(line)); ) {
        const value = p.group ? m[p.group] : m[0];
        if (PLACEHOLDER_RE.test(value)) continue;
        out.push({ type: p.type, confidence: p.confidence, file, line: i + 1, masked: mask(value), fingerprint: fingerprint(value), ...extra });
      }
    }
  }
  return out;
}

/** Scan the added lines of `git log -p` output formatted with "@@commit <sha>" headers. */
export function scanDiff(output) {
  const findings = [];
  let commit, file, commits = 0, newLine = 0;
  for (const line of output.split("\n")) {
    if (line.startsWith("@@commit ")) { commit = line.slice(9).trim(); commits++; file = undefined; continue; }
    if (line.startsWith("+++ ")) { file = line.slice(4).replace(/^b\//, ""); continue; }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(line);
    if (hunk) { newLine = Number(hunk[1]) - 1; continue; }
    if (line.startsWith("+") && file && file !== "/dev/null") {
      newLine++;
      findings.push(...scanText(line.slice(1), file, { commit }).map((f) => ({ ...f, line: newLine })));
    } else if (line.startsWith(" ")) newLine++;
  }
  return { findings, commits };
}

function dedupeFindings(list) {
  const seen = new Set();
  return list.filter((f) => {
    const key = `${f.fingerprint}|${f.file}|${f.line}|${f.commit ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const UNTRUSTED_EXPR = /\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label)|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|head_commit\.(?:message|author\.(?:name|email))|commits\[[^\]]*\]\.message|pages\[[^\]]*\]\.page_name|discussion\.(?:title|body))|github\.head_ref)\s*\}\}/;

export function auditWorkflow(text, file) {
  const issues = [];
  const lines = text.split("\n");
  const add = (severity, title, line, detail) => issues.push({ severity, title, file, line, detail });
  let runIndent = -1;
  let hasPermissions = false;
  let prTarget = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    if (/^permissions\s*:/.test(raw)) hasPermissions = true;
    if (/\bpull_request_target\b/.test(trimmed) && !trimmed.startsWith("uses")) prTarget = true;
    if (/^permissions\s*:\s*write-all/.test(trimmed) || /^\s+permissions\s*:\s*write-all/.test(raw)) add("medium", "permissions: write-all", i + 1, "Grants every scope to the workflow token.");
    if (/secrets\s*:\s*inherit/.test(trimmed)) add("low", "secrets: inherit", i + 1, "Passes all repository secrets to the called workflow.");
    const uses = /^-?\s*uses\s*:\s*([^\s#]+)/.exec(trimmed);
    if (uses) {
      const ref = uses[1];
      if (!ref.startsWith("./") && !ref.startsWith("docker://") && !/@[0-9a-f]{40}$/.test(ref)) {
        add(/^actions\//.test(ref) ? "info" : "low", "Action not pinned to a commit SHA", i + 1, `${ref} can change under you; pin to a full SHA.`);
      }
    }
    if (/^-?\s*ref\s*:.*github\.event\.pull_request\.head\.(?:sha|ref)|^-?\s*ref\s*:.*github\.head_ref/.test(trimmed) && prTarget) {
      add("high", "pull_request_target checks out untrusted PR code", i + 1, "Checking out the PR head in a privileged workflow can expose secrets.");
    }
    // Track `run:` scripts (single-line and block scalars) for expression injection.
    const run = /^-?\s*run\s*:\s*(.*)$/.exec(trimmed);
    if (run) {
      runIndent = indent;
      if (run[1] && !/^[|>][+-]?\s*$/.test(run[1]) && UNTRUSTED_EXPR.test(run[1])) add("high", "Script injection via untrusted event data", i + 1, "Untrusted input is interpolated straight into a shell command; pass it through env: instead.");
      if (run[1] && !/^[|>]/.test(run[1])) runIndent = -1;
      continue;
    }
    if (runIndent >= 0) {
      if (indent <= runIndent) runIndent = -1;
      else if (UNTRUSTED_EXPR.test(raw)) add("high", "Script injection via untrusted event data", i + 1, "Untrusted input is interpolated straight into a shell command; pass it through env: instead.");
    }
  }
  if (!hasPermissions) add("info", "No top-level permissions block", 1, "Default token permissions apply; declare least-privilege permissions explicitly.");
  return issues;
}
