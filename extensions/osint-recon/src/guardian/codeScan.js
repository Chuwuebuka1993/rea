// Scan My Code: read-only, offline scan of YOUR OWN project folder. Zero dependencies.
// A reviewed line may carry: // guardian-scan: allow <rule-id> (reason of 8+ characters). Secrets cannot be allowed this way.
// It never prints a secret's value (only file, line and rule), never follows symlinks, never touches the network.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next", "target"]);
const TEXT_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|json|py|sh|env|yml|yaml|toml|ini|cfg|conf|md|txt|html|rs|go|java|kt|rb|php)$|(^|\/)\.env[^/]*$|(^|\/)Dockerfile$/i;
const MAX_FILE = 512 * 1024, MAX_FILES = 5000;

export const SECRET_RULES = [
  { id: "private-key", severity: "high", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, why: "A private key is stored in a file." },
  { id: "aws-access-key", severity: "high", re: /\bAKIA[0-9A-Z]{16}\b/, why: "Looks like an AWS access key id." },
  { id: "github-token", severity: "high", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, why: "Looks like a GitHub token." },
  { id: "slack-token", severity: "high", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, why: "Looks like a Slack token." },
  { id: "anthropic-or-openai-key", severity: "high", re: /\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b/, why: "Looks like an AI provider API key." },
  { id: "google-api-key", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/, why: "Looks like a Google API key." },
  { id: "generic-secret-assignment", severity: "medium", re: /\b(?:password|passwd|secret|api[_-]?key|token)\b["']?\s*[:=]\s*["'][^"'\s]{12,}["']/i, why: "A secret-like value is written directly in code." },
];

export const CODE_RULES = [
  { id: "eval", severity: "medium", re: /\beval\s*\(/, ext: /\.(js|mjs|cjs|ts|py)$/, why: "eval runs text as code; attackers love it." },
  { id: "shell-exec-string", severity: "medium", re: /\b(?:exec|execSync)\s*\(\s*[`"'][^`"']*\$\{|\bos\.system\s*\(|shell\s*=\s*True/, ext: /\.(js|mjs|cjs|ts|py)$/, why: "Building a shell command from text can allow command injection. Use an argument list." },
  { id: "tls-verify-off", severity: "high", re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False|curl\s[^\n]*\s-k\b/, why: "Certificate checking is switched off." },
  { id: "weak-hash", severity: "low", re: /createHash\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\(/, why: "MD5/SHA-1 must not be used for passwords or signatures." },
  { id: "public-bind", severity: "medium", re: /listen\([^)]*["']0\.0\.0\.0["']|host\s*[:=]\s*["']0\.0\.0\.0["']/, why: "The service listens on every network interface; prefer 127.0.0.1." },
  { id: "curl-pipe-shell", severity: "medium", re: /curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/, why: "Piping a download into a shell runs unreviewed code." },
];

function* walk(root, state) {
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (state.count >= MAX_FILES) { state.truncated = true; return; }
    if (e.isSymbolicLink()) continue;
    const p = path.join(root, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(p, state); }
    else if (e.isFile()) { state.count++; yield p; }
  }
}

function gitIgnores(root, name) {
  try { return fs.readFileSync(path.join(root, ".gitignore"), "utf8").split(/\r?\n/).some((l) => l.trim().replace(/^\//, "") === name || l.trim() === `${name}*`); } catch { return false; }
}

export function scanCode(dir) {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`not a folder: ${dir}`);
  const state = { count: 0, truncated: false };
  const findings = [];
  let scanned = 0;
  for (const file of walk(root, state)) {
    const rel = path.relative(root, file).split(path.sep).join("/");
    const base = path.basename(file);
    if (/^\.env(\..+)?$/.test(base) && !/example|sample|template/i.test(base)) {
      findings.push({ severity: gitIgnores(root, base) ? "low" : "high", rule: "env-file", file: rel, line: 0, why: gitIgnores(root, base) ? "An .env file exists but is ignored by git (good). Keep it off backups you share." : "An .env file is not in .gitignore; it may get committed." });
    }
    if (!TEXT_EXT.test(rel)) continue;
    let text;
    try { if (fs.statSync(file).size > MAX_FILE) continue; text = fs.readFileSync(file, "utf8"); } catch { continue; }
    if (text.includes("\u0000")) continue;
    scanned++;
    const lines = text.split(/\r?\n/);
    const isTest = /(^|\/)(tests?|__tests__|examples?)\//.test(rel) || /\.test\.[a-z]+$/.test(rel);
    const allowed = (i, id) => [lines[i], lines[i - 1]].some((l) => l && l.includes("guardian-scan: allow") && (l.includes(id) || l.includes("all")) && /allow[^\n]*\([^)]{8,}\)/.test(l));
    lines.forEach((ln, i) => {
      if (ln.length > 2000) return;
      for (const r of SECRET_RULES) {
        if (r.re.test(ln)) {
          if (/example|placeholder|your[_-]?(key|token)|xxxx|<[^>]+>|\$\{?[A-Z_]+\}?|process\.env|os\.environ/i.test(ln)) continue;
          findings.push({ severity: isTest ? "low" : r.severity, rule: r.id, file: rel, line: i + 1, why: r.why + (isTest ? " (in a test/example folder: confirm it is fake)" : "") });
        }
      }
      for (const r of CODE_RULES) if ((!r.ext || r.ext.test(rel)) && r.re.test(ln) && !isTest && !allowed(i, r.id)) findings.push({ severity: r.severity, rule: r.id, file: rel, line: i + 1, why: r.why });
    });
    if (base === "package.json") {
      try {
        const pj = JSON.parse(text);
        for (const k of ["preinstall", "postinstall", "install"]) if (pj.scripts?.[k]) findings.push({ severity: "medium", rule: "install-script", file: rel, line: 0, why: `package.json runs a "${k}" script on install; read it before trusting.` });
        const deps = { ...pj.dependencies, ...pj.devDependencies };
        if (Object.keys(deps).length && !fs.existsSync(path.join(path.dirname(file), "package-lock.json"))) findings.push({ severity: "low", rule: "no-lockfile", file: rel, line: 0, why: "Dependencies are not pinned by a lock file." });
        for (const [n, v] of Object.entries(deps)) if (/^(\*|latest|)$/.test(String(v))) findings.push({ severity: "medium", rule: "unpinned-dependency", file: rel, line: 0, why: `${n} uses version "${v || "(empty)"}".` });
      } catch { /* not valid JSON: ignore */ }
    }
  }
  const order = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
  const counts = { high: 0, medium: 0, low: 0 };
  findings.forEach((f) => counts[f.severity]++);
  return { root, filesSeen: state.count, filesScanned: scanned, truncated: state.truncated, counts, findings, note: "Pattern scan only: it finds common mistakes, not every flaw. A clean result is not proof of safety." };
}

// Well-known open-source scanners, run only if you installed them. Nothing is downloaded.
export const EXTERNAL = [
  { name: "gitleaks", license: "MIT", job: "secrets in code and git history", version: ["version"], run: (d) => ["detect", "--source", d, "--no-banner", "--redact"] },
  { name: "semgrep", license: "LGPL-2.1 (engine), rules vary", job: "insecure code patterns", version: ["--version"], run: (d) => ["--config", "auto", "--metrics", "off", d] },
  { name: "osv-scanner", license: "Apache-2.0", job: "known-vulnerable dependencies", version: ["--version"], run: (d) => ["scan", "source", "-r", d] },
  { name: "trivy", license: "Apache-2.0", job: "vulnerabilities, secrets, misconfigurations", version: ["--version"], run: (d) => ["fs", "--scanners", "vuln,secret,misconfig", d] },
];

export function detectExternal(exec = execFileSync) {
  return EXTERNAL.map((t) => {
    let installed = false;
    try { exec(t.name, t.version, { stdio: "ignore", timeout: 5000 }); installed = true; } catch { /* missing */ }
    return { name: t.name, license: t.license, job: t.job, installed };
  });
}

export function runExternal(name, dir, exec = execFileSync) {
  const t = EXTERNAL.find((x) => x.name === name);
  if (!t) throw new Error(`unknown scanner: ${name}`);
  const root = path.resolve(dir);
  try { return { ok: true, output: exec(t.name, t.run(root), { encoding: "utf8", timeout: 300000, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }) }; }
  catch (e) { return { ok: false, output: String(e.stdout ?? "") + String(e.stderr ?? e.message), missing: e.code === "ENOENT" }; }
}
