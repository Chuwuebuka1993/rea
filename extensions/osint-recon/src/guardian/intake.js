import fs from "node:fs";
import path from "node:path";
import { emptyIocs } from "./stix.js";

const lower = (s) => String(s ?? "").toLowerCase();

function findFiles(dir, name, depth = 3) {
  const out = [];
  (function walk(d, n) {
    if (n < 0) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p, n - 1);
      else if (name instanceof RegExp ? name.test(e.name) : e.name === name) out.push(p);
    }
  })(dir, depth);
  return out;
}
const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return undefined; } };

/** Read an AndroidQF-style acquisition folder: packages.json, ps.txt, getprop.txt, settings_*.txt, files.json. Missing files are reported, not guessed. */
export function readAcquisition(dir) {
  const a = { packages: [], processes: [], properties: {}, settings: {}, files: [], found: [], missing: [] };
  const note = (name, ok) => (ok ? a.found : a.missing).push(name);
  const pk = findFiles(dir, "packages.json")[0];
  note("packages.json", !!pk);
  if (pk) {
    const j = readJson(pk);
    for (const p of Array.isArray(j) ? j : j?.packages ?? []) {
      a.packages.push({
        pkg: p.name ?? p.package_name, installer: p.installer && p.installer !== "null" ? p.installer : null,
        system: !!p.system, disabled: !!p.disabled,
        certs: (p.files ?? []).map((f) => f.certificate ?? {}).flatMap((c) => [["md5", c.Md5 ?? c.md5], ["sha1", c.Sha1 ?? c.sha1], ["sha256", c.Sha256 ?? c.sha256]]).filter(([, v]) => v),
        hashes: (p.files ?? []).flatMap((f) => [["md5", f.md5], ["sha1", f.sha1], ["sha256", f.sha256]]).filter(([, v]) => v),
      });
    }
  }
  const ps = findFiles(dir, "ps.txt")[0];
  note("ps.txt", !!ps);
  if (ps) for (const line of fs.readFileSync(ps, "utf8").split(/\r?\n/).slice(1)) { const c = line.trim().split(/\s+/); if (c.length > 8) a.processes.push(c.slice(8).join(" ")); }
  const gp = findFiles(dir, "getprop.txt")[0];
  note("getprop.txt", !!gp);
  if (gp) for (const m of fs.readFileSync(gp, "utf8").matchAll(/^\[([^\]]+)\]:\s*\[([^\]]*)\]/gm)) a.properties[m[1]] = m[2];
  for (const f of findFiles(dir, /^settings_.*\.txt$/)) a.settings[path.basename(f, ".txt").replace(/^settings_/, "")] = fs.readFileSync(f, "utf8");
  note("settings_*.txt", Object.keys(a.settings).length > 0);
  const fl = findFiles(dir, "files.json")[0];
  note("files.json", !!fl);
  if (fl) { const j = readJson(fl); a.files = (Array.isArray(j) ? j : []).map((x) => x.path).filter(Boolean); }
  return a;
}

const get = (iocs, type, v) => iocs[type]?.get(v);

/** Match acquisition data against loaded indicators. Every finding names the indicator collection it came from. */
export function matchAcquisition(a, iocs = emptyIocs()) {
  const findings = [];
  const hit = (title, detail, coll) => findings.push({ severity: "high", title, detail: `${detail}. Matches indicator set: ${coll}.` });
  for (const p of a.packages) {
    const c = get(iocs, "app_ids", lower(p.pkg));
    if (c) hit("Installed app matches a known spyware indicator", p.pkg, c);
    for (const [alg, v] of p.certs) { const cc = get(iocs, `cert_${alg}`, lower(v)); if (cc) hit("App signed with a known malicious certificate", `${p.pkg} (${alg})`, cc); }
    for (const [alg, v] of p.hashes) { const hc = get(iocs, alg, lower(v)); if (hc) hit("App file hash matches a known sample", `${p.pkg} (${alg})`, hc); }
  }
  for (const proc of a.processes) {
    const base = proc.split(/\s+/)[0];
    const c = get(iocs, "processes", base) ?? get(iocs, "processes", base.split("/").pop());
    if (c) hit("Running process matches an indicator", base, c);
  }
  for (const [name, val] of Object.entries(a.properties)) { const c = get(iocs, "properties", name); if (c) hit("Device property matches an indicator", `${name}=${val}`, c); }
  for (const f of a.files) { const c = get(iocs, "file_paths", f) ?? get(iocs, "file_names", f.split("/").pop()); if (c) hit("File on device matches an indicator", f, c); }
  return findings;
}
