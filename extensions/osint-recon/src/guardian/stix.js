// Reads STIX2 indicator bundles (the format used by public stalkerware/spyware indicator lists, including those MVT consumes).
// Independent implementation written from the public STIX 2.x pattern format. No MVT code is included.
import fs from "node:fs";
import { UserError } from "../validate.js";

const TYPES = ["domains", "ips", "processes", "emails", "file_names", "file_paths", "md5", "sha1", "sha256", "cert_md5", "cert_sha1", "cert_sha256", "app_ids", "properties", "urls"];

export function emptyIocs() {
  return Object.fromEntries(TYPES.map((t) => [t, new Map()])); // value -> collection name
}

function normKey(key) {
  let k = key.trim().toLowerCase();
  k = k.replace(/hashes\.'?([a-z0-9-]+)'?/, (_, a) => `hashes.${a.replace(/-/g, "")}`);
  k = k.replace(/cert\.'?([a-z0-9-]+)'?/, (_, a) => `cert.${a.replace(/-/g, "")}`);
  return k;
}
const MAP = {
  "domain-name:value": ["domains", (v) => v.toLowerCase()],
  "ipv4-addr:value": ["ips"], "process:name": ["processes"], "email-addr:value": ["emails", (v) => v.toLowerCase()],
  "file:name": ["file_names"], "file:path": ["file_paths"],
  "file:hashes.md5": ["md5", (v) => v.toLowerCase()], "file:hashes.sha1": ["sha1", (v) => v.toLowerCase()], "file:hashes.sha256": ["sha256", (v) => v.toLowerCase()],
  "app:cert.md5": ["cert_md5", (v) => v.toLowerCase()], "app:cert.sha1": ["cert_sha1", (v) => v.toLowerCase()], "app:cert.sha256": ["cert_sha256", (v) => v.toLowerCase()],
  "app:id": ["app_ids", (v) => v.toLowerCase()], "android-property:name": ["properties"], "url:value": ["urls", (v) => v.toLowerCase()],
};

/** Split "[a = 'x' OR b = 'y']" into comparisons. Only equality is supported; anything else is skipped and counted. */
export function parsePattern(pattern) {
  const body = String(pattern ?? "").trim().replace(/^\[/, "").replace(/\]$/, "");
  const out = [];
  for (const part of body.split(/\s+OR\s+/i)) {
    const m = /^\s*([^=\s]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*$/.exec(part);
    if (m) out.push([normKey(m[1]), m[2].replace(/\\'/g, "'")]);
  }
  return out;
}

export function parseStix2(text, into = emptyIocs()) {
  let bundle;
  try { bundle = JSON.parse(text); } catch { throw new UserError("not valid STIX2/JSON"); }
  const objs = Array.isArray(bundle.objects) ? bundle.objects : [];
  const names = new Map(); // malware/report id -> name
  for (const o of objs) if (o.type === "malware" || o.type === "report" || o.type === "intrusion-set" || o.type === "campaign") names.set(o.id, o.name ?? o.id);
  const owner = new Map(); // indicator id -> collection name
  for (const o of objs) {
    if (o.type === "relationship" && names.has(o.target_ref)) owner.set(o.source_ref, names.get(o.target_ref));
    if (o.type === "report") for (const r of o.object_refs ?? []) if (!owner.has(r)) owner.set(r, o.name ?? o.id);
  }
  let count = 0, skipped = 0;
  for (const o of objs) {
    if (o.type !== "indicator") continue;
    const parts = parsePattern(o.pattern);
    if (!parts.length) { skipped++; continue; }
    for (const [k, v] of parts) {
      const m = MAP[k];
      if (!m) { skipped++; continue; }
      const val = (m[1] ? m[1](v) : v).trim();
      if (val && !into[m[0]].has(val)) { into[m[0]].set(val, owner.get(o.id) ?? o.name ?? "Unnamed indicator set"); count++; }
    }
  }
  return { iocs: into, count, skipped };
}

export function loadStix2Files(paths) {
  const into = emptyIocs();
  let count = 0, skipped = 0;
  for (const p of paths) {
    if (!fs.existsSync(p)) throw new UserError(`indicator file not found: ${p}`);
    const r = parseStix2(fs.readFileSync(p, "utf8"), into);
    count += r.count; skipped += r.skipped;
  }
  return { iocs: into, count, skipped };
}
