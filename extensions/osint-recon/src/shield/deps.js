import fs from "node:fs";
import path from "node:path";
import { UserError } from "../validate.js";
import { tag } from "./csf.js";

const OSV = "https://api.osv.dev/v1";

/** Read pinned dependencies from package-lock.json (npm) and requirements.txt (PyPI). Only local files are read. */
export function readDependencies(dir) {
  const deps = [];
  const lock = path.join(dir, "package-lock.json");
  if (fs.existsSync(lock)) {
    const j = JSON.parse(fs.readFileSync(lock, "utf8"));
    for (const [p, v] of Object.entries(j.packages ?? {})) {
      if (!p.includes("node_modules/") || !v.version) continue;
      deps.push({ ecosystem: "npm", name: p.split("node_modules/").pop(), version: v.version, dev: !!v.dev });
    }
  }
  const req = path.join(dir, "requirements.txt");
  if (fs.existsSync(req)) {
    for (const line of fs.readFileSync(req, "utf8").split(/\r?\n/)) {
      const m = /^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)/.exec(line);
      if (m) deps.push({ ecosystem: "PyPI", name: m[1], version: m[2], dev: false });
    }
  }
  return deps;
}

async function post(fetchImpl, p, body) {
  const res = await fetchImpl(`${OSV}${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new UserError(`OSV API error: HTTP ${res.status}`);
  return res.json();
}

function severityOf(v) {
  const s = String(v.database_specific?.severity ?? "").toUpperCase();
  return s === "CRITICAL" || s === "HIGH" ? "high" : s === "MODERATE" || s === "MEDIUM" ? "medium" : s === "LOW" ? "low" : "medium";
}
function fixedIn(v, name) {
  const out = new Set();
  for (const a of v.affected ?? []) if (!a.package || a.package.name === name) for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) out.add(e.fixed);
  return [...out];
}

/** Query OSV for every dependency (batched), then fetch details for the unique advisories. Sends only package names and versions. */
export async function auditDependencies(deps, { fetchImpl = fetch, maxDetails = 60 } = {}) {
  const hits = [];
  for (let i = 0; i < deps.length; i += 500) {
    const chunk = deps.slice(i, i + 500);
    const res = await post(fetchImpl, "/querybatch", { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) });
    (res.results ?? []).forEach((r, j) => { for (const v of r.vulns ?? []) hits.push({ dep: chunk[j], id: v.id }); });
  }
  const ids = [...new Set(hits.map((h) => h.id))].slice(0, maxDetails);
  const details = new Map();
  for (const id of ids) {
    const res = await fetchImpl(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20000) });
    if (res.ok) details.set(id, await res.json());
  }
  const findings = hits.filter((h) => details.has(h.id)).map((h) => {
    const v = details.get(h.id);
    const fix = fixedIn(v, h.dep.name);
    return tag({ severity: severityOf(v), title: `${h.dep.name}@${h.dep.version}: ${h.id}`, detail: `${(v.summary ?? "").slice(0, 160)} ${fix.length ? `Fixed in ${fix.join(", ")}.` : "No fixed version listed."}${h.dep.dev ? " (dev dependency)" : ""}`.trim(), target: `${h.dep.ecosystem}:${h.dep.name}` }, "supply_chain");
  });
  const unresolved = hits.length - findings.length;
  return { examined: deps.length, vulnerable: new Set(hits.map((h) => `${h.dep.ecosystem}:${h.dep.name}@${h.dep.version}`)).size, findings, unresolved };
}
