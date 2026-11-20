import fs from "node:fs";
import path from "node:path";
import { UserError } from "../validate.js";
import { summarizeByFunction } from "./csf.js";
import { auditDependencies, readDependencies } from "./deps.js";
import { scanCrypto } from "./crypto.js";

const LOCAL = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

function projectDir(cwd, rel = ".") {
  const p = path.resolve(cwd, rel);
  if (path.relative(cwd, p).startsWith("..") || !fs.existsSync(p) || !fs.statSync(p).isDirectory()) throw new UserError("path must be an existing directory inside the working directory");
  return p;
}

export function createShieldTools({ cwd = process.cwd(), fetchImpl = fetch } = {}) {
  const props = { path: { type: "string", maxLength: 200, description: "Project folder inside the working directory (default .)" } };
  return [
    {
      name: "shield_dependency_audit",
      description: "Supply-chain check: reads package-lock.json and requirements.txt and looks every pinned dependency up in OSV.dev (sends only package names and versions). Maps to NIST CSF GV.SC / MITRE T1195.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: { type: "object", properties: props },
      async handler({ path: rel }) {
        const deps = readDependencies(projectDir(cwd, rel));
        if (!deps.length) return { summary: "No pinned dependencies found (need package-lock.json or requirements.txt with ==).", data: {} };
        const r = await auditDependencies(deps, { fetchImpl });
        return { summary: `${r.examined} dependencies checked, ${r.vulnerable} with known vulnerabilities`, findings: r.findings, data: { examined: r.examined, vulnerable: r.vulnerable, unresolved: r.unresolved } };
      },
    },
    {
      name: "shield_crypto_scan",
      description: "Static scan of source for weak or broken crypto, disabled TLS validation, embedded private keys, and an inventory of quantum-vulnerable public-key use (post-quantum readiness, NIST FIPS 203/204/205).",
      annotations: LOCAL,
      inputSchema: { type: "object", properties: props },
      async handler({ path: rel }) {
        const r = scanCrypto(projectDir(cwd, rel));
        return { summary: `${r.files_scanned} files scanned, ${r.findings.length} finding(s)`, findings: r.findings, data: { quantum_files: r.quantum_files } };
      },
    },
    {
      name: "shield_posture",
      description: "Run the dependency audit and crypto scan together and summarize results by NIST CSF 2.0 function.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: { type: "object", properties: props },
      async handler({ path: rel }) {
        const dir = projectDir(cwd, rel);
        const c = scanCrypto(dir);
        const deps = readDependencies(dir);
        const d = deps.length ? await auditDependencies(deps, { fetchImpl }) : { findings: [], examined: 0, vulnerable: 0 };
        const findings = [...d.findings, ...c.findings];
        return { summary: `Posture: ${findings.filter((f) => f.severity === "high").length} high, ${findings.filter((f) => f.severity === "medium").length} medium across ${d.examined} dependencies and ${c.files_scanned} files`, findings, data: { by_csf_function: summarizeByFunction(findings), not_covered: ["Runtime/host monitoring", "Network traffic analysis", "Cloud configuration", "Human and process controls (CSF Govern)"] } };
      },
    },
  ];
}
