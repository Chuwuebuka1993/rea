import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { auditDependencies, readDependencies } from "../src/shield/deps.js";
import { scanCrypto } from "../src/shield/crypto.js";
import { summarizeByFunction } from "../src/shield/csf.js";
import { createShieldTools } from "../src/shield/tools.js";

function proj(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "shield-"));
  for (const [n, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, n)), { recursive: true }); fs.writeFileSync(path.join(d, n), c); }
  return d;
}

test("readDependencies parses npm lockfile and pinned pip requirements", () => {
  const d = proj({
    "package-lock.json": JSON.stringify({ packages: { "": {}, "node_modules/lodash": { version: "4.17.20" }, "node_modules/a/node_modules/b": { version: "1.0.0", dev: true } } }),
    "requirements.txt": "flask==2.0.0\nrequests>=2\n# c\n",
  });
  const deps = readDependencies(d);
  assert.deepEqual(deps.map((x) => `${x.ecosystem}:${x.name}@${x.version}`).sort(), ["PyPI:flask@2.0.0", "npm:b@1.0.0", "npm:lodash@4.17.20"]);
  assert.equal(deps.find((x) => x.name === "b").dev, true);
});

test("OSV audit sends only names/versions, batches, and reports severity and fixed version", async () => {
  const sent = [];
  const fetchImpl = async (u, o) => {
    if (u.endsWith("/querybatch")) { sent.push(o.body); return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-1" }] }, {}] }) }; }
    return { ok: true, json: async () => ({ id: "GHSA-1", summary: "Prototype pollution", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }) };
  };
  const r = await auditDependencies([{ ecosystem: "npm", name: "lodash", version: "4.17.20" }, { ecosystem: "npm", name: "safe", version: "1.0.0" }], { fetchImpl });
  assert.equal(r.vulnerable, 1);
  assert.equal(r.findings[0].severity, "high");
  assert.match(r.findings[0].detail, /Fixed in 4\.17\.21/);
  assert.equal(r.findings[0].framework.csf, "GV.SC");
  assert.ok(!sent[0].includes("password") && JSON.parse(sent[0]).queries.length === 2);
});

test("crypto scan flags weak crypto and builds a quantum inventory; skips node_modules", () => {
  const d = proj({
    "src/a.js": "const h = crypto.createHash('md5');\nhttps.request({ rejectUnauthorized: false });\ncrypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\nconst t = Math.random() + 'token';",
    "src/b.py": "requests.get(u, verify=False)\ncipher = AES.new(k, AES.MODE_ECB)\n",
    "src/k.js": "const k = `-----BEGIN PRIVATE KEY-----`;",
    "node_modules/x/bad.js": "createHash('md5')",
  });
  const r = scanCrypto(d);
  const t = r.findings.map((f) => f.title).join("|");
  for (const x of ["Weak hash", "TLS certificate validation disabled", "RSA key shorter", "Math.random", "ECB mode", "Private key embedded", "Quantum-vulnerable"]) assert.match(t, new RegExp(x));
  assert.ok(!r.findings.some((f) => f.target?.includes("node_modules")));
  assert.equal(r.files_scanned, 3);
  const by = summarizeByFunction(r.findings);
  assert.ok(by.Protect.high >= 3);
});

test("shield tools refuse paths outside the working directory and run posture", async () => {
  const d = proj({ "a.js": "createHash('sha1')" });
  const tools = createShieldTools({ cwd: d, fetchImpl: async () => { throw new Error("no network expected"); } });
  const posture = tools.find((t) => t.name === "shield_posture");
  await assert.rejects(() => posture.handler({ path: ".." }), /inside the working directory/);
  const r = await posture.handler({});
  assert.match(r.summary, /1 medium/);
  assert.ok(r.data.not_covered.length >= 3);
});
