import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanCode, detectExternal, runExternal } from "../src/guardian/codeScan.js";

function proj(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "cs-"));
  for (const [n, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, n)), { recursive: true }); fs.writeFileSync(path.join(d, n), c); }
  return d;
}
const FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";

test("finds a token without ever printing its value", () => {
  const d = proj({ "app.js": `const t = "${FAKE_GH}";\n` });
  const r = scanCode(d);
  assert.equal(r.counts.high, 1);
  assert.equal(r.findings[0].rule, "github-token");
  assert.equal(r.findings[0].line, 1);
  assert.ok(!JSON.stringify(r).includes(FAKE_GH));
});
test("placeholders and env lookups are not flagged", () => {
  const d = proj({ "a.js": 'const k = process.env.API_KEY; const t = "your_token_here_please";\n', ".env.example": "API_KEY=changeme\n" });
  assert.equal(scanCode(d).findings.length, 0);
});
test(".env is high unless git ignores it", () => {
  assert.equal(scanCode(proj({ ".env": "A=1\n" })).findings[0].severity, "high");
  assert.equal(scanCode(proj({ ".env": "A=1\n", ".gitignore": ".env\n" })).findings[0].severity, "low");
});
test("risky code patterns and package.json checks", () => {
  const d = proj({ "x.js": "eval(input);\nhttps.get(u,{rejectUnauthorized:false});\n", "package.json": '{"scripts":{"postinstall":"node x"},"dependencies":{"left":"*"}}' });
  const rules = scanCode(d).findings.map((f) => f.rule);
  for (const r of ["eval", "tls-verify-off", "install-script", "unpinned-dependency", "no-lockfile"]) assert.ok(rules.includes(r), r);
});
test("skips node_modules, symlinks and test folders' severity", () => {
  const d = proj({ "node_modules/p/i.js": `k="${FAKE_GH}"`, "tests/t.js": `k="${FAKE_GH}"` });
  fs.symlinkSync("/etc", path.join(d, "link"));
  const r = scanCode(d);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].severity, "low");
});
test("rejects a missing folder", () => assert.throws(() => scanCode("/nonexistent-zzz")));
test("scanner detection uses only the injected exec and never downloads", () => {
  const seen = [];
  const exec = (n) => { seen.push(n); if (n !== "gitleaks") throw new Error("nope"); };
  const d = detectExternal(exec);
  assert.deepEqual(d.filter((x) => x.installed).map((x) => x.name), ["gitleaks"]);
  assert.equal(runExternal("semgrep", ".", () => { const e = new Error("x"); e.code = "ENOENT"; throw e; }).missing, true);
  assert.throws(() => runExternal("rm", "."));
});
test("a reviewed line with a reason is allowed; no reason or a secret is not", () => {
  const ok = proj({ "a.js": "// guardian-scan: allow tls-verify-off (probe must read invalid certificates)\nx({rejectUnauthorized:false});\n" });
  assert.equal(scanCode(ok).findings.length, 0);
  const noReason = proj({ "a.js": "x({rejectUnauthorized:false}); // guardian-scan: allow tls-verify-off\n" });
  assert.equal(scanCode(noReason).findings.length, 1);
  const secret = proj({ "a.js": `// guardian-scan: allow all (trust me bro it is fine)\nk="${FAKE_GH}";\n` });
  assert.equal(scanCode(secret).counts.high, 1);
});
