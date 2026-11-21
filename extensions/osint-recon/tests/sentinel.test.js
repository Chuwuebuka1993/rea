import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Ledger } from "../src/sentinel/ledger.js";
import { Detector } from "../src/sentinel/detect.js";
import { validateEvent } from "../src/sentinel/events.js";
import { createCollector, sign } from "../src/sentinel/server.js";
import { SentinelClient } from "../src/sentinel/sdk.js";
import { CanaryStore, canaryLabel, makeCanary } from "../src/sentinel/canary.js";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-"));
const KEY = "k".repeat(32);

test("ledger: intact chain verifies; edit, deletion, insertion and tail truncation are all detected", () => {
  const dir = tmp(), l = new Ledger({ dir, key: KEY });
  for (let i = 0; i < 5; i++) l.append({ type: "login_success", actor: `u${i}` });
  assert.equal(l.verify().ok, true);
  const orig = fs.readFileSync(l.file, "utf8"), lines = orig.split("\n").filter(Boolean);
  const check = (content, re) => { fs.writeFileSync(l.file, content); const r = new Ledger({ dir, key: KEY }).verify(); assert.equal(r.ok, false); assert.match(r.error, re); };
  check(orig.replace("u2", "u9"), /modified/);
  check([...lines.slice(0, 2), ...lines.slice(3)].join("\n") + "\n", /sequence broken|chain/);
  check(lines.slice(0, 3).join("\n") + "\n", /tail was removed/);
  fs.writeFileSync(l.file, orig);
  assert.equal(new Ledger({ dir, key: KEY }).verify().ok, true);
  const head = JSON.parse(fs.readFileSync(l.headFile, "utf8")); head.seq = 3; fs.writeFileSync(l.headFile, JSON.stringify(head));
  assert.match(new Ledger({ dir, key: KEY }).verify().error, /signature/);
});

test("ledger: reopening continues the chain", () => {
  const dir = tmp(); new Ledger({ dir }).append({ type: "logout" });
  const l2 = new Ledger({ dir }); l2.append({ type: "logout" });
  assert.deepEqual([l2.verify().ok, l2.verify().entries], [true, 2]);
});

test("events: rejects unknown types, secret-looking and nested meta", () => {
  assert.throws(() => validateEvent({ type: "nope" }), /unknown event/);
  assert.throws(() => validateEvent({ type: "login_failure", meta: { password: "x" } }), /secret/);
  assert.throws(() => validateEvent({ type: "login_failure", meta: { a: { b: 1 } } }), /string, number/);
  assert.throws(() => validateEvent({ type: "login_failure", actor: "x".repeat(200) }), /too long/);
  assert.deepEqual(validateEvent({ type: "login_failure", actor: "u1", extra: "dropped" }), { type: "login_failure", actor: "u1" });
});

const E = (type, minute, extra = {}) => ({ seq: minute + 1, ts: new Date(Date.UTC(2026, 10, 21, 12, minute)).toISOString(), event: { app: "ssng", type, actor: "ada", ip: "1.1.1.1", ...extra } });

test("detect: brute force then success is a suspected takeover", () => {
  const d = new Detector(); let all = [];
  for (let i = 0; i < 5; i++) all.push(...d.ingest(E("login_failure", i)));
  all.push(...d.ingest(E("login_success", 6, { device: "d1" })));
  const rules = all.map((a) => a.rule);
  assert.ok(rules.includes("brute_force") && rules.includes("takeover_suspected"));
  assert.equal(all.find((a) => a.rule === "takeover_suspected").severity, "critical");
});

test("detect: spraying across accounts from one ip; old failures expire", () => {
  const d = new Detector(); let a = [];
  for (let i = 0; i < 10; i++) a.push(...d.ingest({ seq: i, ts: E("x", 0).ts, event: { app: "ssng", type: "login_failure", actor: `u${i}`, ip: "9.9.9.9" } }));
  assert.ok(a.some((x) => x.rule === "credential_stuffing" && x.action === "block_ip"));
  const d2 = new Detector(); for (let i = 0; i < 4; i++) d2.ingest(E("login_failure", i));
  assert.equal(d2.ingest(E("login_success", 40, { device: "d" })).some((x) => x.rule === "takeover_suspected"), false);
});

test("detect: payout change after password reset is critical; admin action from unseen device is high", () => {
  const d = new Detector();
  d.ingest(E("login_success", 0, { device: "phone" }));
  d.ingest(E("password_reset", 1));
  const a = d.ingest(E("payout_change", 5, { device: "phone" }));
  assert.ok(a.some((x) => x.rule === "payout_after_reset" && x.action.startsWith("hold_payout")));
  const b = d.ingest(E("role_change", 6, { device: "laptop-x", meta: { new_role: "admin" } }));
  assert.ok(b.some((x) => x.rule === "new_device_admin") && b.some((x) => x.rule === "privilege_grant"));
  assert.equal(new Detector().ingest({ seq: 1, ts: E("x", 0).ts, event: { app: "a", type: "canary_touch", ip: "2.2.2.2" } })[0].severity, "critical");
});

function signedHeaders(secret, app, body, over = {}) {
  const ts = over.ts ?? Date.now(), nonce = over.nonce ?? Math.random().toString(16).slice(2);
  return { "x-sentinel-app": app, "x-sentinel-ts": String(ts), "x-sentinel-nonce": nonce, "x-sentinel-sig": over.sig ?? sign(secret, ts, nonce, body) };
}

test("collector auth: bad signature, unknown app, stale time, replay, bad body", () => {
  const S = "s".repeat(32), c = createCollector({ dir: tmp(), apps: { ssng: S }, ledgerKey: KEY });
  const body = JSON.stringify({ type: "login_failure", actor: "ada", ip: "1.2.3.4" });
  assert.equal(c.handle(signedHeaders(S, "ssng", body), body).status, 202);
  const h = signedHeaders(S, "ssng", body, { nonce: "n1" });
  assert.equal(c.handle(h, body).status, 202);
  assert.equal(c.handle(h, body).status, 409);
  assert.equal(c.handle(signedHeaders("w".repeat(32), "ssng", body), body).status, 401);
  assert.equal(c.handle(signedHeaders(S, "other", body), body).status, 401);
  assert.equal(c.handle(signedHeaders(S, "ssng", body, { ts: Date.now() - 3600000 }), body).status, 401);
  const tampered = body.replace("ada", "eve");
  assert.equal(c.handle(signedHeaders(S, "ssng", body), tampered).status, 401);
  const bad = JSON.stringify({ type: "login_failure", meta: { token: "abc" } });
  assert.equal(c.handle(signedHeaders(S, "ssng", bad), bad).status, 400);
  assert.equal(c.ledger.verify().ok, true);
});

test("collector rate limit and restart replays detector state", async () => {
  const S = "s".repeat(32), dir = tmp(), c = createCollector({ dir, apps: { ssng: S }, ledgerKey: KEY, ratePerMin: 3 });
  const body = JSON.stringify({ type: "logout" });
  const codes = Array.from({ length: 5 }, () => c.handle(signedHeaders(S, "ssng", body), body).status);
  assert.deepEqual(codes.slice(3), [429, 429]);
  const c2 = createCollector({ dir, apps: { ssng: S }, ledgerKey: KEY });
  for (let i = 0; i < 4; i++) { const b = JSON.stringify({ type: "login_failure", actor: "z", ip: "3.3.3.3" }); c2.handle(signedHeaders(S, "ssng", b), b); }
  const c3 = createCollector({ dir, apps: { ssng: S }, ledgerKey: KEY });
  const b5 = JSON.stringify({ type: "login_failure", actor: "z", ip: "3.3.3.3" });
  assert.ok(c3.handle(signedHeaders(S, "ssng", b5), b5).body.alerts.some((a) => a.rule === "brute_force"));
});

test("end to end: SDK over real HTTP raises alert, canary use is critical, oversize rejected, ledger verifies", async () => {
  const S = "s".repeat(32), dir = tmp(), seen = [];
  const c = createCollector({ dir, apps: { ssng: S }, ledgerKey: KEY, notify: (a) => seen.push(a) });
  const { port } = await c.listen(0);
  const trap = makeCanary("old-env-file"); new CanaryStore(dir).add(trap);
  const sdk = new SentinelClient({ url: `http://127.0.0.1:${port}`, app: "ssng", secret: S, canaries: new CanaryStore(dir).load() });
  for (let i = 0; i < 5; i++) await sdk.report({ type: "login_failure", actor: "ada", ip: "8.8.8.8" });
  assert.ok(seen.some((a) => a.rule === "brute_force"));
  assert.equal(await sdk.checkCredential("not-a-trap-value", { ip: "6.6.6.6" }), false);
  assert.equal(await sdk.checkCredential(trap.value, { ip: "6.6.6.6" }), true);
  assert.ok(seen.some((a) => a.rule === "canary" && a.severity === "critical"));
  assert.ok(!fs.readFileSync(new CanaryStore(dir).file, "utf8").includes(trap.value));
  const big = await fetch(`http://127.0.0.1:${port}/events`, { method: "POST", body: "x".repeat(40000) }).then((r) => r.status).catch(() => 413);
  assert.equal(big, 413);
  assert.equal(c.ledger.verify().ok, true);
  const dead = new SentinelClient({ url: "http://127.0.0.1:1", app: "ssng", secret: S, timeoutMs: 300 });
  assert.equal((await dead.report({ type: "logout" })).ok, false);
  await c.close();
});

test("canary lookup is hash based and length limited", () => {
  const t = makeCanary("x", "token");
  assert.equal(canaryLabel(t.value, [{ label: "x", sha256: t.sha256 }]), "x");
  assert.equal(canaryLabel("short", [{ label: "x", sha256: t.sha256 }]), undefined);
});

test("collector: unauthenticated flood cannot use up an app's quota, and is itself limited per source", () => {
  const S = "s".repeat(32), c = createCollector({ dir: tmp(), apps: { ssng: S }, ledgerKey: KEY, ratePerMin: 3 });
  const body = JSON.stringify({ type: "logout" });
  const forged = () => c.handle({ ...signedHeaders("x".repeat(32), "ssng", body) }, body, "6.6.6.6").status;
  const codes = Array.from({ length: 70 }, forged);
  assert.equal(codes[0], 401);
  assert.equal(codes.at(-1), 429);
  assert.equal(c.handle(signedHeaders(S, "ssng", body), body, "1.1.1.1").status, 202);
  assert.equal(c.handle(signedHeaders(S, "ssng", body), body, "1.1.1.1").status, 202);
});
