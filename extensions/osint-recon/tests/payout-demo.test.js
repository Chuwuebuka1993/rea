import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApp } from "../examples/payout-demo/app.js";
import { createCollector } from "../src/sentinel/server.js";
import { SentinelClient } from "../src/sentinel/sdk.js";
import { CanaryStore, makeCanary } from "../src/sentinel/canary.js";

const S = "s".repeat(32);
async function setup({ sentinelUp = true, opts = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "demo-"));
  const col = createCollector({ dir, apps: { shop: S }, ledgerKey: "k".repeat(32), detectorOpts: { utcOffsetH: 1, offHours: [25, 25] } });
  const cport = (await col.listen(0)).port;
  const trap = makeCanary("decoy-admin-key"); new CanaryStore(dir).add(trap);
  const sentinel = new SentinelClient({ url: `http://127.0.0.1:${sentinelUp ? cport : 1}`, app: "shop", secret: S, canaries: new CanaryStore(dir).load(), timeoutMs: 500 });
  const codes = [];
  const app = createApp({ sentinel, notifyOwner: (u, m, x) => codes.push({ u, m, ...x }), ...opts });
  const port = await app.listen(0);
  const call = async (method, p, body, headers = {}) => { const r = await fetch(`http://127.0.0.1:${port}${p}`, { method, body: body ? JSON.stringify(body) : undefined, headers: { "content-type": "application/json", ...headers } }); return { status: r.status, body: await r.json().catch(() => ({})) }; };
  const login = async (user, password, device = "phone-1") => (await call("POST", "/login", { user, password }, { "x-device-id": device })).body.token;
  return { app, call, login, codes, trap, col, close: async () => { await app.close(); await col.close(); } };
}
const PW = "correct horse battery";

test("normal use works: register, login, payout change with re-auth", async () => {
  const t = await setup();
  assert.equal((await t.call("POST", "/register", { user: "ada", password: PW })).status, 201);
  assert.equal((await t.call("POST", "/register", { user: "bad", password: "short" })).status, 400);
  const tok = await t.login("ada", PW);
  const auth = { authorization: `Bearer ${tok}`, "x-device-id": "phone-1" };
  assert.equal((await t.call("PUT", "/payout", { account: "0123456789", password: "wrong-one-here" }, auth)).status, 403);
  assert.equal((await t.call("PUT", "/payout", { account: "0123456789", password: PW }, auth)).status, 200);
  assert.equal(t.app.users.get("ada").payout, "0123456789");
  assert.equal(t.col.ledger.verify().ok, true);
  await t.close();
});

test("attack: password guessing locks the account even for the right password", async () => {
  const t = await setup();
  await t.call("POST", "/register", { user: "ada", password: PW });
  for (let i = 0; i < 5; i++) assert.equal((await t.call("POST", "/login", { user: "ada", password: `guess-number-${i}` })).status, 401);
  assert.equal((await t.call("POST", "/login", { user: "ada", password: PW })).status, 429);
  await t.close();
});

test("attack: takeover then cash-out is blocked; the owner recovers with the out-of-band code; the attacker's account is never paid", async () => {
  const t = await setup();
  await t.call("POST", "/register", { user: "ada", password: PW });
  const tok = await t.login("ada", PW, "phone-1");
  const evil = { authorization: `Bearer ${tok}`, "x-device-id": "attacker-pc" };
  assert.equal((await t.call("POST", "/password", { current: PW, next: "attacker-chosen-pass" }, evil)).status, 200);
  const r = await t.call("PUT", "/payout", { account: "9999999999", password: "attacker-chosen-pass" }, evil);
  assert.equal(r.status, 423);
  assert.equal(t.app.users.get("ada").payout, null);
  const withCode = t.codes.filter((c) => c.code);
  assert.equal(withCode.length, 1);
  assert.ok(!JSON.stringify(r.body).includes(withCode[0].code), "the code must never be in the HTTP response");
  assert.match(withCode[0].m, /ending 9999/);
  assert.equal(t.app.sessions.size, 0, "risk signal should have signed the attacker out");
  assert.equal((await t.call("PUT", "/payout", { account: "9999999999", password: "attacker-chosen-pass" }, evil)).status, 401);
  assert.equal((await t.call("POST", "/recover", { user: "ada", code: "00000000", newPassword: "attacker-again-pass" })).status, 403);
  assert.equal((await t.call("POST", "/recover", { user: "ada", code: withCode[0].code, newPassword: "owner-new-password" })).status, 200);
  assert.equal(t.app.users.get("ada").payout, null, "the attacker's pending account must be discarded");
  assert.equal(t.app.users.get("ada").hold, null);
  assert.ok(await t.login("ada", "owner-new-password", "phone-1"));
  assert.equal(await t.login("ada", "attacker-chosen-pass", "attacker-pc"), undefined);
  await t.close();
});

test("a held change the owner really made can be approved from their own session", async () => {
  const t = await setup({ sentinelUp: false });
  await t.call("POST", "/register", { user: "ada", password: PW });
  const tok = await t.login("ada", PW);
  const h = { authorization: `Bearer ${tok}` };
  assert.equal((await t.call("PUT", "/payout", { account: "0123456789", password: PW }, h)).status, 423);
  const code = t.codes.find((c) => c.code).code;
  assert.equal((await t.call("POST", "/payout/confirm", { code: "11111111", approve: true }, h)).status, 403);
  assert.equal((await t.call("POST", "/payout/confirm", { code, approve: true }, h)).status, 200);
  assert.equal(t.app.users.get("ada").payout, "0123456789");
  await t.close();
});

test("attack: password spraying gets the source IP blocked", async () => {
  const t = await setup();
  for (let i = 0; i < 10; i++) await t.call("POST", "/login", { user: `victim${i}`, password: "whatever-pass-1" });
  assert.equal((await t.call("POST", "/login", { user: "x", password: "y" })).status, 403);
  await t.close();
});

test("trap credential: using the decoy key raises a critical alert and revokes every session", async () => {
  const t = await setup();
  await t.call("POST", "/register", { user: "ada", password: PW });
  const tok = await t.login("ada", PW);
  assert.equal(t.app.sessions.size, 1);
  const r = await t.call("GET", "/internal/api", undefined, { "x-api-key": t.trap.value });
  assert.equal(r.status, 401);
  assert.equal(t.app.sessions.size, 0);
  assert.ok(fs.readFileSync(t.col.ledger.file, "utf8").includes("canary_touch"));
  assert.equal((await t.call("POST", "/logout", undefined, { authorization: `Bearer ${tok}` })).status, 401);
  await t.close();
});

test("fail closed: with Sentinel unreachable, payout changes are held (login still works)", async () => {
  const t = await setup({ sentinelUp: false });
  await t.call("POST", "/register", { user: "ada", password: PW });
  const tok = await t.login("ada", PW);
  assert.ok(tok);
  const r = await t.call("PUT", "/payout", { account: "0123456789", password: PW }, { authorization: `Bearer ${tok}` });
  assert.equal(r.status, 423);
  assert.equal(t.app.users.get("ada").payout, null);
  await t.close();
});

test("hardening: unknown user and wrong password look identical; oversize body rejected; no auth means 401", async () => {
  const t = await setup();
  await t.call("POST", "/register", { user: "ada", password: PW });
  const a = await t.call("POST", "/login", { user: "ghost", password: "nope-nope-nope" });
  const b = await t.call("POST", "/login", { user: "ada", password: "nope-nope-nope" });
  assert.deepEqual([a.status, a.body], [b.status, b.body]);
  const big = await fetch(`http://127.0.0.1:${await t.app.server.address().port}/login`, { method: "POST", body: "x".repeat(20000) }).then((r) => r.status).catch(() => 413);
  assert.equal(big, 413);
  assert.equal((await t.call("PUT", "/payout", { account: "0123456789", password: PW })).status, 401);
  await t.close();
});

test("hardening: the confirmation code cannot be brute-forced (5 wrong tries destroy it)", async () => {
  const t = await setup({ sentinelUp: false });
  await t.call("POST", "/register", { user: "ada", password: PW });
  const tok = await t.login("ada", PW);
  const h = { authorization: `Bearer ${tok}` };
  await t.call("PUT", "/payout", { account: "0123456789", password: PW }, h);
  const real = t.codes.find((c) => c.code).code;
  for (let i = 0; i < 5; i++) assert.equal((await t.call("POST", "/payout/confirm", { code: String(i).padStart(8, "1"), approve: true }, h)).status, 403);
  assert.equal((await t.call("POST", "/payout/confirm", { code: real, approve: true }, h)).status, 403);
  assert.equal(t.app.users.get("ada").payout, null);
  await t.close();
});
