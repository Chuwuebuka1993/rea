import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { assessRegistry, validateAccount } from "../src/guardian/registry.js";
import { parseRange, pwnedCount, passwordVerdict } from "../src/guardian/hibp.js";
import { auditGithub, diffSnapshots, sshFingerprint } from "../src/guardian/githubAudit.js";
import { triageAndroid, parseComponents, parseThirdParty } from "../src/guardian/android.js";
import { getPlaybook, listPlatforms } from "../src/guardian/playbooks.js";

const NOW = Date.parse("2026-11-19T00:00:00Z");

test("registry rejects secrets and unknown fields", () => {
  assert.throws(() => validateAccount({ id: "a", password: "x" }), /secret|unknown/);
  assert.throws(() => validateAccount({ id: "a", twofa: "magic" }), /twofa/);
  assert.throws(() => validateAccount({ id: "bad id!" }), /id must/);
});

test("scoring: strong account beats bare account; email caps dependent account", () => {
  const strong = { id: "mail", platform: "google", twofa: "passkey", backup_codes_saved: true, recovery_email: true, recovery_phone: true, passkey_or_key: true, password_manager: true, unique_password: true, last_reviewed: "2026-10-01", owners: 1 };
  const weakMail = { id: "wmail", twofa: "none" };
  const child = { ...strong, id: "gh", platform: "github", email_account: "wmail" };
  const res = assessRegistry({ accounts: [strong, weakMail, child].map(validateAccount) }, NOW);
  const by = Object.fromEntries(res.accounts.map((a) => [a.id, a]));
  assert.ok(by.mail.score >= 85);
  assert.ok(by.wmail.score < 40);
  assert.equal(by.gh.capped_by, "wmail");
  assert.equal(by.gh.score, by.wmail.score);
  assert.match(by.gh.actions[0], /Fix/);
  assert.equal(res.accounts[0].score <= res.accounts.at(-1).score, true);
});

test("critical account with one owner is flagged", () => {
  const r = assessRegistry({ accounts: [validateAccount({ id: "x", twofa: "totp", critical: true, owners: 1, last_reviewed: "2026-11-01" })] }, NOW);
  assert.ok(r.accounts[0].actions.some((a) => /second trusted owner/.test(a)));
});

test("HIBP: sends only a 5-char prefix and matches the suffix", async () => {
  const sha = crypto.createHash("sha1").update("password").digest("hex").toUpperCase();
  let url;
  const fetchImpl = async (u) => { url = u; return { ok: true, text: async () => `0000000000000000000000000000000000A:1\r\n${sha.slice(5)}:42\r\n` }; };
  const n = await pwnedCount("password", { fetchImpl });
  assert.equal(n, 42);
  assert.equal(url, `https://api.pwnedpasswords.com/range/${sha.slice(0, 5)}`);
  assert.ok(!url.includes(sha.slice(5)));
  assert.equal(parseRange("ABC:0", "ZZZ"), 0);
  assert.equal(passwordVerdict(0).safe, true);
  assert.equal(passwordVerdict(3).safe, false);
});

function ghFetch({ twofa = true, keyAge = 400, hooks = [] } = {}) {
  const pub = "ssh-ed25519 " + Buffer.from("fake-key-bytes").toString("base64") + " me@x";
  const created = new Date(NOW - keyAge * 86400000).toISOString();
  const routes = {
    "/user": { login: "me", two_factor_authentication: twofa },
    "/user/keys": [{ id: 1, title: "laptop", key: pub, created_at: created }],
    "/user/gpg_keys": [],
    "/user/emails": [{ email: "a@b.c", verified: false, visibility: "public" }],
    "/user/repos": [{ full_name: "me/app" }],
    "/repos/me/app/keys": [{ id: 9, title: "ci", read_only: false }],
    "/repos/me/app/hooks": hooks,
  };
  return async (u) => {
    const p = u.replace("https://api.github.com", "").split("?")[0];
    return p in routes ? { ok: true, status: 200, headers: new Map(), json: async () => routes[p] } : { ok: false, status: 404, headers: new Map() };
  };
}

test("github audit flags 2FA off, new key, unverified email, write deploy key, http hook", async () => {
  const r = await auditGithub({ token: "t", fetchImpl: ghFetch({ twofa: false, keyAge: 2, hooks: [{ id: 5, config: { url: "http://evil.example/x" } }] }), now: NOW });
  const titles = r.findings.map((f) => f.title).join("|");
  for (const t of ["Two-factor authentication is OFF", "SSH key added in the last 7 days", "Unverified email", "Deploy key with WRITE", "plain HTTP"]) assert.match(titles, new RegExp(t));
  assert.equal(r.snapshot.ssh_keys[0].fingerprint, sshFingerprint("ssh-ed25519 " + Buffer.from("fake-key-bytes").toString("base64")));
});

test("github audit needs a token and the token is never echoed", async () => {
  await assert.rejects(() => auditGithub({}), /GUARDIAN_GITHUB_TOKEN/);
  const r = await auditGithub({ token: "SECRET-TOKEN-123", fetchImpl: ghFetch(), now: NOW });
  assert.ok(!JSON.stringify(r).includes("SECRET-TOKEN-123"));
});

test("baseline diff raises alerts only for new items", async () => {
  const a = (await auditGithub({ token: "t", fetchImpl: ghFetch(), now: NOW })).snapshot;
  assert.equal(diffSnapshots(a, a).length, 0);
  const b = structuredClone(a);
  b.ssh_keys.push({ id: 2, title: "intruder", fingerprint: "SHA256:zzz" });
  b.webhooks.push({ repo: "me/app", id: 77, host: "x.io" });
  const alerts = diffSnapshots(a, b);
  assert.deepEqual(alerts.map((x) => x.title).sort(), ["New SSH key", "New webhook"]);
  assert.equal(alerts.find((x) => x.title === "New SSH key").severity, "high");
});

test("android triage finds spy-style powers and honours allow list and IOCs", () => {
  const r = triageAndroid({
    accessibility: "com.evil.spy/com.evil.spy.Svc:com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService",
    notification_listeners: "com.snoop.app/com.snoop.app.Listener",
    device_admins: "Admin policies:\n  com.hider.admin/com.hider.admin.Receiver:\n",
    third_party_packages: "package:com.whatsapp  installer=com.android.vending\npackage:com.evil.spy  installer=null\n",
  }, { iocs: ["com.evil.spy"] });
  const t = r.findings.map((f) => `${f.severity}:${f.title}:${f.detail}`).join("\n");
  assert.match(t, /high:Package matches your indicator list:com\.evil\.spy/);
  assert.match(t, /Accessibility service enabled:com\.evil\.spy/);
  assert.doesNotMatch(t, /Accessibility service enabled:com\.google/);
  assert.match(t, /Notification access granted:com\.snoop\.app/);
  assert.match(t, /high:Device administrator app:com\.hider\.admin/);
  assert.match(t, /not installed from a known store/);
  assert.ok(r.limits.length >= 2);
});

test("android parsers handle null and empty", () => {
  assert.deepEqual(parseComponents("null"), []);
  assert.deepEqual(parseThirdParty(""), []);
  assert.equal(triageAndroid({}).findings.length, 0);
});

test("playbooks exist for the apps in use, with sources and dates", () => {
  for (const p of ["google", "github", "whatsapp", "facebook", "instagram", "telegram", "x", "generic"]) {
    const pb = getPlaybook(p);
    assert.ok(pb.source && pb.verified_on && pb.recover.length, p);
  }
  assert.equal(getPlaybook("gmail").name, getPlaybook("google").name);
  assert.equal(getPlaybook("nope"), undefined);
  assert.ok(listPlatforms().includes("generic"));
});

import { approve, respond, revoke } from "../src/guardian/respond.js";

function mkSnap(extra = {}) { return { ssh_keys: [{ id: 1, title: "laptop", fingerprint: "SHA256:aaa" }], gpg_keys: [], emails: ["a@b.c"], deploy_keys: [], webhooks: [], ...extra }; }

test("response: no baseline means alert only, never revoke", async () => {
  const calls = [];
  const s = { approved: null, pending: {}, log: [] };
  const alerts = diffSnapshots({ ssh_keys: [] }, mkSnap());
  const { events } = await respond({ alerts, state: s, enforce: true, token: "t", fetchImpl: async (u, o) => { calls.push(o.method); return { status: 204 }; } });
  assert.equal(calls.length, 0);
  assert.match(events[0].text, /no approved baseline/);
});

test("response: unapproved key alerts, waits for grace, then is revoked only with enforce", async () => {
  const calls = [];
  const fetchImpl = async (u, o) => { calls.push(`${o.method} ${u}`); return { status: 204 }; };
  const state = { approved: mkSnap(), pending: {}, log: [] };
  const now = 1_000_000;
  const bad = mkSnap({ ssh_keys: [...mkSnap().ssh_keys, { id: 7, title: "intruder", fingerprint: "SHA256:bad" }] });
  let r = await respond({ alerts: diffSnapshots(state.approved, bad), state, now, enforce: true, token: "t", fetchImpl });
  assert.equal(calls.length, 0);
  assert.match(r.events[0].text, /UNAPPROVED New SSH key/);
  r = await respond({ alerts: diffSnapshots(state.approved, bad), state, now: now + 11 * 60000, enforce: false, token: "t", fetchImpl });
  assert.equal(calls.length, 0);
  assert.match(r.events[0].text, /dry run/);
  r = await respond({ alerts: diffSnapshots(state.approved, bad), state, now: now + 12 * 60000, enforce: true, token: "t", fetchImpl });
  assert.deepEqual(calls, ["DELETE https://api.github.com/user/keys/7"]);
  assert.equal(r.events[0].level, "action");
  assert.deepEqual(state.pending, {});
});

test("response: approving a pending item stops revocation", async () => {
  const calls = [];
  const state = { approved: mkSnap(), pending: {}, log: [] };
  const bad = mkSnap({ webhooks: [{ repo: "me/app", id: 5, host: "x.io" }] });
  await respond({ alerts: diffSnapshots(state.approved, bad), state, now: 0, enforce: true, token: "t" });
  assert.match(approve(state, bad, "hook:me/app#5"), /approved/);
  const alerts = diffSnapshots(state.approved, bad);
  assert.equal(alerts.length, 0);
  await respond({ alerts, state, now: 99 * 60000, enforce: true, token: "t", fetchImpl: async () => { calls.push(1); return { status: 204 }; } });
  assert.equal(calls.length, 0);
});

test("response: circuit breaker refuses mass revocation; emails are never auto-revoked", async () => {
  const calls = [];
  const fetchImpl = async () => { calls.push(1); return { status: 204 }; };
  const many = Array.from({ length: 6 }, (_, i) => ({ id: 10 + i, title: "k", fingerprint: `SHA256:${i}` }));
  const state = { approved: mkSnap(), pending: {}, log: [] };
  const snap = mkSnap({ ssh_keys: [...mkSnap().ssh_keys, ...many], emails: ["a@b.c", "evil@x.y"] });
  await respond({ alerts: diffSnapshots(state.approved, snap), state, now: 0, enforce: true, token: "t", fetchImpl });
  const r = await respond({ alerts: diffSnapshots(state.approved, snap), state, now: 99 * 60000, enforce: true, token: "t", fetchImpl });
  assert.equal(calls.length, 0);
  assert.ok(r.events.some((e) => e.level === "critical"));
  await assert.rejects(() => revoke({ type: "email" }, { token: "t" }), /cannot be revoked/);
});
