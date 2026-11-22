import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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

import fs2 from "node:fs";
import os2 from "node:os";
import path2 from "node:path";
import { parsePattern, parseStix2 } from "../src/guardian/stix.js";
import { matchAcquisition, readAcquisition } from "../src/guardian/intake.js";

const BUNDLE = JSON.stringify({ type: "bundle", objects: [
  { type: "malware", id: "malware--1", name: "TestSpy" },
  { type: "indicator", id: "indicator--1", pattern: "[app:id = 'com.evil.spy']" },
  { type: "indicator", id: "indicator--2", pattern: "[domain-name:value = 'Evil.Example' OR file:hashes.'SHA-256' = 'ABCDEF']" },
  { type: "indicator", id: "indicator--3", pattern: "[process:name = 'spyd']" },
  { type: "indicator", id: "indicator--4", pattern: "[app:cert.sha1 = 'AA11']" },
  { type: "indicator", id: "indicator--5", pattern: "[file:size > 5]" },
  { type: "relationship", source_ref: "indicator--1", target_ref: "malware--1", relationship_type: "indicates" },
] });

test("stix: parses patterns, normalises hashes, attributes to malware, counts unsupported", () => {
  assert.deepEqual(parsePattern("[file:hashes.'SHA-256' = 'AB' OR url:value = 'http://x']"), [["file:hashes.sha256", "AB"], ["url:value", "http://x"]]);
  const r = parseStix2(BUNDLE);
  assert.equal(r.iocs.app_ids.get("com.evil.spy"), "TestSpy");
  assert.ok(r.iocs.domains.has("evil.example"));
  assert.ok(r.iocs.sha256.has("abcdef"));
  assert.equal(r.skipped, 1);
  assert.throws(() => parseStix2("nope"), /not valid/);
});

test("androidqf intake matches packages, certs, processes and reports missing inputs", () => {
  const d = fs2.mkdtempSync(path2.join(os2.tmpdir(), "aqf-"));
  fs2.mkdirSync(path2.join(d, "run1"));
  fs2.writeFileSync(path2.join(d, "run1", "packages.json"), JSON.stringify([
    { name: "com.evil.spy", installer: "null", system: false, disabled: false, files: [] },
    { name: "com.ok", installer: "com.android.vending", system: false, files: [{ path: "/x.apk", certificate: { Sha1: "aa11" } }] },
  ]));
  fs2.writeFileSync(path2.join(d, "run1", "ps.txt"), "USER PID PPID VSZ RSS WCHAN ADDR S NAME\nroot 1 0 1 1 x 0 S spyd\n");
  const acq = readAcquisition(d);
  assert.deepEqual(acq.found.sort(), ["packages.json", "ps.txt"]);
  assert.ok(acq.missing.includes("getprop.txt"));
  const f = matchAcquisition(acq, parseStix2(BUNDLE).iocs);
  const t = f.map((x) => `${x.title}:${x.detail}`).join("\n");
  assert.match(t, /Installed app matches.*com\.evil\.spy.*TestSpy/);
  assert.match(t, /malicious certificate.*com\.ok/);
  assert.match(t, /Running process.*spyd/);
  const r = triageAndroid({}, { extraFindings: f, coverage: acq.missing });
  assert.ok(r.findings.some((x) => x.title === "Not checked" && /getprop/.test(x.detail)));
});

import { auditGmail, newGmailFindings, deleteFilter } from "../src/guardian/gmailAudit.js";
test("gmail audit: flags auto-forward, forwarding filter, hiding filter, delegate; baseline hides approved; delete works", async () => {
  const data = {
    filters: { filter: [{ id: "f1", criteria: { from: "bank" }, action: { forwardTo: "evil@x.com" } }, { id: "f2", criteria: { from: "google" }, action: { removeLabelIds: ["INBOX"] } }, { id: "f3", criteria: { from: "news" }, action: { addLabelIds: ["Label_1"] } }] },
    forwardingAddresses: { forwardingAddresses: [{ forwardingEmail: "evil@x.com", verificationStatus: "accepted" }] },
    autoForwarding: { enabled: true, emailAddress: "evil@x.com", disposition: "leaveInInbox" },
    delegates: { delegates: [{ delegateEmail: "d@x.com", verificationStatus: "accepted" }] },
  };
  const calls = [];
  const fetchImpl = async (url, o = {}) => { calls.push([o.method ?? "GET", url, o.headers.authorization]); const k = url.split("/settings/")[1]; return { ok: true, status: 200, json: async () => data[k] ?? {} }; };
  const r = await auditGmail({ token: "T", fetchImpl });
  assert.deepEqual(r.findings.map((f) => f.key).sort(), ["autofwd:evil@x.com", "delegate:d@x.com", "filter:f1", "filter:f2", "fwd:evil@x.com"]);
  assert.equal(r.findings.filter((f) => f.severity === "high").length, 3);
  assert.equal(newGmailFindings(r.findings, ["filter:f2", "fwd:evil@x.com"]).length, 3);
  await deleteFilter("f1", { token: "T", fetchImpl });
  assert.equal(calls.at(-1)[0], "DELETE"); assert.ok(calls.every((c) => c[2] === "Bearer T"));
  await assert.rejects(auditGmail({}), /GUARDIAN_GMAIL_TOKEN/);
  await assert.rejects(auditGmail({ token: "T", fetchImpl: async () => ({ ok: false, status: 401 }) }), /expired or missing scope/);
});

import { gatherStatus } from "../src/status.js";
import { Books } from "../src/assurance/books.js";
test("status: empty setup is 'setup' not 'ok'; healthy and tampered books are told apart", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "st-"));
  const env = { GUARDIAN_REGISTRY: `${d}/r.json`, GUARDIAN_STATE: `${d}/s.json`, GUARDIAN_GMAIL_BASELINE: `${d}/g.json`, SENTINEL_DIR: `${d}/sen`, ASSURANCE_DIR: `${d}/books` };
  let r = gatherStatus({ env });
  assert.ok(r.items.every((i) => i.level === "setup")); assert.match(r.summary, /not set up/);
  const b = new Books({ dir: env.ASSURANCE_DIR });
  b.openAccount("bank:main", "asset"); b.openAccount("payable:w", "liability");
  b.post({ id: "s", lines: [{ account: "bank:main", amount: 5000 }, { account: "payable:w", amount: -5000 }] });
  r = gatherStatus({ env }); assert.equal(r.items.find((i) => i.area === "books").level, "ok");
  const f = `${env.ASSURANCE_DIR}/ledger.jsonl`; fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace("5000", "9000"));
  r = gatherStatus({ env }); assert.equal(r.items[0].area, "books"); assert.equal(r.items[0].level, "alert"); assert.match(r.summary, /ALERT/);
});
