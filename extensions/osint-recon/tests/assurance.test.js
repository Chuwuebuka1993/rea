import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Books, PayoutDesk, reconcile, IncidentLog, controlTests, evidenceMarkdown, toKobo, formatNaira } from "../src/assurance/index.js";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "assure-"));
function mk() {
  const b = new Books({ dir: tmp(), key: "k".repeat(32) });
  b.openAccount("bank:main", "asset", { nonNegative: true });
  b.openAccount("payable:wallets", "liability");
  b.post({ id: "seed", lines: [{ account: "bank:main", amount: "1,000,000.00" }, { account: "payable:wallets", amount: "-1000000" }] });
  return b;
}

test("money: kobo parsing is exact and rejects floats", () => {
  assert.equal(toKobo("1234.5"), 123450); assert.equal(toKobo("0.07"), 7); assert.equal(toKobo(-5), -5);
  assert.throws(() => toKobo(1.5)); assert.throws(() => toKobo("1.234")); assert.throws(() => toKobo("abc"));
  assert.equal(formatNaira(123456), "₦1,234.56");
});

test("books: balanced, idempotent, no overdraw, reversal once, tamper detected", () => {
  const b = mk();
  assert.throws(() => b.post({ id: "u", lines: [{ account: "bank:main", amount: 10 }, { account: "payable:wallets", amount: -9 }] }), /balance/);
  assert.throws(() => b.post({ id: "o", lines: [{ account: "payable:wallets", amount: "2000000" }, { account: "bank:main", amount: "-2000000" }] }), /below zero/);
  const j = { id: "p1", lines: [{ account: "payable:wallets", amount: 500 }, { account: "bank:main", amount: -500 }] };
  assert.equal(b.post(j).posted, true); assert.equal(b.post(j).duplicate, true);
  assert.equal(b.balance("bank:main"), 100000000 - 500);
  assert.ok(b.verify().ok, b.verify().error); // optional undefined fields must not break verification
  b.reverse("p1", { by: "ada" });
  assert.equal(b.balance("bank:main"), 100000000);
  assert.throws(() => b.reverse("p1")); assert.throws(() => b.reverse("rev:p1"));
  assert.ok(b.trialBalance().balanced);
  // survives restart by replay
  const again = new Books({ dir: b.ledger.dir, key: "k".repeat(32) });
  assert.equal(again.balance("bank:main"), 100000000);
  // tampering with an amount in the file is caught
  const f = path.join(b.ledger.dir, "ledger.jsonl");
  fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace("100000000", "900000000"));
  assert.equal(b.verify().ok, false);
});

test("recon: exact, settlement with fees, review, duplicates, missing with aging", () => {
  const now = new Date("2026-11-21");
  const ledger = [
    { id: "l1", ref: "A1", amount: 1000, date: "2026-11-19" },
    { id: "l2", ref: "B1", amount: 5000, date: "2026-11-18", batch: "SETTLE-9", fee: 75 },
    { id: "l3", ref: "B2", amount: 3000, date: "2026-11-18", batch: "SETTLE-9", fee: 45 },
    { id: "l4", ref: "C1", amount: 700, date: "2026-11-01" },
    { id: "l5", ref: "D1", amount: 800, date: "2026-11-10" },
    { id: "l6", ref: "E1", amount: 900, date: "2026-11-20" },
  ];
  const bank = [
    { id: "b1", ref: "A1", amount: 1000, date: "2026-11-19" },
    { id: "b2", ref: "SETTLE-9", amount: 7880, date: "2026-11-20" },
    { id: "b3", ref: "D1", amount: 750, date: "2026-11-10" },
    { id: "b4", ref: "X9", amount: 900, date: "2026-11-20" },
    { id: "b5", ref: "Z1", amount: 123, date: "2026-10-01" },
    { id: "b6", ref: "Z2", amount: 55, date: "2026-11-19" },
    { id: "b7", ref: "Z2", amount: 55, date: "2026-11-19" },
  ];
  const r = reconcile(ledger, bank, { now });
  assert.equal(r.matched.length, 1);
  assert.equal(r.settlements.length, 1); assert.equal(r.settlements[0].fees, 120);
  assert.ok(r.needs_review.some((x) => x.difference === -50));
  assert.ok(r.needs_review.some((x) => /reference differs/.test(x.why)));
  assert.equal(r.duplicates.length, 1);
  assert.equal(r.missing_at_bank.length, 1); assert.equal(r.missing_at_bank[0].ref, "C1");
  assert.equal(r.missing_in_ledger[0].age_days, 51); assert.equal(r.aging.missing_in_ledger["30+"], 1);
});

test("recon: wrong settlement total is never silently matched", () => {
  const r = reconcile([{ id: "a", ref: "1", amount: 100, date: "2026-11-01", batch: "S" }], [{ id: "b", ref: "S", amount: 90, date: "2026-11-02" }], { now: new Date("2026-11-03") });
  assert.equal(r.settlements.length, 0); assert.equal(r.needs_review[0].difference, -10);
});

function desk(over = {}) {
  let t = 1_000_000_000_000;
  const books = mk();
  const d = new PayoutDesk({ books, now: () => t, coolOffMs: 3600e3, dualAt: 5_000_000, velocity: { windowMs: 3600e3, maxKobo: 20_000_000 }, ...over });
  d.addDestination("ada", "GTB-001", "ops");
  t += 2 * 3600e3;
  return { d, books, tick: (ms) => { t += ms; } };
}

test("desk: maker cannot approve; small payout needs one other person", () => {
  const { d, books } = desk();
  const p = d.request({ owner: "ada", amount: "1000.00", dest: "GTB-001", maker: "tobi" });
  assert.throws(() => d.approve(p.id, "tobi"), /own payout/);
  assert.equal(d.approve(p.id, "chi").status, "released");
  assert.equal(books.balance("payable:wallets"), -100000000 + 100000);
  assert.equal(d.approve(p.id, "chi").status, "released");
  assert.equal(books.balance("bank:main"), 100000000 - 100000); // not paid twice
});

test("desk: large payout needs two different approvers", () => {
  const { d } = desk();
  const p = d.request({ owner: "ada", amount: "60000", dest: "GTB-001", maker: "tobi" });
  assert.equal(d.approve(p.id, "chi").status, "held");
  assert.match(d.explain(p.id), /Needs 2/);
  assert.equal(d.approve(p.id, "chi").status, "held");
  assert.equal(d.approve(p.id, "eze").status, "released");
});

test("desk: new or unknown destination is held (takeover cash-out defence)", () => {
  const { d, tick } = desk();
  const p0 = d.request({ owner: "ada", amount: "10", dest: "NEW-999", maker: "tobi" });
  assert.equal(d.approve(p0.id, "chi").status, "held"); assert.match(d.explain(p0.id), /not registered/);
  d.addDestination("ada", "NEW-999", "ops");
  assert.equal(d.tryRelease(p0.id).status, "held"); assert.match(d.explain(p0.id), /cooling-off/);
  tick(3600e3 + 1);
  assert.equal(d.tryRelease(p0.id).status, "released");
});

test("desk: Sentinel hold freezes an owner until a named person releases", () => {
  const { d } = desk();
  d.onSentinelAlert({ actor: "ada", action: "hold_payout_and_confirm_out_of_band", rule: "payout_after_reset", message: "x" });
  const p = d.request({ owner: "ada", amount: "10", dest: "GTB-001", maker: "tobi" });
  assert.equal(d.approve(p.id, "chi").status, "held"); assert.match(d.explain(p.id), /on hold/);
  assert.throws(() => d.releaseHold("ada", "sentinel"));
  d.releaseHold("ada", "chi");
  assert.equal(d.retryHeld()[0].status, "released");
});

test("desk: velocity breaker trips, stays tripped, needs a person to recover", () => {
  const { d } = desk();
  const mkp = (amt) => d.request({ owner: "ada", amount: amt, dest: "GTB-001", maker: "tobi" });
  const a = mkp("150000"); d.approve(a.id, "chi"); d.approve(a.id, "eze");
  assert.equal(d.payouts.get(a.id).status, "released");
  const b = mkp("100000"); d.approve(b.id, "chi"); d.approve(b.id, "eze");
  assert.equal(d.payouts.get(b.id).status, "held"); assert.ok(d.tripped);
  const c = mkp("1"); assert.equal(d.approve(c.id, "chi").status, "held");
  assert.throws(() => d.recover("system"));
  d.recover("chi");
  assert.equal(d.tryRelease(c.id).status, "released");
});

test("desk: books refusing the posting holds the payout rather than throwing", () => {
  const { d } = desk();
  const p = d.request({ owner: "ada", amount: "20000", dest: "GTB-001", maker: "tobi" });
  // drain the bank so the payout would overdraw
  d.books.post({ id: "drain", lines: [{ account: "payable:wallets", amount: "999999" }, { account: "bank:main", amount: "-999999" }] });
  d.approve(p.id, "chi"); d.approve(p.id, "eze");
  assert.equal(d.payouts.get(p.id).status, "held"); assert.match(d.explain(p.id), /Books refused/);
});

test("incidents: 72h clock, human assessment, overdue states", () => {
  let t = 0; const log = new IncidentLog({ now: () => t });
  log.open({ id: "i1", summary: "leaked export", by: "jerome" });
  assert.equal(log.status("i1").state, "needs_assessment");
  assert.throws(() => log.assess("i1", { by: "j" }));
  log.assess("i1", { likelyRisk: true, by: "jerome" });
  t = 70 * 3600e3; assert.equal(log.status("i1").state, "notify_due"); assert.equal(log.status("i1").hoursLeft, 2);
  t = 73 * 3600e3; assert.equal(log.status("i1").state, "overdue");
  log.markNotified("i1", { by: "jerome", reference: "NDPC-1" }); assert.equal(log.status("i1").state, "notified");
  log.open({ id: "i2", summary: "x", by: "j" }); t = 200 * 3600e3; assert.equal(log.status("i2").state, "overdue_unassessed");
});

test("evidence: controls pass on healthy books and fail after tampering", () => {
  const { d, books } = desk();
  const ok = controlTests({ books, desk: d });
  assert.ok(ok.every((r) => r.ok), JSON.stringify(ok.filter((r) => !r.ok)));
  assert.match(evidenceMarkdown(ok), /controls passed/);
  const f = path.join(books.ledger.dir, "ledger.jsonl");
  fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace("1000000", "9000000"));
  const bad = controlTests({ books, desk: d });
  assert.equal(bad.find((r) => r.id === "books-chain").ok, false);
});

import { parseCsv } from "../src/assurance/cli.js";
test("cli csv: parses naira to kobo and rejects bad rows", () => {
  const r = parseCsv("id,ref,amount,date,batch,fee\n1,A,1,234.50,2026-11-01,,\n".replace("1,234.50", "1234.50"));
  assert.equal(r[0].amount, 123450);
  assert.throws(() => parseCsv("id,ref,amount,date\n1,A,5.555,2026-11-01"));
  assert.throws(() => parseCsv("id,ref,amount,date\n1,A,5,notadate"));
  assert.throws(() => parseCsv("id,ref,date\n1,A,2026-11-01"));
});
