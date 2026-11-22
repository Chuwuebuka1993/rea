import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { toKobo, formatNaira } from "./money.js";

const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
/** Proof an approver attaches: HMAC-SHA256 of "<payout id>:<checker name>" keyed with their approver secret. */
export function approvalProof(secret, id, checker) {
  return crypto.createHmac("sha256", secret).update(`${id}:${checker}`).digest("hex");
}

/**
 * Payout desk: money leaves only after maker-checker approval, and anything unusual is held with a plain-language reason.
 * Rules: the requester can never approve; amounts >= dualAt need two different approvers; a payout destination must be
 * registered and older than coolOffMs; a velocity breaker trips when too much leaves in a window and stays tripped until
 * a named person recovers it; an account Sentinel flagged is held. When in doubt the money stays put (fail closed).
 *
 * Controls added in the P0 hardening:
 * - Durable state (dir option): payouts, destinations, holds, the velocity breaker and the audit log survive a restart.
 *   Without `dir` the desk stays in-memory (used by tests and probes).
 * - Authenticated approvers (approvers option): { name: secret }. Approvals then require a proof (see approvalProof);
 *   a bare name is rejected, so an approver identity is bound to a secret, not to whoever typed the name.
 *   Without `approvers`, approvals remain name-based for compatibility; record-level `auth: "name"` shows that on the payout.
 * - Hold independence: the person who placed a hold can never release it. Sentinel holds (by "sentinel") need any named
 *   human; human holds need a different named human.
 */
export class PayoutDesk {
  constructor({ books, dir, approvers, bankAccount = "bank:main", payableAccount = "payable:wallets", dualAt = 50_000_00, coolOffMs = 24 * 3600e3, velocity = { windowMs: 3600e3, maxKobo: 500_000_00 }, now = () => Date.now() } = {}) {
    Object.assign(this, { books, dir, approvers, bankAccount, payableAccount, dualAt, coolOffMs, velocity, now });
    this.payouts = new Map(); this.destinations = new Map(); this.holds = new Map(); this.released = []; this.tripped = null; this.log = [];
    if (dir) { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); this.file = path.join(dir, "desk-state.json"); this.#load(); }
  }
  #load() {
    if (!fs.existsSync(this.file)) return;
    let s;
    try { s = JSON.parse(fs.readFileSync(this.file, "utf8")); }
    catch { throw new Error(`payout desk state at ${this.file} is corrupt: refusing to guess. Restore desk-state.json from backup.`); }
    this.payouts = new Map(s.payouts ?? []);
    this.destinations = new Map(s.destinations ?? []);
    this.holds = new Map(s.holds ?? []);
    this.released = s.released ?? [];
    this.tripped = s.tripped ?? null;
    this.log = s.log ?? [];
  }
  #save() {
    if (!this.file) return;
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, payouts: [...this.payouts], destinations: [...this.destinations], holds: [...this.holds], released: this.released, tripped: this.tripped, log: this.log }), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
  #note(kind, id, by, text) { this.log.push({ at: new Date(this.now()).toISOString(), kind, id, by, text }); }
  addDestination(owner, dest, by) { if (!this.destinations.has(`${owner}|${dest}`)) { this.destinations.set(`${owner}|${dest}`, this.now()); this.#note("destination_added", dest, by, `New destination for ${owner}; payouts to it wait ${Math.round(this.coolOffMs / 3600e3)}h.`); this.#save(); } }
  /** Sentinel (or a person) freezes an owner's payouts. Release needs a different person than whoever placed the hold. */
  holdOwner(owner, reason, by = "sentinel") { this.holds.set(owner, { reason, by, at: this.now() }); this.#note("hold", owner, by, reason); this.#save(); }
  releaseHold(owner, by) {
    const h = this.holds.get(owner);
    if (!by || by === "sentinel") throw new Error("a named person must release a hold");
    if (h && h.by !== "sentinel" && h.by === by) throw new Error(`${by} placed this hold and cannot release it: a different named person must release it.`);
    this.holds.delete(owner); this.#note("hold_released", owner, by, "Hold released by a person independent of the holder."); this.#save();
  }
  /** Plug this into Sentinel's alert callback. */
  onSentinelAlert(a) { if (a?.actor && /^hold_payout/.test(a.action ?? "")) this.holdOwner(a.actor, `Sentinel ${a.rule}: ${a.message ?? ""}`.trim()); }

  request({ id = crypto.randomUUID(), owner, amount, dest, maker }) {
    if (!maker || !owner || !dest) throw new Error("owner, dest and maker are required");
    const kobo = toKobo(amount);
    if (!(kobo > 0)) throw new Error("amount must be positive");
    if (this.payouts.has(id)) return this.payouts.get(id); // idempotent
    const p = { id, owner, amount: kobo, dest, maker, approvals: [], status: "pending_approval", reasons: [], auth: this.approvers ? "proof" : "name" };
    this.payouts.set(id, p); this.#note("requested", id, maker, `${formatNaira(kobo)} to ${dest} for ${owner}`); this.#save();
    return p;
  }
  #blockers(p) {
    const r = [], t = this.now();
    if (this.tripped) r.push(`Velocity breaker tripped (${this.tripped.why}). A named person must run recover().`);
    const h = this.holds.get(p.owner); if (h) r.push(`${p.owner} is on hold: ${h.reason}`);
    const added = this.destinations.get(`${p.owner}|${p.dest}`);
    if (added === undefined) r.push("Destination is not registered for this owner. Register it first, then wait the cooling-off period.");
    else if (t - added < this.coolOffMs) r.push(`Destination is new (cooling-off ends in ${Math.ceil((this.coolOffMs - (t - added)) / 3600e3)}h). Account takeovers change the payout destination first.`);
    const need = p.amount >= this.dualAt ? 2 : 1;
    if (p.approvals.length < need) r.push(`Needs ${need} approval(s) from people other than ${p.maker}; has ${p.approvals.length}.`);
    return r;
  }
  approve(id, checker, proof) {
    const p = this.payouts.get(id); if (!p) throw new Error("unknown payout");
    if (p.status === "released") return p;
    if (p.status === "rejected") throw new Error("payout was rejected");
    if (checker === p.maker) throw new Error("maker cannot approve their own payout");
    if (!checker) throw new Error("approver name required");
    if (this.approvers) {
      const secret = this.approvers[checker];
      if (!secret) throw new Error(`${checker} is not a registered approver`);
      if (!safeEq(proof ?? "", approvalProof(secret, id, checker))) throw new Error("invalid approval proof for " + checker);
    }
    if (!p.approvals.includes(checker)) p.approvals.push(checker);
    this.#note("approved", id, checker, `${p.approvals.length} approval(s)`); this.#save();
    return this.tryRelease(id);
  }
  reject(id, by, reason = "") { const p = this.payouts.get(id); if (!p) throw new Error("unknown payout"); if (p.status === "released") throw new Error("already released"); p.status = "rejected"; this.#note("rejected", id, by, reason); this.#save(); return p; }
  tryRelease(id) {
    const p = this.payouts.get(id);
    if (p.status === "released" || p.status === "rejected") return p;
    // velocity check on this release
    const t = this.now(), recent = this.released.filter((x) => t - x.at < this.velocity.windowMs).reduce((s, x) => s + x.amount, 0);
    if (!this.tripped && recent + p.amount > this.velocity.maxKobo) { this.tripped = { at: t, why: `${formatNaira(recent + p.amount)} would leave within ${Math.round(this.velocity.windowMs / 60000)} minutes` }; this.#note("breaker_tripped", id, "system", this.tripped.why); }
    p.reasons = this.#blockers(p);
    if (p.reasons.length) { p.status = p.approvals.length ? "held" : "pending_approval"; this.#save(); return p; }
    try {
      this.books.post({ id: `payout:${p.id}`, memo: `Payout to ${p.dest}`, ref: p.id, by: p.approvals.join("+"), lines: [{ account: this.payableAccount, amount: p.amount }, { account: this.bankAccount, amount: -p.amount }] });
    } catch (e) { p.status = "held"; p.reasons = [`Books refused the posting: ${e.message}`]; this.#save(); return p; }
    p.status = "released"; this.released.push({ at: t, amount: p.amount }); this.#note("released", id, p.approvals.join("+"), formatNaira(p.amount)); this.#save();
    return p;
  }
  /** Re-evaluate everything held, e.g. after a hold is released. */
  retryHeld() { return [...this.payouts.values()].filter((p) => p.status === "held").map((p) => this.tryRelease(p.id)); }
  recover(by) { if (!by || by === "system" || by === "sentinel") throw new Error("a named person must recover the breaker"); this.tripped = null; this.released = []; this.#note("breaker_recovered", "-", by, "Velocity window cleared by a person."); this.#save(); }
  explain(id) { const p = this.payouts.get(id); return p ? `${p.status.toUpperCase()}: ${p.reasons.length ? p.reasons.join(" ") : "no blockers"}` : "unknown payout"; }
}
