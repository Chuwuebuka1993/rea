import crypto from "node:crypto";
import { toKobo, formatNaira } from "./money.js";

/**
 * Payout desk: money leaves only after maker-checker approval, and anything unusual is held with a plain-language reason.
 * Rules: the requester can never approve; amounts >= dualAt need two different approvers; a payout destination must be
 * registered and older than coolOffMs; a velocity breaker trips when too much leaves in a window and stays tripped until
 * a named person recovers it; an account Sentinel flagged is held. When in doubt the money stays put (fail closed).
 */
export class PayoutDesk {
  constructor({ books, bankAccount = "bank:main", payableAccount = "payable:wallets", dualAt = 50_000_00, coolOffMs = 24 * 3600e3, velocity = { windowMs: 3600e3, maxKobo: 500_000_00 }, now = () => Date.now() } = {}) {
    Object.assign(this, { books, bankAccount, payableAccount, dualAt, coolOffMs, velocity, now });
    this.payouts = new Map(); this.destinations = new Map(); this.holds = new Map(); this.released = []; this.tripped = null; this.log = [];
  }
  #note(kind, id, by, text) { this.log.push({ at: new Date(this.now()).toISOString(), kind, id, by, text }); }
  addDestination(owner, dest, by) { if (!this.destinations.has(`${owner}|${dest}`)) { this.destinations.set(`${owner}|${dest}`, this.now()); this.#note("destination_added", dest, by, `New destination for ${owner}; payouts to it wait ${Math.round(this.coolOffMs / 3600e3)}h.`); } }
  /** Sentinel (or a person) freezes an owner's payouts. Release needs a different person than whoever reported nothing: any named human. */
  holdOwner(owner, reason, by = "sentinel") { this.holds.set(owner, { reason, by, at: this.now() }); this.#note("hold", owner, by, reason); }
  releaseHold(owner, by) { if (!by || by === "sentinel") throw new Error("a named person must release a hold"); this.holds.delete(owner); this.#note("hold_released", owner, by, "Hold released by a person."); }
  /** Plug this into Sentinel's alert callback. */
  onSentinelAlert(a) { if (a?.actor && /^hold_payout/.test(a.action ?? "")) this.holdOwner(a.actor, `Sentinel ${a.rule}: ${a.message ?? ""}`.trim()); }

  request({ id = crypto.randomUUID(), owner, amount, dest, maker }) {
    if (!maker || !owner || !dest) throw new Error("owner, dest and maker are required");
    const kobo = toKobo(amount);
    if (!(kobo > 0)) throw new Error("amount must be positive");
    if (this.payouts.has(id)) return this.payouts.get(id); // idempotent
    const p = { id, owner, amount: kobo, dest, maker, approvals: [], status: "pending_approval", reasons: [] };
    this.payouts.set(id, p); this.#note("requested", id, maker, `${formatNaira(kobo)} to ${dest} for ${owner}`);
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
  approve(id, checker) {
    const p = this.payouts.get(id); if (!p) throw new Error("unknown payout");
    if (p.status === "released") return p;
    if (p.status === "rejected") throw new Error("payout was rejected");
    if (checker === p.maker) throw new Error("maker cannot approve their own payout");
    if (!checker) throw new Error("approver name required");
    if (!p.approvals.includes(checker)) p.approvals.push(checker);
    this.#note("approved", id, checker, `${p.approvals.length} approval(s)`);
    return this.tryRelease(id);
  }
  reject(id, by, reason = "") { const p = this.payouts.get(id); if (!p) throw new Error("unknown payout"); if (p.status === "released") throw new Error("already released"); p.status = "rejected"; this.#note("rejected", id, by, reason); return p; }
  tryRelease(id) {
    const p = this.payouts.get(id);
    if (p.status === "released" || p.status === "rejected") return p;
    // velocity check on this release
    const t = this.now(), recent = this.released.filter((x) => t - x.at < this.velocity.windowMs).reduce((s, x) => s + x.amount, 0);
    if (!this.tripped && recent + p.amount > this.velocity.maxKobo) { this.tripped = { at: t, why: `${formatNaira(recent + p.amount)} would leave within ${Math.round(this.velocity.windowMs / 60000)} minutes` }; this.#note("breaker_tripped", id, "system", this.tripped.why); }
    p.reasons = this.#blockers(p);
    if (p.reasons.length) { p.status = p.approvals.length ? "held" : "pending_approval"; return p; }
    try {
      this.books.post({ id: `payout:${p.id}`, memo: `Payout to ${p.dest}`, ref: p.id, by: p.approvals.join("+"), lines: [{ account: this.payableAccount, amount: p.amount }, { account: this.bankAccount, amount: -p.amount }] });
    } catch (e) { p.status = "held"; p.reasons = [`Books refused the posting: ${e.message}`]; return p; }
    p.status = "released"; this.released.push({ at: t, amount: p.amount }); this.#note("released", id, p.approvals.join("+"), formatNaira(p.amount));
    return p;
  }
  /** Re-evaluate everything held, e.g. after a hold is released. */
  retryHeld() { return [...this.payouts.values()].filter((p) => p.status === "held").map((p) => this.tryRelease(p.id)); }
  recover(by) { if (!by || by === "system" || by === "sentinel") throw new Error("a named person must recover the breaker"); this.tripped = null; this.released = []; this.#note("breaker_recovered", "-", by, "Velocity window cleared by a person."); }
  explain(id) { const p = this.payouts.get(id); return p ? `${p.status.toUpperCase()}: ${p.reasons.length ? p.reasons.join(" ") : "no blockers"}` : "unknown payout"; }
}
