import { Ledger } from "../sentinel/ledger.js";
import { toKobo } from "./money.js";

/**
 * Double-entry books on the tamper-evident ledger. Amounts: debit positive, credit negative, integer kobo.
 * Rules enforced: every journal sums to zero; ids are idempotent (a retry never double-posts); nothing is edited or
 * deleted, a mistake is fixed by a reversal; accounts flagged nonNegative can never go below zero.
 */
export class Books {
  constructor({ dir, key } = {}) {
    this.ledger = new Ledger({ dir, key });
    this.accounts = new Map(); this.journals = new Map(); this.balances = new Map(); this.reversed = new Set();
    for (const e of this.ledger.readAll()) this.#apply(e.event);
  }
  #apply(ev) {
    if (ev.type === "account") this.accounts.set(ev.id, { kind: ev.kind, nonNegative: !!ev.nonNegative });
    else if (ev.type === "journal") {
      this.journals.set(ev.id, ev);
      for (const l of ev.lines) this.balances.set(l.account, (this.balances.get(l.account) ?? 0) + l.amount);
      if (ev.reverses) this.reversed.add(ev.reverses);
    }
  }
  openAccount(id, kind, { nonNegative = false } = {}) {
    if (!/^[a-z0-9:_-]{2,64}$/.test(id)) throw new Error("account id: lowercase letters, digits, : _ -");
    if (!["asset", "liability", "income", "expense", "equity"].includes(kind)) throw new Error("bad account kind");
    if (this.accounts.has(id)) return false;
    const ev = { type: "account", id, kind, nonNegative };
    this.ledger.append(ev); this.#apply(ev); return true;
  }
  balance(id) { return this.balances.get(id) ?? 0; }
  /** @returns {{posted:boolean, duplicate?:boolean, journal:object}} */
  post({ id, memo = "", lines, ref, by, reverses }) {
    if (!id) throw new Error("journal id (idempotency key) is required");
    if (this.journals.has(id)) return { posted: false, duplicate: true, journal: this.journals.get(id) };
    if (!Array.isArray(lines) || lines.length < 2) throw new Error("a journal needs at least two lines");
    const norm = lines.map((l) => {
      if (!this.accounts.has(l.account)) throw new Error(`unknown account ${l.account}`);
      const amount = toKobo(l.amount);
      if (amount === 0) throw new Error("zero-amount line");
      return { account: l.account, amount };
    });
    if (norm.reduce((s, l) => s + l.amount, 0) !== 0) throw new Error("journal does not balance: debits must equal credits");
    const delta = new Map();
    for (const l of norm) delta.set(l.account, (delta.get(l.account) ?? 0) + l.amount);
    for (const [acc, d] of delta) {
      const a = this.accounts.get(acc);
      const after = this.balance(acc) + d;
      // Asset accounts hold debit balances; liability/income/equity hold credit (negative) balances.
      if (a.nonNegative && (a.kind === "asset" || a.kind === "expense" ? after < 0 : after > 0)) throw new Error(`${acc} cannot go below zero`);
    }
    const ev = { type: "journal", id, memo, lines: norm, ref, by, reverses };
    this.ledger.append(ev); this.#apply(ev);
    return { posted: true, journal: ev };
  }
  reverse(id, { by, reason = "" } = {}) {
    const j = this.journals.get(id);
    if (!j) throw new Error(`no journal ${id}`);
    if (j.reverses) throw new Error("a reversal cannot itself be reversed; post a new journal");
    if (this.reversed.has(id)) throw new Error(`journal ${id} is already reversed`);
    return this.post({ id: `rev:${id}`, memo: `Reversal of ${id}. ${reason}`.trim(), by, reverses: id, lines: j.lines.map((l) => ({ account: l.account, amount: -l.amount })) });
  }
  trialBalance() {
    const rows = [...this.balances].map(([account, balance]) => ({ account, kind: this.accounts.get(account)?.kind, balance }));
    const total = rows.reduce((s, r) => s + r.balance, 0);
    return { rows, total, balanced: total === 0 };
  }
  verify() { return this.ledger.verify(); }
}
