import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/** Deterministic JSON: sorted keys, so the same data always hashes the same. */
export function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
}
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const GENESIS = "0".repeat(64);

/**
 * Append-only, hash-chained log. Each entry commits to the previous one, so editing or deleting any line breaks the chain.
 * A separate "head" file records the latest seq+hash (HMAC-signed when a key is set), which also exposes truncation of the tail.
 * Honest limit: someone who controls this machine AND the key can rewrite both. Copy the head hash somewhere off-box regularly.
 */
export class Ledger {
  constructor({ dir, key } = {}) {
    this.dir = dir;
    this.key = key;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, "ledger.jsonl");
    this.headFile = path.join(dir, "ledger.head.json");
    const last = this.#last();
    this.seq = last?.seq ?? 0;
    this.prev = last?.hash ?? GENESIS;
  }
  #last() {
    if (!fs.existsSync(this.file)) return undefined;
    const lines = fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean);
    if (!lines.length) return undefined;
    try { return JSON.parse(lines.at(-1)); } catch { return undefined; }
  }
  #mac(seq, hash) { return this.key ? crypto.createHmac("sha256", this.key).update(`${seq}:${hash}`).digest("hex") : undefined; }
  append(event, ts = new Date().toISOString()) {
    const seq = this.seq + 1;
    const hash = sha(`${this.prev}\n${canonical({ seq, ts, event })}`);
    const entry = { seq, ts, event, prev: this.prev, hash };
    const fd = fs.openSync(this.file, "a", 0o600);
    try { fs.writeSync(fd, `${JSON.stringify(entry)}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const tmp = `${this.headFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ seq, hash, mac: this.#mac(seq, hash) }), { mode: 0o600 });
    fs.renameSync(tmp, this.headFile);
    this.seq = seq; this.prev = hash;
    return entry;
  }
  readAll() {
    if (!fs.existsSync(this.file)) return [];
    return fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  }
  verify() {
    let prev = GENESIS, n = 0;
    const lines = fs.existsSync(this.file) ? fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean) : [];
    for (const line of lines) {
      let e;
      try { e = JSON.parse(line); } catch { return { ok: false, entries: n, error: `line ${n + 1} is not valid JSON` }; }
      if (e.seq !== n + 1) return { ok: false, entries: n, error: `sequence broken at entry ${n + 1} (found ${e.seq}): a line was removed or inserted` };
      if (e.prev !== prev) return { ok: false, entries: n, error: `chain broken at seq ${e.seq}: previous hash does not match` };
      if (sha(`${e.prev}\n${canonical({ seq: e.seq, ts: e.ts, event: e.event })}`) !== e.hash) return { ok: false, entries: n, error: `entry ${e.seq} was modified: its hash does not match its content` };
      prev = e.hash; n++;
    }
    if (!fs.existsSync(this.headFile)) return { ok: n === 0, entries: n, error: n ? "head file missing: cannot rule out truncation" : undefined, head: prev };
    const head = JSON.parse(fs.readFileSync(this.headFile, "utf8"));
    if (this.key && head.mac !== this.#mac(head.seq, head.hash)) return { ok: false, entries: n, error: "head file signature is invalid: it was altered or signed with another key" };
    if (head.seq !== n || head.hash !== prev) return { ok: false, entries: n, error: `log ends at ${n} but head says ${head.seq}: the tail was removed or replaced` };
    return { ok: true, entries: n, head: prev };
  }
}
