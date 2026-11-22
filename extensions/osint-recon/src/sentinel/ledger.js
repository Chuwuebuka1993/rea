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

const sleep = (ms) => {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
  catch { const t = Date.now() + ms; while (Date.now() < t); }
};

/**
 * Append-only, hash-chained log. Each entry commits to the previous one, so editing or deleting any line breaks the chain.
 * A separate "head" file records the latest seq+hash (HMAC-signed when a key is set), which also exposes truncation of the tail.
 * Honest limit: someone who controls this machine AND the key can rewrite both. Copy the head hash somewhere off-box regularly.
 *
 * Integrity model (P0): the full chain is verified on construction. A ledger that fails verification is never appended to
 * (`corrupt` is set and `append` throws); callers that replay the log must check `verify()`/`corrupt` first. Appends take an
 * inter-process lock and re-read the tail under the lock, so concurrent writers cannot fork the chain. `repair()` truncates
 * at the first invalid entry and re-anchors the head — explicit, reported recovery instead of silent divergence.
 */
export class Ledger {
  constructor({ dir, key, lockTimeoutMs = 5000 } = {}) {
    this.dir = dir;
    this.key = key;
    this.lockTimeoutMs = lockTimeoutMs;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, "ledger.jsonl");
    this.headFile = path.join(dir, "ledger.head.json");
    this.lockFile = path.join(dir, "ledger.lock");
    const v = this.verify();
    this.corrupt = v.ok ? null : v.error;
    const last = this.#last();
    this.seq = last?.seq ?? 0;
    this.prev = last?.hash ?? GENESIS;
  }
  #last() {
    if (!fs.existsSync(this.file)) return undefined;
    const lines = fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean);
    if (!lines.length) return undefined;
    try { return JSON.parse(lines.at(-1)); } catch { return undefined; } // corrupt tail: verify() already reported it in `corrupt`
  }
  #mac(seq, hash) { return this.key ? crypto.createHmac("sha256", this.key).update(`${seq}:${hash}`).digest("hex") : undefined; }
  /** Run fn holding the inter-process lock. Stale locks (holder died) are broken after lockTimeoutMs. */
  #withLock(fn) {
    const deadline = Date.now() + this.lockTimeoutMs;
    for (;;) {
      let fd;
      try { fd = fs.openSync(this.lockFile, "wx", 0o600); }
      catch (e) {
        if (e.code !== "EEXIST") throw e;
        let stale = false;
        try { stale = Date.now() - fs.statSync(this.lockFile).mtimeMs > this.lockTimeoutMs; } catch { stale = false; }
        if (stale) { try { fs.rmSync(this.lockFile); } catch { /* raced with another breaker; loop re-checks */ } continue; }
        if (Date.now() > deadline) throw new Error("could not acquire the ledger lock: another writer is stuck or the clock jumped");
        sleep(15);
        continue;
      }
      try { return fn(); }
      finally { try { fs.closeSync(fd); } catch { /* already closed */ } try { fs.rmSync(this.lockFile); } catch { /* already removed */ } }
    }
  }
  append(event, ts = new Date().toISOString()) {
    if (this.corrupt) throw new Error(`refusing to append: ledger failed verification (${this.corrupt}). Run repair() after investigating, or restore from backup.`);
    return this.#withLock(() => {
      // Re-read the tail under the lock: another process may have appended since this instance was constructed.
      const last = this.#last();
      const prev = last?.hash ?? GENESIS;
      const seq = (last?.seq ?? 0) + 1;
      const hash = sha(`${prev}\n${canonical({ seq, ts, event })}`);
      const entry = { seq, ts, event, prev, hash };
      const fd = fs.openSync(this.file, "a", 0o600);
      try { fs.writeSync(fd, `${JSON.stringify(entry)}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      const tmp = `${this.headFile}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ seq, hash, mac: this.#mac(seq, hash) }), { mode: 0o600 });
      fs.renameSync(tmp, this.headFile);
      this.seq = seq; this.prev = hash;
      return entry;
    });
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
  /**
   * Explicit recovery: truncate the log at the first invalid entry, re-anchor the signed head, and report what was removed.
   * Removing entries is a big deal: the returned report says exactly how many lines were dropped so the loss is visible,
   * never silent. Backup the directory before repairing if you can.
   */
  repair() {
    return this.#withLock(() => {
      const lines = fs.existsSync(this.file) ? fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean) : [];
      let prev = GENESIS, keep = 0;
      for (let i = 0; i < lines.length; i++) {
        let e;
        try { e = JSON.parse(lines[i]); } catch { break; }
        if (e.seq !== i + 1 || e.prev !== prev || sha(`${e.prev}\n${canonical({ seq: e.seq, ts: e.ts, event: e.event })}`) !== e.hash) break;
        prev = e.hash; keep = i + 1;
      }
      const removed = lines.length - keep;
      const tmp = `${this.file}.repair`;
      fs.writeFileSync(tmp, lines.slice(0, keep).map((l) => `${l}\n`).join(""), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
      const seq = keep, hash = keep ? prev : GENESIS;
      const htmp = `${this.headFile}.tmp`;
      fs.writeFileSync(htmp, JSON.stringify({ seq, hash, mac: this.#mac(seq, hash) }), { mode: 0o600 });
      fs.renameSync(htmp, this.headFile);
      this.seq = seq; this.prev = hash;
      const v = this.verify();
      this.corrupt = v.ok ? null : v.error;
      return { removed, entries: keep, ok: v.ok, error: v.error };
    });
  }
}
