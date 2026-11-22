import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { Detector } from "./detect.js";
import { validateEvent } from "./events.js";
import { Ledger } from "./ledger.js";

const MAX_BODY = 16 * 1024, SKEW_MS = 5 * 60000;
// Nonces older than this can never be accepted again (the timestamp skew check would reject them first),
// so the durable nonce store only needs to cover this window plus a safety margin.
const NONCE_TTL_MS = 30 * 60000;

export function sign(secret, ts, nonce, body) {
  return crypto.createHmac("sha256", secret).update(`${ts}.${nonce}.${body}`).digest("hex");
}
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

/** Durable, append-only nonce record so a collector restart cannot reopen the replay window. */
class NonceStore {
  constructor(file, now) { this.file = file; this.now = now; this.seen = new Map(); this.#load(); }
  #load() {
    if (!fs.existsSync(this.file)) return;
    const t = this.now();
    for (const line of fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean)) {
      try { const { k, at } = JSON.parse(line); if (typeof k === "string" && Number.isFinite(at) && t - at <= NONCE_TTL_MS) this.seen.set(k, at); } catch { /* skip malformed line */ }
    }
    this.#compact();
  }
  #compact() {
    // Rewrite without expired entries once the file is mostly garbage; keeps restarts fast and the file bounded.
    const t = this.now();
    let lines = 0;
    try { lines = fs.readFileSync(this.file, "utf8").split("\n").filter(Boolean).length; } catch { /* missing is fine */ }
    if (lines > 0 && lines > this.seen.size * 2 + 100) {
      const tmp = `${this.file}.tmp`;
      fs.writeFileSync(tmp, [...this.seen].map(([k, at]) => `${JSON.stringify({ k, at })}\n`).join(""), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
    }
    for (const [k, at] of this.seen) if (t - at > NONCE_TTL_MS) this.seen.delete(k);
  }
  has(k) { return this.seen.has(k); }
  add(k) {
    const at = this.now();
    this.seen.set(k, at);
    const fd = fs.openSync(this.file, "a", 0o600);
    try { fs.writeSync(fd, `${JSON.stringify({ k, at })}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    if (this.seen.size % 512 === 0) this.#compact();
  }
}

/**
 * Collector. Apps POST signed events; it verifies, logs to the ledger, runs detectors and returns alerts with recommended actions.
 * apps: {appName: secret}. Binds to loopback by default: put it behind TLS if it must be reachable from other hosts.
 *
 * Integrity model (P0): the ledger chain is verified before any replay; if verification fails the collector refuses to start
 * rather than rebuilding detector state from a tampered history. Replay protection is durable across restarts via NonceStore.
 */
export function createCollector({ dir, apps, ledgerKey, notify = () => {}, now = () => Date.now(), detectorOpts, ratePerMin = 600 }) {
  const ledger = new Ledger({ dir, key: ledgerKey });
  const integrity = ledger.verify();
  if (!integrity.ok) throw new Error(`refusing to start: ledger failed verification (${integrity.error}). Fix or repair the log first; starting on a tampered history would hide the tampering.`);
  const detector = new Detector(detectorOpts);
  for (const e of ledger.readAll()) detector.ingest(e); // rebuild windows after a restart (chain already verified above)
  const alertsFile = path.join(dir, "alerts.jsonl");
  const nonces = new NonceStore(path.join(dir, "nonces.jsonl"), now);
  const hits = new Map();

  function emit(a) {
    fs.appendFileSync(alertsFile, `${JSON.stringify({ at: new Date(now()).toISOString(), ...a })}\n`, { mode: 0o600 });
    try { notify(a); } catch { /* alert sinks must not break ingestion */ }
  }

  const badAuth = new Map();
  function handle(headers, body, remote = "local") {
    const app = headers["x-sentinel-app"], ts = Number(headers["x-sentinel-ts"]), nonce = headers["x-sentinel-nonce"], sig = headers["x-sentinel-sig"];
    const secret = apps[app];
    const fail = (status, error) => ({ status, body: { ok: false, error } });
    const minute = Math.floor(now() / 60000);
    // Unauthenticated traffic is limited per source and never consumes an app's own quota.
    const authFail = () => {
      const k = `${remote}|${minute}`;
      for (const x of badAuth.keys()) if (!x.endsWith(`|${minute}`)) badAuth.delete(x);
      badAuth.set(k, (badAuth.get(k) ?? 0) + 1);
      return fail(badAuth.get(k) > 60 ? 429 : 401, badAuth.get(k) > 60 ? "rate limit" : "unauthorized");
    };
    if ((badAuth.get(`${remote}|${minute}`) ?? 0) > 60) return fail(429, "rate limit");
    if (!secret || !nonce || !sig || !Number.isFinite(ts)) return authFail();
    if (!safeEq(sig, sign(secret, ts, nonce, body))) return authFail();
    const rk = `${app}|${minute}`;
    hits.set(rk, (hits.get(rk) ?? 0) + 1);
    for (const k of hits.keys()) if (!k.endsWith(`|${minute}`)) hits.delete(k);
    if (hits.get(rk) > ratePerMin) return fail(429, "rate limit");
    if (Math.abs(now() - ts) > SKEW_MS) return fail(401, "stale timestamp");
    const nk = `${app}|${nonce}`;
    if (nonces.has(nk)) return fail(409, "replayed request");
    let event;
    try { event = validateEvent(JSON.parse(body)); } catch (e) { return fail(400, e.name === "UserError" ? e.message : "invalid JSON"); }
    nonces.add(nk); // only persist the nonce once the request is fully valid; a 400 body can be retried with a fixed body
    event.app = app;
    const entry = ledger.append(event, new Date(now()).toISOString());
    const alerts = detector.ingest(entry);
    alerts.forEach(emit);
    return { status: 202, body: { ok: true, seq: entry.seq, alerts: alerts.map(({ severity, rule, message, action }) => ({ severity, rule, message, action })) } };
  }

  const server = http.createServer((req, res) => {
    const send = (r) => { res.writeHead(r.status, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(r.body)); };
    if (req.method === "GET" && req.url === "/health") return send({ status: 200, body: { ok: true } });
    if (req.method !== "POST" || req.url !== "/events") return send({ status: 404, body: { ok: false, error: "not found" } });
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { send({ status: 413, body: { ok: false, error: "too large" } }); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { if (size <= MAX_BODY) send(handle(req.headers, Buffer.concat(chunks).toString("utf8"), req.socket.remoteAddress)); });
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000;
  return { server, ledger, handle, listen: (port = 7070, host = "127.0.0.1") => new Promise((r) => server.listen(port, host, () => r(server.address()))), close: () => new Promise((r) => server.close(r)) };
}
