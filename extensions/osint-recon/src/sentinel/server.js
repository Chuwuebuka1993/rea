import crypto from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { Detector } from "./detect.js";
import { validateEvent } from "./events.js";
import { Ledger } from "./ledger.js";

const MAX_BODY = 16 * 1024, SKEW_MS = 5 * 60000;

export function sign(secret, ts, nonce, body) {
  return crypto.createHmac("sha256", secret).update(`${ts}.${nonce}.${body}`).digest("hex");
}
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

/**
 * Collector. Apps POST signed events; it verifies, logs to the ledger, runs detectors and returns alerts with recommended actions.
 * apps: {appName: secret}. Binds to loopback by default: put it behind TLS if it must be reachable from other hosts.
 */
export function createCollector({ dir, apps, ledgerKey, notify = () => {}, now = () => Date.now(), detectorOpts, ratePerMin = 600 }) {
  const ledger = new Ledger({ dir, key: ledgerKey });
  const detector = new Detector(detectorOpts);
  for (const e of ledger.readAll()) detector.ingest(e); // rebuild windows after a restart
  const alertsFile = path.join(dir, "alerts.jsonl");
  const nonces = new Map();
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
    for (const [n, t] of nonces) if (now() - t > SKEW_MS) nonces.delete(n);
    const nk = `${app}|${nonce}`;
    if (nonces.has(nk)) return fail(409, "replayed request");
    nonces.set(nk, now());
    let event;
    try { event = validateEvent(JSON.parse(body)); } catch (e) { return fail(400, e.name === "UserError" ? e.message : "invalid JSON"); }
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
