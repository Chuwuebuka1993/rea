import crypto from "node:crypto";
import { canaryLabel } from "./canary.js";
import { sign } from "./server.js";

/**
 * Drop-in client for your own apps. report() never throws and never blocks your request path for long:
 * if Sentinel is down your app keeps working (fail-open for monitoring, not for security decisions).
 */
export class SentinelClient {
  constructor({ url, app, secret, canaries = [], fetchImpl = fetch, timeoutMs = 1500, onAlert }) {
    Object.assign(this, { url: url.replace(/\/$/, ""), app, secret, canaries, fetchImpl, timeoutMs, onAlert });
  }
  async report(event) {
    try {
      const body = JSON.stringify(event), ts = Date.now(), nonce = crypto.randomBytes(12).toString("hex");
      const res = await this.fetchImpl(`${this.url}/events`, {
        method: "POST", body, signal: AbortSignal.timeout(this.timeoutMs),
        headers: { "content-type": "application/json", "x-sentinel-app": this.app, "x-sentinel-ts": String(ts), "x-sentinel-nonce": nonce, "x-sentinel-sig": sign(this.secret, ts, nonce, body) },
      });
      const out = await res.json();
      for (const a of out.alerts ?? []) this.onAlert?.(a);
      return out;
    } catch (e) { return { ok: false, error: e.name }; }
  }
  /** Call this wherever your app receives a credential it could not validate. A hit means a trap value was used. */
  async checkCredential(value, ctx = {}) {
    const label = canaryLabel(value, this.canaries);
    if (!label) return false;
    await this.report({ type: "canary_touch", resource: label, ...ctx });
    return true;
  }
}
