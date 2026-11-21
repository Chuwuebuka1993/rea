const MIN = 60000;
const ADMIN_TYPES = new Set(["role_change", "api_key_created", "payout_change", "config_change", "admin_action", "data_export", "mfa_disabled"]);

/**
 * Stateful detector. Feed it ledger entries in order; it returns alerts with recommended actions.
 * The app decides what to do with an action (Sentinel never reaches into your app or your accounts).
 */
export class Detector {
  constructor(opts = {}) {
    this.o = { failWindowMin: 10, failLimit: 5, sprayLimit: 10, riskWindowH: 24, exportRows: 1000, offHours: [23, 5], utcOffsetH: 1, ...opts };
    this.fails = new Map();      // app|actor -> [ts]
    this.ipFails = new Map();    // app|ip -> Map(actor->ts)
    this.devices = new Map();    // app|actor -> Set(device)
    this.risky = new Map();      // app|actor -> {type, ts}
  }
  ingest(entry) {
    const e = entry.event, t = Date.parse(entry.ts), alerts = [];
    const app = e.app ?? "default", ak = `${app}|${e.actor ?? ""}`;
    const alert = (severity, rule, message, action) => alerts.push({ severity, rule, app, actor: e.actor, ip: e.ip, seq: entry.seq, message, action });
    const win = this.o.failWindowMin * MIN;
    const prune = (arr) => { while (arr.length && t - arr[0] > win) arr.shift(); return arr; };

    if (e.type === "canary_touch") alert("critical", "canary", `A trap credential${e.resource ? ` "${e.resource}"` : ""} was used from ${e.ip ?? "unknown ip"}. Nobody legitimate has this value: treat as an intruder inside or a leaked secret.`, "revoke_all_sessions_and_rotate_secrets");

    if (e.type === "login_failure") {
      const list = prune(this.fails.get(ak) ?? []); list.push(t); this.fails.set(ak, list);
      if (list.length === this.o.failLimit) alert("high", "brute_force", `${list.length} failed logins for ${e.actor} in ${this.o.failWindowMin} min.`, "lock_user_temporarily");
      if (e.ip) {
        const k = `${app}|${e.ip}`, m = this.ipFails.get(k) ?? new Map();
        for (const [a, ts] of m) if (t - ts > win) m.delete(a);
        m.set(e.actor ?? "?", t); this.ipFails.set(k, m);
        if (m.size === this.o.sprayLimit) alert("high", "credential_stuffing", `${m.size} different accounts failed from ${e.ip} in ${this.o.failWindowMin} min: password spraying or credential stuffing.`, "block_ip");
      }
    }
    if (e.type === "login_success") {
      const list = prune(this.fails.get(ak) ?? []);
      if (list.length >= this.o.failLimit) alert("critical", "takeover_suspected", `${e.actor} logged in right after ${list.length} failures: the password may have been guessed.`, "force_reauth_with_mfa");
      this.fails.set(ak, []);
      if (e.device) { const s = this.devices.get(ak) ?? new Set(); s.add(e.device); this.devices.set(ak, s); }
    }
    if (e.type === "password_reset" || e.type === "mfa_disabled") this.risky.set(ak, { type: e.type, ts: t });
    if (ADMIN_TYPES.has(e.type)) {
      const known = this.devices.get(ak);
      if (e.device && known && !known.has(e.device)) alert("high", "new_device_admin", `${e.type} by ${e.actor} from a device never seen logging in.`, "require_reauth_and_notify_owner");
      else if (!known && e.actor) alert("medium", "no_login_seen", `${e.type} by ${e.actor} with no recorded login: session may predate monitoring or be forged.`, "review");
      if (e.type === "role_change" && /^(admin|owner|root)$/i.test(String(e.meta?.new_role ?? ""))) alert("medium", "privilege_grant", `${e.actor} granted ${e.meta.new_role} to ${e.target ?? "someone"}.`, "confirm_with_owner");
      const hour = (new Date(t).getUTCHours() + this.o.utcOffsetH + 24) % 24, [from, to] = this.o.offHours;
      if (hour >= from || hour < to) alert("low", "off_hours_admin", `${e.type} by ${e.actor} at ${String(hour).padStart(2, "0")}:00 local.`, "review");
    }
    if (e.type === "payout_change") {
      const r = this.risky.get(ak);
      if (r && t - r.ts <= this.o.riskWindowH * 60 * MIN) alert("critical", "payout_after_reset", `Payout details changed within ${this.o.riskWindowH}h of a ${r.type} for ${e.actor}: the classic account-takeover cash-out.`, "hold_payout_and_confirm_out_of_band");
    }
    if (e.type === "data_export" && Number(e.meta?.rows) >= this.o.exportRows) alert("medium", "bulk_export", `${e.actor} exported ${e.meta.rows} rows.`, "review");
    return alerts;
  }
}
