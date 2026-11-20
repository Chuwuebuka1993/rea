import fs from "node:fs";
import { UserError } from "../validate.js";

const API = "https://api.github.com";
export const REVOCABLE = new Set(["ssh", "gpg", "deploy", "hook"]);

/** State file: {approved: snapshot|null, pending: {key: {first_seen, alert}}, log: []}. Holds no secrets. */
export function loadState(file) {
  if (!fs.existsSync(file)) return { approved: null, pending: {}, log: [] };
  try { return { approved: null, pending: {}, log: [], ...JSON.parse(fs.readFileSync(file, "utf8")) }; } catch { throw new UserError(`${file} is not valid JSON`); }
}
export function saveState(file, state) {
  state.log = state.log.slice(-500);
  fs.writeFileSync(file, JSON.stringify(state, null, 2), { mode: 0o600 });
}

/** Approve everything currently present, or one pending key. Approving is the ONLY way an item becomes trusted. */
export function approve(state, snapshot, which) {
  if (which === "all") { state.approved = snapshot; state.pending = {}; return "all current items approved"; }
  const p = state.pending[which];
  if (!p) throw new UserError(`nothing pending with key "${which}"`);
  const a = (state.approved ??= { ssh_keys: [], gpg_keys: [], emails: [], deploy_keys: [], webhooks: [] });
  const r = p.alert.ref;
  const push = (list, item) => { (a[list] ??= []).push(item); };
  if (r.type === "ssh") push("ssh_keys", { id: r.id, title: r.title, fingerprint: r.fingerprint });
  else if (r.type === "gpg") push("gpg_keys", { id: r.id, key_id: r.key_id });
  else if (r.type === "email") push("emails", r.value);
  else if (r.type === "deploy") push("deploy_keys", { repo: r.repo, id: r.id });
  else if (r.type === "hook") push("webhooks", { repo: r.repo, id: r.id });
  delete state.pending[which];
  return `approved ${which}`;
}

export async function revoke(ref, { token, fetchImpl = fetch }) {
  const path = ref.type === "ssh" ? `/user/keys/${ref.id}` : ref.type === "gpg" ? `/user/gpg_keys/${ref.id}`
    : ref.type === "deploy" ? `/repos/${ref.repo}/keys/${ref.id}` : ref.type === "hook" ? `/repos/${ref.repo}/hooks/${ref.id}` : null;
  if (!path) throw new UserError(`${ref.type} cannot be revoked automatically`);
  const res = await fetchImpl(`${API}${path}`, { method: "DELETE", headers: { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", authorization: `Bearer ${token}`, "user-agent": "rea-guardian/0.1" }, signal: AbortSignal.timeout(20000) });
  if (res.status !== 204 && res.status !== 404) throw new UserError(`revoke failed: HTTP ${res.status} (token needs admin:public_key / admin:gpg_key / admin:repo_hook / repo)`);
  return res.status === 404 ? "already gone" : "revoked";
}

/**
 * One response cycle. Policy:
 *  - No approved baseline yet: alert only (an intruder already present must not be auto-trusted).
 *  - New unapproved item: alert at once and start a grace timer so you can approve something you added yourself.
 *  - After grace, with enforce on: revoke it. Dry-run otherwise.
 *  - Circuit breaker: if more than maxRevocations are due in one cycle, revoke nothing and escalate to manual review.
 * Returns {events, state}. Never changes passwords or deletes repositories.
 */
export async function respond({ alerts, state, now = Date.now(), graceMs = 10 * 60000, enforce = false, maxRevocations = 5, token, fetchImpl = fetch }) {
  const events = [];
  const ev = (level, text, key) => { const e = { at: new Date(now).toISOString(), level, text, key }; events.push(e); state.log.push(e); };
  if (!state.approved) {
    for (const a of alerts) ev("warn", `${a.title}: ${a.detail} (no approved baseline yet: run "approve all" after you review the list)`, a.key);
    return { events, state };
  }
  const live = new Set(alerts.map((a) => a.key));
  for (const k of Object.keys(state.pending)) if (!live.has(k)) { delete state.pending[k]; ev("info", `${k} is gone`, k); }
  const due = [];
  for (const a of alerts) {
    const known = state.pending[a.key];
    if (!known) {
      state.pending[a.key] = { first_seen: now, alert: a };
      ev("alert", `UNAPPROVED ${a.title}: ${a.detail}. Approve within ${Math.round(graceMs / 60000)} min or it is ${enforce ? "revoked" : "flagged (dry run)"}.`, a.key);
    } else if (now - known.first_seen >= graceMs && REVOCABLE.has(a.ref.type)) due.push(a);
    else if (!REVOCABLE.has(a.ref.type) && !known.escalated) { known.escalated = true; ev("alert", `${a.title} cannot be removed automatically: remove it in GitHub settings`, a.key); }
  }
  if (due.length > maxRevocations) {
    ev("critical", `${due.length} unapproved items are due: too many for automatic action, which may mean a mass compromise. Review manually and follow the recovery playbook.`);
    return { events, state };
  }
  for (const a of due) {
    if (!enforce) { ev("warn", `would revoke ${a.key} (dry run: start watch with --enforce)`, a.key); continue; }
    try {
      const r = await revoke(a.ref, { token, fetchImpl });
      delete state.pending[a.key];
      ev("action", `${r}: ${a.title} ${a.key}. Now change your GitHub password, reset 2FA, and check the security log.`, a.key);
    } catch (e) { ev("error", `${a.key}: ${e.message}`, a.key); }
  }
  return { events, state };
}
