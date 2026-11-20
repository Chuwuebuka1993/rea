import fs from "node:fs";
import path from "node:path";
import { UserError } from "../validate.js";

// The registry stores no secrets: only facts about how an account is protected.
const TWOFA = { none: 0, sms: 15, totp: 28, passkey: 35, hardware: 35 };
const SECRET_LIKE = /(pass(word)?|secret|token|seed|pin|otp|code_value)/i;
const ALLOWED = new Set([
  "id", "platform", "label", "email_account", "twofa", "backup_codes_saved", "recovery_email",
  "recovery_phone", "passkey_or_key", "password_manager", "unique_password", "last_reviewed", "owners", "critical", "notes",
]);

export function validateAccount(raw) {
  if (!raw || typeof raw !== "object") throw new UserError("account must be an object");
  for (const k of Object.keys(raw)) {
    if (SECRET_LIKE.test(k) && !ALLOWED.has(k)) throw new UserError(`field "${k}" looks like a secret: the registry never stores secrets`);
    if (!ALLOWED.has(k)) throw new UserError(`unknown field "${k}"`);
  }
  const id = String(raw.id ?? "").trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(id)) throw new UserError("id must be 1-64 letters, digits, . _ -");
  const twofa = raw.twofa ?? "none";
  if (!(twofa in TWOFA)) throw new UserError(`twofa must be one of ${Object.keys(TWOFA).join(", ")}`);
  const bool = (v) => (v === undefined ? false : Boolean(v));
  return {
    id,
    platform: String(raw.platform ?? "generic").toLowerCase(),
    label: String(raw.label ?? id).slice(0, 80),
    email_account: raw.email_account ? String(raw.email_account) : undefined,
    twofa,
    backup_codes_saved: bool(raw.backup_codes_saved),
    recovery_email: bool(raw.recovery_email),
    recovery_phone: bool(raw.recovery_phone),
    passkey_or_key: bool(raw.passkey_or_key),
    password_manager: bool(raw.password_manager),
    unique_password: bool(raw.unique_password),
    owners: Number.isInteger(raw.owners) ? raw.owners : 1,
    critical: bool(raw.critical),
    last_reviewed: raw.last_reviewed ? String(raw.last_reviewed) : undefined,
    notes: raw.notes ? String(raw.notes).slice(0, 200) : undefined,
  };
}

export function loadRegistry(file) {
  if (!fs.existsSync(file)) return { accounts: [] };
  let data;
  try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new UserError(`${file} is not valid JSON`); }
  if (!Array.isArray(data.accounts)) throw new UserError(`${file} must contain an "accounts" array`);
  return { accounts: data.accounts.map(validateAccount) };
}

export function saveRegistry(file, registry) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ accounts: registry.accounts.map(validateAccount) }, null, 2), { mode: 0o600 });
}

export function upsertAccount(registry, raw) {
  const acc = validateAccount(raw);
  const i = registry.accounts.findIndex((a) => a.id === acc.id);
  if (i >= 0) registry.accounts[i] = acc; else registry.accounts.push(acc);
  return acc;
}

const DAY = 86400000;

/** Score one account 0-100 for "can we get back in, and is it hard to break in". Returns score, grade and ordered actions. */
export function scoreAccount(acc, byId = new Map(), now = Date.now()) {
  let score = TWOFA[acc.twofa];
  const actions = [];
  const add = (cond, pts, action) => { if (cond) score += pts; else actions.push(action); };
  if (acc.twofa === "none") actions.push("Turn on two-factor authentication. Prefer an authenticator app or passkey over SMS.");
  if (acc.twofa === "sms") actions.push("Move from SMS to an authenticator app or passkey: SMS codes can be stolen by SIM swap.");
  add(acc.backup_codes_saved, 15, "Save backup/recovery codes offline (paper or an offline file). They are what rescues you when 2FA is lost.");
  add(acc.recovery_email, 10, "Add a recovery email you control.");
  add(acc.recovery_phone, 7, "Add a recovery phone number, and tell your carrier to add a SIM-swap PIN.");
  add(acc.passkey_or_key, 8, "Add a passkey or hardware security key as a second route in.");
  add(acc.unique_password && acc.password_manager, 10, "Use a unique password from a password manager.");
  const stale = !acc.last_reviewed || now - Date.parse(acc.last_reviewed) > 180 * DAY;
  if (!stale) score += 5; else actions.push("Review recovery settings now: last review is missing or older than 6 months.");
  if (acc.critical && acc.owners < 2) { score -= 5; actions.push("Add a second trusted owner/admin with a different 2FA method, so one hack cannot lock everyone out."); }
  const parent = acc.email_account ? byId.get(acc.email_account) : undefined;
  if (acc.email_account && !parent) actions.push(`Recovery email account "${acc.email_account}" is not in the registry: add it, because it can reset this one.`);
  score = Math.max(0, Math.min(100, score));
  return { id: acc.id, label: acc.label, platform: acc.platform, score, grade: grade(score), actions };
}

function grade(s) { return s >= 85 ? "strong" : s >= 65 ? "fair" : s >= 40 ? "weak" : "critical"; }

/** Score all accounts and apply email-dependency caps: an account is no safer than the email that can reset it. */
export function assessRegistry(registry, now = Date.now()) {
  const byId = new Map(registry.accounts.map((a) => [a.id, a]));
  const raw = new Map(registry.accounts.map((a) => [a.id, scoreAccount(a, byId, now)]));
  const results = [];
  for (const a of registry.accounts) {
    const r = { ...raw.get(a.id) };
    const parent = a.email_account ? raw.get(a.email_account) : undefined;
    if (parent && parent.score < r.score) {
      r.capped_by = parent.id;
      r.score = parent.score;
      r.grade = grade(r.score);
      r.actions.unshift(`Fix "${parent.label}" first: it can reset this account and is only rated ${parent.grade}.`);
    }
    results.push(r);
  }
  results.sort((x, y) => x.score - y.score);
  const overall = results.length ? Math.round(results.reduce((s, r) => s + r.score, 0) / results.length) : 0;
  return { overall, accounts: results };
}
