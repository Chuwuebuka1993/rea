import { UserError } from "../validate.js";

export const EVENT_TYPES = new Set([
  "login_success", "login_failure", "logout", "password_reset", "mfa_disabled", "mfa_enabled",
  "role_change", "api_key_created", "api_key_used", "config_change", "payout_change", "data_export",
  "admin_action", "session_revoked", "canary_touch",
]);
const SECRET_KEY = /(pass(word)?|secret|token|authorization|cookie|otp|pin|card|cvv|private)/i;
const SAFE_KEY = /^[a-z][a-z0-9_]{0,39}$/;

/** Validate and minimise an incoming event. Secrets must never reach the log, so secret-looking keys are rejected, not stored. */
export function validateEvent(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new UserError("event must be an object");
  const type = String(raw.type ?? "");
  if (!EVENT_TYPES.has(type)) throw new UserError(`unknown event type "${type}"`);
  const out = { type };
  for (const f of ["actor", "target", "ip", "device", "result", "resource"]) {
    if (raw[f] === undefined) continue;
    const v = String(raw[f]);
    if (v.length > 128) throw new UserError(`${f} is too long`);
    out[f] = v;
  }
  if (raw.meta !== undefined) {
    if (typeof raw.meta !== "object" || raw.meta === null || Array.isArray(raw.meta)) throw new UserError("meta must be an object");
    const keys = Object.keys(raw.meta);
    if (keys.length > 20) throw new UserError("meta has too many keys");
    out.meta = {};
    for (const k of keys) {
      if (!SAFE_KEY.test(k)) throw new UserError(`meta key "${k}" is not allowed`);
      if (SECRET_KEY.test(k)) throw new UserError(`meta key "${k}" looks like a secret: send an identifier, never the secret`);
      const v = raw.meta[k];
      if (!["string", "number", "boolean"].includes(typeof v)) throw new UserError(`meta.${k} must be a string, number or boolean`);
      out.meta[k] = typeof v === "string" ? v.slice(0, 200) : v;
    }
  }
  return out;
}
