import crypto from "node:crypto";
import { UserError } from "../validate.js";

/**
 * Pwned Passwords range lookup (k-anonymity). Only the first 5 characters of the SHA-1 hash leave this machine;
 * the password and the full hash never do. Add-Padding hides the number of matches from network observers.
 * Never pass real passwords through an AI chat: use the CLI (`guardian pwcheck`), which reads them from a hidden prompt.
 */
export async function pwnedCount(password, { fetchImpl = fetch } = {}) {
  if (typeof password !== "string" || !password) throw new UserError("password must be a non-empty string");
  // guardian-scan: allow weak-hash (the breach-check API is defined on SHA-1 prefixes; not used to store passwords)
  const sha1 = crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const res = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "add-padding": "true", "user-agent": "rea-guardian/0.1" },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new UserError(`Pwned Passwords API returned HTTP ${res.status}`);
  return parseRange(await res.text(), suffix);
}

export function parseRange(text, suffix) {
  for (const line of text.split(/\r?\n/)) {
    const [s, n] = line.trim().split(":");
    if (s && s.toUpperCase() === suffix) return Number(n) || 0;
  }
  return 0;
}

export function passwordVerdict(count) {
  if (count > 0) return { safe: false, message: `Found ${count.toLocaleString("en")} times in known breaches. Never use it, and change it everywhere you used it.` };
  return { safe: true, message: "Not found in known breaches. That does not make it strong: still make it long and unique." };
}
