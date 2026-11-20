import crypto from "node:crypto";
import { UserError } from "../validate.js";

const API = "https://api.github.com";
const DAY = 86400000;

export function sshFingerprint(publicKey) {
  const b64 = String(publicKey).trim().split(/\s+/)[1];
  if (!b64) return "unknown";
  return `SHA256:${crypto.createHash("sha256").update(Buffer.from(b64, "base64")).digest("base64").replace(/=+$/, "")}`;
}

/**
 * Read-only audit of YOUR OWN GitHub account using a token you supply (env GUARDIAN_GITHUB_TOKEN).
 * Needs a classic token with read:user, user:email, read:public_key, read:gpg_key (and repo/admin:repo_hook to inspect webhooks).
 * Returns a snapshot (for diffing later) and findings. Never modifies anything.
 */
export async function auditGithub({ token, fetchImpl = fetch, now = Date.now(), maxRepos = 30 } = {}) {
  if (!token) throw new UserError("Set GUARDIAN_GITHUB_TOKEN to a token for your own account (read-only scopes). Never paste it into a chat.");
  let scopes = "";
  async function api(p, { optional = false } = {}) {
    const res = await fetchImpl(`${API}${p}`, {
      headers: { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", authorization: `Bearer ${token}`, "user-agent": "rea-guardian/0.1" },
      signal: AbortSignal.timeout(20000),
    });
    scopes = res.headers?.get?.("x-oauth-scopes") ?? scopes;
    if (res.status === 401) throw new UserError("GitHub rejected the token (401). It may be expired or revoked.");
    if ((res.status === 403 || res.status === 404) && optional) return null;
    if (!res.ok) throw new UserError(`GitHub API error ${res.status} on ${p}`);
    return res.json();
  }

  const findings = [];
  const f = (severity, title, detail) => findings.push({ severity, title, detail });
  const user = await api("/user");
  const keys = (await api("/user/keys?per_page=100", { optional: true })) ?? [];
  const gpg = (await api("/user/gpg_keys?per_page=100", { optional: true })) ?? [];
  const emails = (await api("/user/emails?per_page=100", { optional: true })) ?? [];
  const repos = (await api(`/user/repos?affiliation=owner&per_page=${Math.min(maxRepos, 100)}&sort=pushed`, { optional: true })) ?? [];

  if (user.two_factor_authentication === false) f("high", "Two-factor authentication is OFF", "Turn it on and save the recovery codes.");
  if (!keys.length && !gpg.length) f("info", "No SSH or GPG keys", "Nothing to review.");
  for (const k of keys) {
    const age = k.created_at ? now - Date.parse(k.created_at) : Infinity;
    if (age < 7 * DAY) f("medium", "SSH key added in the last 7 days", `"${k.title}" ${sshFingerprint(k.key)}. If you did not add it, remove it and treat the account as compromised.`);
    if (age > 730 * DAY) f("low", "SSH key older than 2 years", `"${k.title}" ${sshFingerprint(k.key)}. Rotate if the device is gone.`);
  }
  for (const e of emails) {
    if (!e.verified) f("medium", "Unverified email address on account", e.email);
    if (e.visibility === "public") f("low", "Email address is public", `${e.email} is shown on your profile, which helps phishing.`);
  }

  const deploy = [];
  const hooks = [];
  for (const r of repos.slice(0, maxRepos)) {
    const full = r.full_name;
    const dk = await api(`/repos/${full}/keys?per_page=100`, { optional: true });
    for (const k of dk ?? []) {
      deploy.push({ repo: full, id: k.id, title: k.title, read_only: k.read_only });
      if (!k.read_only) f("medium", "Deploy key with WRITE access", `${full}: "${k.title}". Keep only if a service you trust needs it.`);
    }
    const hk = await api(`/repos/${full}/hooks?per_page=100`, { optional: true });
    for (const h of hk ?? []) {
      const url = h.config?.url ?? "";
      hooks.push({ repo: full, id: h.id, host: safeHost(url) });
      if (url.startsWith("http://")) f("medium", "Webhook sends data over plain HTTP", `${full}: ${safeHost(url)}`);
      else f("info", "Webhook present", `${full} sends events to ${safeHost(url)}. Make sure you recognize this host.`);
    }
  }
  if (/\b(delete_repo|admin:org|workflow|write:packages)\b/.test(scopes)) f("low", "This token is broader than an audit needs", `Scopes: ${scopes}. Create a narrower token for Guardian.`);

  const snapshot = {
    at: new Date(now).toISOString(),
    login: user.login,
    ssh_keys: keys.map((k) => ({ id: k.id, title: k.title, fingerprint: sshFingerprint(k.key) })),
    gpg_keys: gpg.map((k) => ({ id: k.id, key_id: k.key_id })),
    emails: emails.map((e) => e.email),
    deploy_keys: deploy,
    webhooks: hooks,
  };
  return {
    summary: `${user.login}: ${keys.length} SSH key(s), ${gpg.length} GPG key(s), ${deploy.length} deploy key(s), ${hooks.length} webhook(s) across ${repos.length} repo(s) examined`,
    snapshot,
    findings,
    limits: [
      "Cannot list personal access tokens, authorized OAuth apps or the security log through the public API: open github.com/settings/security-log and /settings/applications and review them by hand.",
      "Webhooks and deploy keys are only visible on repos where the token has admin rights.",
    ],
  };
}

function safeHost(url) { try { return new URL(url).host; } catch { return "unparseable-url"; } }

/** Compare a new snapshot with a saved baseline and raise an alert for anything new. */
export function diffSnapshots(oldS, newS) {
  const alerts = [];
  const added = (list, key, label, sev = "high") => {
    const before = new Set((oldS[list] ?? []).map((x) => x[key] ?? x));
    for (const x of newS[list] ?? []) if (!before.has(x[key] ?? x)) alerts.push({ severity: sev, title: `New ${label}`, detail: typeof x === "string" ? x : JSON.stringify(x) });
  };
  added("ssh_keys", "fingerprint", "SSH key");
  added("gpg_keys", "key_id", "GPG key");
  added("emails", undefined, "email address");
  added("deploy_keys", "id", "deploy key", "medium");
  added("webhooks", "id", "webhook", "medium");
  return alerts;
}
