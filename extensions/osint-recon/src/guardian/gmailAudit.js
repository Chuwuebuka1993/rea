// Gmail takeover audit: the classic persistence tricks are a forwarding address/auto-forward, a filter that forwards or hides
// security mail, and a delegate. Reads Gmail settings with an OAuth access token you create yourself (env GUARDIAN_GMAIL_TOKEN,
// scope gmail.readonly to audit; gmail.settings.basic only if you want filter deletion). Tokens never go in chat or files.
const API = "https://gmail.googleapis.com/gmail/v1/users/me/settings";

async function get(path, token, fetchImpl) {
  const res = await fetchImpl(`${API}/${path}`, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15000) });
  if (res.status === 401 || res.status === 403) throw new Error(`Gmail refused ${path} (${res.status}): token expired or missing scope`);
  if (!res.ok) throw new Error(`Gmail ${path} failed (${res.status})`);
  return res.json();
}

export async function auditGmail({ token, fetchImpl = fetch } = {}) {
  if (!token) throw new Error("set GUARDIAN_GMAIL_TOKEN (OAuth access token, gmail.readonly)");
  const [filters, fwd, auto, deleg] = await Promise.all(["filters", "forwardingAddresses", "autoForwarding", "delegates"].map((p) => get(p, token, fetchImpl)));
  const snapshot = {
    filters: (filters.filter ?? []).map((f) => ({ id: f.id, from: f.criteria?.from, subject: f.criteria?.subject, forwardTo: f.action?.forwardTo, add: f.action?.addLabelIds ?? [], remove: f.action?.removeLabelIds ?? [] })),
    forwarding: (fwd.forwardingAddresses ?? []).map((a) => ({ email: a.forwardingEmail, status: a.verificationStatus })),
    auto_forward: auto.enabled ? { to: auto.emailAddress, disposition: auto.disposition } : null,
    delegates: (deleg.delegates ?? []).map((d) => ({ email: d.delegateEmail, status: d.verificationStatus })),
  };
  const findings = [];
  const add = (severity, title, detail, key, ref) => findings.push({ severity, title, detail, key, ref });
  if (snapshot.auto_forward) add("high", "Auto-forwarding is ON", `All new mail is copied to ${snapshot.auto_forward.to}. If you did not set this, it is a takeover tell.`, `autofwd:${snapshot.auto_forward.to}`, { type: "autofwd" });
  for (const a of snapshot.forwarding) add("medium", "Forwarding address on the account", `${a.email} (${a.status})`, `fwd:${a.email}`, { type: "fwd", email: a.email });
  for (const d of snapshot.delegates) add("high", "Delegate can read and send your mail", `${d.email} (${d.status})`, `delegate:${d.email}`, { type: "delegate", email: d.email });
  for (const f of snapshot.filters) {
    const hides = f.remove.includes("INBOX") || f.add.includes("TRASH");
    if (f.forwardTo) add("high", "Filter forwards mail elsewhere", `to ${f.forwardTo} (from: ${f.from ?? "any"}, subject: ${f.subject ?? "any"})`, `filter:${f.id}`, { type: "filter", id: f.id });
    else if (hides) add("medium", "Filter hides or deletes mail", `from: ${f.from ?? "any"}, subject: ${f.subject ?? "any"}. Attackers hide security alerts this way.`, `filter:${f.id}`, { type: "filter", id: f.id });
  }
  return { snapshot, findings, summary: `Gmail audit: ${findings.filter((f) => f.severity === "high").length} high, ${findings.filter((f) => f.severity === "medium").length} medium` };
}

/** Findings whose key is not in the approved list of keys. */
export function newGmailFindings(findings, approvedKeys = []) {
  const ok = new Set(approvedKeys);
  return findings.filter((f) => !ok.has(f.key));
}

/** Deletes one filter (needs gmail.settings.basic). The only automatic change offered: it is reversible by re-creating the filter and never touches mail. */
export async function deleteFilter(id, { token, fetchImpl = fetch }) {
  const res = await fetchImpl(`${API}/filters/${encodeURIComponent(id)}`, { method: "DELETE", headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15000) });
  if (!res.ok && res.status !== 404) throw new Error(`could not delete filter (${res.status}): token needs gmail.settings.basic`);
  return true;
}
