const SEVERITY_ORDER = ["high", "medium", "low", "info"];

/** In-memory findings store for the current server session. */
export function createFindingsStore() {
  const items = [];
  return {
    add(tool, target, findings) {
      for (const f of findings ?? []) {
        items.push({ ...f, tool, target: f.target ?? target, at: new Date().toISOString() });
      }
    },
    all: () => [...items],
    clear: () => { items.length = 0; },
    counts() {
      return Object.fromEntries(SEVERITY_ORDER.map((s) => [s, items.filter((f) => f.severity === s).length]));
    },
  };
}

export function renderMarkdown(items, { title = "Recon report", authorization } = {}) {
  const lines = [`# ${title}`, ""];
  lines.push(`Generated: ${new Date().toISOString()}`);
  if (authorization) lines.push(`Authorized by: ${authorization.authorized_by} (${authorization.date})`);
  lines.push("", `Findings: ${items.length}`, "");
  const sorted = [...items].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  for (const sev of SEVERITY_ORDER) {
    const group = sorted.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push(`## ${sev[0].toUpperCase()}${sev.slice(1)} (${group.length})`, "");
    for (const f of group) {
      lines.push(`- **${f.title}** — \`${f.target ?? "n/a"}\` (${f.tool})`, `  ${f.detail ?? ""}`);
    }
    lines.push("");
  }
  lines.push("---", "Findings are tool observations, not confirmed vulnerabilities. Verify before acting.");
  return lines.join("\n");
}
