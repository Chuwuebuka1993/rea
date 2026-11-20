// Maps Shield findings to NIST CSF 2.0 categories (identifiers from NIST CSWP 29) and MITRE ATT&CK techniques.
export const CSF = {
  supply_chain: { csf: "GV.SC", function: "Govern", attack: "T1195 Supply Chain Compromise" },
  asset_vuln: { csf: "ID.RA", function: "Identify", attack: "T1190 Exploit Public-Facing Application" },
  weak_crypto: { csf: "PR.DS", function: "Protect", attack: "T1600 Weaken Encryption" },
  quantum: { csf: "PR.DS", function: "Protect", attack: "Harvest-now-decrypt-later (no ATT&CK ID)" },
  secrets: { csf: "PR.AA", function: "Protect", attack: "T1552 Unsecured Credentials" },
  tls_validation: { csf: "PR.DS", function: "Protect", attack: "T1557 Adversary-in-the-Middle" },
};
export const tag = (finding, kind) => ({ ...finding, framework: CSF[kind] });

export function summarizeByFunction(findings) {
  const out = {};
  for (const f of findings) {
    const fn = f.framework?.function ?? "Unmapped";
    out[fn] ??= { high: 0, medium: 0, low: 0, info: 0 };
    out[fn][f.severity] = (out[fn][f.severity] ?? 0) + 1;
  }
  return out;
}
