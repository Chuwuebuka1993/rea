import fs from "node:fs";
import path from "node:path";

/**
 * Map of well-known Kali Linux tools to what this server offers. `covered_by` names a tool in this
 * server; null means "use the real tool yourself". Exploitation frameworks are listed for orientation
 * only and are intentionally not wrapped.
 */
export const KALI_CATALOG = [
  { tool: "dig", category: "dns", purpose: "DNS queries", covered_by: "recon_dns" },
  { tool: "dnsrecon", category: "dns", purpose: "DNS enumeration", covered_by: "recon_dns" },
  { tool: "whois", category: "registration", purpose: "Domain/IP registration data", covered_by: "recon_whois" },
  { tool: "nmap", category: "scanning", purpose: "Port and service scanning", covered_by: "recon_port_scan", note: "Connect scan only; run nmap for service/version detection." },
  { tool: "masscan", category: "scanning", purpose: "High-speed port scanning", covered_by: null },
  { tool: "sslscan", category: "tls", purpose: "TLS configuration check", covered_by: "recon_tls" },
  { tool: "sslyze", category: "tls", purpose: "TLS configuration analysis", covered_by: "recon_tls" },
  { tool: "curl", category: "web", purpose: "HTTP requests", covered_by: "recon_http_headers" },
  { tool: "nikto", category: "web", purpose: "Web server misconfiguration scanning", covered_by: "recon_http_headers", note: "Headers/cookies only." },
  { tool: "whatweb", category: "web", purpose: "Web technology fingerprinting", covered_by: "recon_http_headers" },
  { tool: "gobuster", category: "web", purpose: "Directory/DNS brute forcing", covered_by: null },
  { tool: "sqlmap", category: "web", purpose: "SQL injection testing", covered_by: null },
  { tool: "burpsuite", category: "web", purpose: "Intercepting web proxy", covered_by: null },
  { tool: "theharvester", category: "osint", purpose: "Email/subdomain OSINT", covered_by: "recon_dns", note: "DNS part only; no personal-data harvesting." },
  { tool: "recon-ng", category: "osint", purpose: "OSINT framework", covered_by: null },
  { tool: "maltego", category: "osint", purpose: "Link analysis", covered_by: null },
  { tool: "spiderfoot", category: "osint", purpose: "Automated OSINT", covered_by: null },
  { tool: "trufflehog", category: "github-osint", purpose: "Secret scanning in repos", covered_by: "github_exposure_scan" },
  { tool: "gitleaks", category: "github-osint", purpose: "Secret scanning in repos", covered_by: "github_exposure_scan" },
  { tool: "gh", category: "github-osint", purpose: "GitHub CLI", covered_by: "github_org_overview" },
  { tool: "wireshark", category: "traffic", purpose: "Packet analysis", covered_by: null, note: "REA's pcap tools cover capture analysis." },
  { tool: "tcpdump", category: "traffic", purpose: "Packet capture", covered_by: null },
  { tool: "ghidra", category: "reverse-engineering", purpose: "Disassembler/decompiler", covered_by: null, note: "Use REA's native analysis tools." },
  { tool: "radare2", category: "reverse-engineering", purpose: "Reverse engineering framework", covered_by: null, note: "Use REA's native analysis tools." },
  { tool: "binwalk", category: "reverse-engineering", purpose: "Firmware analysis", covered_by: null, note: "REA's firmware tools cover this." },
  { tool: "apktool", category: "reverse-engineering", purpose: "APK decoding", covered_by: null, note: "REA's Android tools cover this." },
  { tool: "jadx", category: "reverse-engineering", purpose: "Android decompiler", covered_by: null, note: "REA's Android tools cover this." },
  { tool: "metasploit-framework", category: "exploitation", purpose: "Exploitation framework", covered_by: null, note: "Not wrapped by design." },
  { tool: "hydra", category: "credentials", purpose: "Online password guessing", covered_by: null, note: "Not wrapped by design." },
  { tool: "john", category: "credentials", purpose: "Offline password auditing", covered_by: null, note: "Not wrapped by design." },
  { tool: "aircrack-ng", category: "wireless", purpose: "Wi-Fi security auditing", covered_by: null, note: "Not wrapped by design." },
];

/** Return the catalog annotated with whether each executable is on PATH. */
export function annotateInstalled(catalog, pathVar = process.env.PATH ?? "") {
  const dirs = pathVar.split(path.delimiter).filter(Boolean);
  return catalog.map((entry) => ({ ...entry, installed: dirs.some((d) => isExecutable(path.join(d, entry.tool))) }));
}

function isExecutable(file) {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}
