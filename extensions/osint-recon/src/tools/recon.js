import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { assertHostInScope, guardedLookup } from "../scope.js";
import { UserError, parsePorts } from "../validate.js";

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
const HOST = { type: "string", maxLength: 253, description: "Hostname or IP address (must be in the scope file)" };

const SERVICE_NAMES = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
  135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
  465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
  1521: "oracle", 2375: "docker (unencrypted)", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
  5432: "postgresql", 5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
  9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
};
/** Services that should rarely be exposed to the internet. */
const RISKY_EXPOSED = new Set([23, 111, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017]);

export function createReconTools({ getScope }) {
  const recon = {};

  /* ---------------- DNS ---------------- */
  const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"];
  recon.dns = {
    name: "recon_dns",
    description:
      "Passive DNS lookup (dig-style) for an in-scope domain: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA. " +
      "Also flags missing SPF/DMARC on mail-enabled domains.",
    annotations: READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["host"],
      properties: { host: HOST, types: { type: "array", maxItems: 8, items: { type: "string", enum: DNS_TYPES } } },
    },
    async handler({ host, types }) {
      const target = assertHostInScope(getScope(), host);
      if (target.kind === "ip") throw new UserError("recon_dns needs a domain name, not an IP address");
      const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
      const wanted = types?.length ? types : DNS_TYPES;
      const records = {};
      for (const type of wanted) records[type] = await resolveType(resolver, target.value, type);
      const findings = [];
      const txt = (records.TXT ?? []).map((r) => (Array.isArray(r) ? r.join("") : r));
      if ((records.MX ?? []).length > 0 || txt.length > 0) {
        if (wanted.includes("TXT") && !txt.some((t) => t.toLowerCase().startsWith("v=spf1"))) {
          findings.push(finding("low", "No SPF record", `${target.value} has mail or TXT records but no SPF policy.`, target.value));
        }
        if (wanted.includes("TXT")) {
          const dmarc = await resolveType(resolver, `_dmarc.${target.value}`, "TXT");
          if (!dmarc.some((r) => String(Array.isArray(r) ? r.join("") : r).toLowerCase().startsWith("v=dmarc1"))) {
            findings.push(finding("low", "No DMARC record", `_dmarc.${target.value} has no DMARC policy.`, target.value));
          }
        }
      }
      return {
        summary: `DNS records for ${target.value}: ${Object.entries(records).filter(([, v]) => v.length).map(([k, v]) => `${k}=${v.length}`).join(", ") || "none found"}`,
        data: { host: target.value, records, limitations: ["Answers come from the system resolver and may be cached or split-horizon."] },
        findings,
      };
    },
  };

  /* ---------------- RDAP / whois ---------------- */
  recon.whois = {
    name: "recon_whois",
    description:
      "Registration data via RDAP (the structured successor of whois) for an in-scope domain or IP. " +
      "Returns registrar, status, key dates and nameservers; personal contact data is deliberately omitted.",
    annotations: READ_ONLY,
    inputSchema: { type: "object", required: ["host"], properties: { host: HOST } },
    async handler({ host }) {
      const target = assertHostInScope(getScope(), host);
      const url = `https://rdap.org/${target.kind === "ip" ? "ip" : "domain"}/${encodeURIComponent(target.value)}`;
      const res = await fetch(url, { headers: { accept: "application/rdap+json" }, signal: AbortSignal.timeout(15000), redirect: "follow" });
      if (!res.ok) throw new UserError(`RDAP lookup failed with HTTP ${res.status}`);
      const body = await res.json();
      const data = summarizeRdap(body, target.value);
      return { summary: `RDAP for ${target.value}: ${data.status.join(", ") || "no status reported"}`, data };
    },
  };

  /* ---------------- TLS ---------------- */
  recon.tls = {
    name: "recon_tls",
    description: "Inspect the TLS endpoint of an in-scope host: protocol, cipher, certificate subject/issuer/SANs, expiry and trust.",
    annotations: READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["host"],
      properties: { host: HOST, port: { type: "integer", minimum: 1, maximum: 65535 } },
    },
    async handler({ host, port = 443 }) {
      const scope = getScope();
      const target = assertHostInScope(scope, host);
      const info = await tlsProbe(scope, target, port);
      const findings = [];
      if (!info.trusted) findings.push(finding("medium", "Certificate not trusted", `${info.authorizationError ?? "validation failed"} on ${target.value}:${port}`, target.value));
      if (info.daysRemaining !== undefined && info.daysRemaining < 0) findings.push(finding("high", "Certificate expired", `Expired ${-info.daysRemaining} days ago.`, target.value));
      else if (info.daysRemaining !== undefined && info.daysRemaining < 21) findings.push(finding("medium", "Certificate expires soon", `${info.daysRemaining} days remaining.`, target.value));
      if (["TLSv1", "TLSv1.1"].includes(info.protocol)) findings.push(finding("medium", "Legacy TLS protocol negotiated", info.protocol, target.value));
      return {
        summary: `${target.value}:${port} negotiated ${info.protocol}, certificate ${info.trusted ? "trusted" : "NOT trusted"}, ${info.daysRemaining} days remaining`,
        data: { host: target.value, port, ...info },
        findings,
      };
    },
  };

  /* ---------------- HTTP headers ---------------- */
  recon.http = {
    name: "recon_http_headers",
    description:
      "Fetch response headers from an in-scope web server (no body is downloaded, redirects are not followed) and audit " +
      "security headers, server banner and cookie flags.",
    annotations: READ_ONLY,
    inputSchema: {
      type: "object",
      required: ["host"],
      properties: {
        host: HOST,
        port: { type: "integer", minimum: 1, maximum: 65535 },
        scheme: { type: "string", enum: ["https", "http"] },
        path: { type: "string", maxLength: 512 },
      },
    },
    async handler({ host, port, scheme = "https", path = "/" }) {
      const scope = getScope();
      const target = assertHostInScope(scope, host);
      if (!path.startsWith("/")) throw new UserError('path must start with "/"');
      const res = await headProbe(scope, target, { port, scheme, path });
      const audit = auditHeaders(res.headers, scheme);
      return {
        summary: `${scheme}://${target.value}${path} -> HTTP ${res.status}; ${audit.findings.length} header issue(s)`,
        data: { url: res.url, status: res.status, location: res.headers.location, server: res.headers.server, headers: res.headers, missing: audit.missing },
        findings: audit.findings.map((f) => ({ ...f, target: target.value })),
      };
    },
  };

  /* ---------------- TCP connect check ---------------- */
  recon.ports = {
    name: "recon_port_scan",
    description:
      "Bounded TCP connect scan of an in-scope host (no banner grabbing, no exploitation). Defaults to ~80 common ports; " +
      "limits come from the scope file. Use nmap yourself for deeper service detection.",
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    inputSchema: {
      type: "object",
      required: ["host"],
      properties: {
        host: HOST,
        ports: { type: ["string", "array"], description: 'Ports as "top", "80,443,8000-8010" or an array of integers', maxItems: 1024, items: { type: "integer" } },
      },
    },
    async handler({ host, ports }) {
      const scope = getScope();
      const target = assertHostInScope(scope, host);
      const list = parsePorts(ports, scope.limits.max_ports);
      const results = await connectScan(scope, target, list);
      const open = results.filter((r) => r.state === "open");
      const findings = open.filter((r) => RISKY_EXPOSED.has(r.port)).map((r) =>
        finding("medium", `Sensitive service reachable: ${r.port}/${r.service}`, `${target.value}:${r.port} accepts TCP connections.`, target.value));
      return {
        summary: `${target.value}: ${open.length} open of ${list.length} ports checked`,
        data: {
          host: target.value, checked: list.length, open,
          closed: results.filter((r) => r.state === "closed").length,
          filtered: results.filter((r) => r.state === "filtered").length,
          limitations: ["TCP connect only; filtered means no answer before the timeout, not necessarily a firewall.", "No service or version detection was performed."],
        },
        findings,
      };
    },
  };

  return Object.values(recon);
}

/* ======================= helpers (exported for tests) ======================= */

export function finding(severity, title, detail, target) {
  return { severity, title, detail, target };
}

async function resolveType(resolver, name, type) {
  try {
    const out = await resolver.resolve(name, type);
    return Array.isArray(out) ? out : [out];
  } catch (err) {
    if (["ENODATA", "ENOTFOUND", "ENOENT", "ESERVFAIL", "EBADRESP"].includes(err.code)) return [];
    throw new UserError(`DNS ${type} lookup for ${name} failed: ${err.code ?? err.message}`);
  }
}

export function summarizeRdap(body, query) {
  const events = (body.events ?? []).map((e) => ({ action: e.eventAction, date: e.eventDate }));
  const registrar = (body.entities ?? []).find((e) => (e.roles ?? []).includes("registrar"));
  const registrarName = registrar?.vcardArray?.[1]?.find((p) => p[0] === "fn")?.[3];
  return {
    query,
    handle: body.handle,
    name: body.ldhName ?? body.name,
    status: body.status ?? [],
    registrar: registrarName,
    events,
    nameservers: (body.nameservers ?? []).map((n) => n.ldhName).filter(Boolean),
    country: body.country,
    limitations: ["Registrant and technical contact data is omitted on purpose."],
  };
}

export function tlsProbe(scope, target, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: target.value, port, servername: target.kind === "domain" ? target.value : undefined,
      rejectUnauthorized: false, lookup: guardedLookup(scope), timeout: 8000,
    });
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const validTo = cert?.valid_to ? new Date(cert.valid_to) : undefined;
      const out = {
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name,
        trusted: socket.authorized,
        authorizationError: socket.authorized ? undefined : String(socket.authorizationError),
        subject: cert?.subject?.CN,
        issuer: cert?.issuer?.O ?? cert?.issuer?.CN,
        altNames: cert?.subjectaltname?.split(", ").map((s) => s.replace(/^DNS:/, "")).slice(0, 50),
        validFrom: cert?.valid_from,
        validTo: cert?.valid_to,
        daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : undefined,
        fingerprint256: cert?.fingerprint256,
      };
      socket.end();
      resolve(out);
    });
    socket.once("timeout", () => { socket.destroy(); reject(new UserError(`TLS handshake with ${target.value}:${port} timed out`)); });
    socket.once("error", (err) => reject(err instanceof UserError ? err : new UserError(`TLS connection failed: ${err.code ?? err.message}`)));
  });
}

export function headProbe(scope, target, { port, scheme, path }) {
  const mod = scheme === "http" ? http : https;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        host: target.value, port: port ?? (scheme === "http" ? 80 : 443), path, method: "GET",
        servername: target.kind === "domain" ? target.value : undefined, rejectUnauthorized: false,
        lookup: guardedLookup(scope), timeout: 10000,
        headers: { "user-agent": "rea-osint-recon/0.1", accept: "*/*", host: target.value },
      },
      (res) => {
        const headers = {};
        for (const [k, v] of Object.entries(res.headers)) headers[k] = v;
        resolve({ status: res.statusCode, headers, url: `${scheme}://${target.value}${port ? `:${port}` : ""}${path}` });
        res.destroy();
      },
    );
    req.once("timeout", () => req.destroy(new UserError("HTTP request timed out")));
    req.once("error", (err) => reject(err instanceof UserError ? err : new UserError(`HTTP request failed: ${err.code ?? err.message}`)));
    req.end();
  });
}

const SECURITY_HEADERS = [
  ["strict-transport-security", "medium", "Missing HSTS", "https"],
  ["content-security-policy", "low", "Missing Content-Security-Policy"],
  ["x-content-type-options", "low", "Missing X-Content-Type-Options"],
  ["referrer-policy", "low", "Missing Referrer-Policy"],
];

export function auditHeaders(headers, scheme) {
  const findings = [];
  const missing = [];
  for (const [name, severity, title, only] of SECURITY_HEADERS) {
    if (only && only !== scheme) continue;
    if (headers[name] === undefined) {
      missing.push(name);
      findings.push(finding(severity, title, `Response did not include "${name}".`));
    }
  }
  if (headers["x-frame-options"] === undefined && !/frame-ancestors/i.test(String(headers["content-security-policy"] ?? ""))) {
    missing.push("x-frame-options");
    findings.push(finding("low", "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set."));
  }
  const server = String(headers.server ?? "");
  if (/\d+\.\d+/.test(server)) findings.push(finding("info", "Server banner discloses a version", server));
  if (headers["x-powered-by"]) findings.push(finding("info", "X-Powered-By discloses technology", String(headers["x-powered-by"])));
  for (const cookie of [].concat(headers["set-cookie"] ?? [])) {
    const name = cookie.split("=")[0];
    const flags = [];
    if (scheme === "https" && !/;\s*secure/i.test(cookie)) flags.push("Secure");
    if (!/;\s*httponly/i.test(cookie)) flags.push("HttpOnly");
    if (!/;\s*samesite=/i.test(cookie)) flags.push("SameSite");
    if (flags.length) findings.push(finding("low", `Cookie "${name}" missing ${flags.join(", ")}`, "Cookie attributes weaken session protection."));
  }
  return { findings, missing };
}

export async function connectScan(scope, target, ports) {
  const { concurrency, connect_timeout_ms: timeout } = scope.limits;
  const lookup = guardedLookup(scope);
  const results = [];
  let next = 0;
  async function worker() {
    while (next < ports.length) {
      const port = ports[next++];
      results.push(await probePort(target.value, port, timeout, lookup));
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  return results.sort((a, b) => a.port - b.port);
}

function probePort(host, port, timeout, lookup) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port, lookup, timeout });
    const done = (state) => { socket.destroy(); resolve({ port, state, service: SERVICE_NAMES[port] }); };
    socket.once("connect", () => done("open"));
    socket.once("timeout", () => done("filtered"));
    socket.once("error", (err) => {
      // A scope violation is not a network result; surface it instead of reporting "filtered".
      if (err instanceof UserError) { socket.destroy(); reject(err); return; }
      done(err.code === "ECONNREFUSED" ? "closed" : "filtered");
    });
  });
}
