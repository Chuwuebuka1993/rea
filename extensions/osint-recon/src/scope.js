import dns from "node:dns";
import fs from "node:fs";
import net from "node:net";
import { UserError, parseHost, parseGithubOwner, parseRepoSlug } from "./validate.js";

/** Raised when a target is outside the declared, authorized scope. */
export class ScopeError extends UserError {
  constructor(message) {
    super(message);
    this.name = "ScopeError";
  }
}

export const SCOPE_HELP =
  "Create an osint-scope.json (see osint-scope.example.json) that records who authorized the testing " +
  "and which domains, CIDR ranges and GitHub orgs/repos are in scope, then set OSINT_SCOPE_FILE to its path.";

const DEFAULT_LIMITS = { max_ports: 100, concurrency: 20, connect_timeout_ms: 2000 };
const HARD_LIMITS = { max_ports: 1024, concurrency: 100, connect_timeout_ms: 10000 };

function strings(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new ScopeError(`scope: "${label}" must be an array of strings`);
  }
  return value.map((v) => v.trim()).filter(Boolean);
}

/** Validate and normalize a raw scope object. */
export function parseScope(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ScopeError("scope file must contain a JSON object");
  const auth = raw.authorization;
  if (!auth || typeof auth.authorized_by !== "string" || !auth.authorized_by.trim()) {
    throw new ScopeError('scope: "authorization.authorized_by" is required (who authorized this testing?)');
  }
  if (typeof auth.date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(auth.date)) {
    throw new ScopeError('scope: "authorization.date" is required as YYYY-MM-DD');
  }
  if (auth.expires !== undefined) {
    if (typeof auth.expires !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(auth.expires)) {
      throw new ScopeError('scope: "authorization.expires" must be YYYY-MM-DD');
    }
    if (auth.expires < new Date().toISOString().slice(0, 10)) {
      throw new ScopeError(`scope: authorization expired on ${auth.expires}`);
    }
  }
  const domains = strings(raw.domains, "domains").map((d) => parseHost(d.replace(/^\*\./, "")).value);
  const hosts = strings(raw.hosts, "hosts").map((h) => parseHost(h).value);
  const cidrs = strings(raw.cidrs, "cidrs").map(parseCidr);
  const orgs = strings(raw.github?.orgs, "github.orgs").map((o) => parseGithubOwner(o).toLowerCase());
  const repos = strings(raw.github?.repos, "github.repos").map((r) => {
    const { owner, repo } = parseRepoSlug(r);
    return `${owner}/${repo}`.toLowerCase();
  });
  if (!domains.length && !hosts.length && !cidrs.length && !orgs.length && !repos.length) {
    throw new ScopeError("scope is empty: list at least one domain, host, cidr, GitHub org or repo");
  }
  const limits = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(DEFAULT_LIMITS)) {
    const v = raw.limits?.[key];
    if (v !== undefined) {
      if (!Number.isInteger(v) || v < 1) throw new ScopeError(`scope: limits.${key} must be a positive integer`);
      limits[key] = Math.min(v, HARD_LIMITS[key]);
    }
  }
  return {
    authorization: { authorized_by: auth.authorized_by.trim(), date: auth.date, expires: auth.expires, statement: auth.statement },
    domains,
    hosts,
    cidrs,
    github: { orgs, repos },
    limits,
  };
}

export function loadScope(path) {
  if (!path) throw new ScopeError(`No scope file configured. ${SCOPE_HELP}`);
  let text;
  try {
    text = fs.readFileSync(path, "utf8");
  } catch {
    throw new ScopeError(`Cannot read scope file "${path}". ${SCOPE_HELP}`);
  }
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ScopeError(`Scope file "${path}" is not valid JSON`);
  }
  return parseScope(json);
}

/* ---------- IP helpers ---------- */

function v4ToInt(ip) {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

export function parseCidr(text) {
  const [addr, bitsRaw] = text.split("/");
  if (net.isIPv4(addr)) {
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new ScopeError(`invalid CIDR "${text}"`);
    return { text, family: 4, base: v4ToInt(addr), bits };
  }
  if (net.isIPv6(addr) && bitsRaw === undefined) return { text, family: 6, exact: addr.toLowerCase() };
  throw new ScopeError(`invalid CIDR "${text}" (IPv4 CIDRs or exact IPv6 addresses only)`);
}

function inV4(ipInt, base, bits) {
  if (bits === 0) return true;
  const size = 2 ** (32 - bits);
  return Math.floor(ipInt / size) === Math.floor(base / size);
}

function mappedV4(ip) {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1] : undefined;
}

export function ipInCidr(ip, cidr) {
  const v4 = net.isIPv4(ip) ? ip : mappedV4(ip);
  if (v4) return cidr.family === 4 && inV4(v4ToInt(v4), cidr.base, cidr.bits);
  return cidr.family === 6 && cidr.exact === ip.toLowerCase();
}

const NON_PUBLIC_V4 = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([a, b]) => ({ base: v4ToInt(a), bits: b }));

/** True for loopback, private, link-local, metadata, multicast and other non-public addresses. */
export function isNonPublicIp(ip) {
  const v4 = net.isIPv4(ip) ? ip : mappedV4(ip);
  if (v4) {
    const n = v4ToInt(v4);
    return NON_PUBLIC_V4.some((r) => inV4(n, r.base, r.bits));
  }
  const lower = ip.toLowerCase();
  return lower === "::" || lower === "::1" || /^fe[89ab]/.test(lower) || /^f[cd]/.test(lower) || lower.startsWith("ff");
}

/* ---------- scope checks ---------- */

function explicitIp(scope, ip) {
  return scope.hosts.includes(ip.toLowerCase()) || scope.cidrs.some((c) => ipInCidr(ip, c));
}

/**
 * Is this parsed host (from parseHost) in scope? IP literals must be listed in hosts/cidrs.
 * Domains match a scoped domain or any of its subdomains, or an exact scoped host.
 */
export function hostInScope(scope, host) {
  if (host.kind === "ip") return explicitIp(scope, host.value);
  if (scope.hosts.includes(host.value)) return true;
  return scope.domains.some((d) => host.value === d || host.value.endsWith(`.${d}`));
}

export function assertHostInScope(scope, rawHost) {
  const host = parseHost(rawHost);
  if (!hostInScope(scope, host)) {
    throw new ScopeError(
      `"${host.value}" is not in the authorized scope. Add it to the scope file only if you are authorized to test it.`,
    );
  }
  return host;
}

export function assertGithubInScope(scope, owner, repo) {
  const o = owner.toLowerCase();
  const full = repo ? `${o}/${repo.toLowerCase()}` : undefined;
  if (scope.github.orgs.includes(o) || (full && scope.github.repos.includes(full))) return;
  throw new ScopeError(
    `GitHub ${full ? `repo "${owner}/${repo}"` : `owner "${owner}"`} is not in the authorized scope (github.orgs / github.repos).`,
  );
}

/** Whether a resolved address may be contacted for a target already confirmed in scope. */
export function ipAllowed(scope, ip) {
  if (explicitIp(scope, ip)) return true;
  return !isNonPublicIp(ip);
}

/**
 * A `lookup` function for net/tls/http that resolves the name itself and drops any address that
 * is non-public and not explicitly scoped. Validating at connect time closes the DNS-rebinding gap.
 */
export function guardedLookup(scope) {
  return (hostname, options, callback) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err);
      const allowed = addresses.filter((a) => ipAllowed(scope, a.address));
      if (allowed.length === 0) {
        return callback(new ScopeError(`"${hostname}" resolves only to non-public or out-of-scope addresses`));
      }
      if (options?.all) return callback(null, allowed);
      return callback(null, allowed[0].address, allowed[0].family);
    });
  };
}
