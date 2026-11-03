import net from "node:net";

/** Error whose message is safe and useful to show to the caller. */
export class UserError extends Error {
  constructor(message) {
    super(message);
    this.name = "UserError";
  }
}

const HOST_RE =
  /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** Parse a hostname or IP literal. Returns {kind:'ip'|'domain', value, family?}. */
export function parseHost(raw) {
  if (typeof raw !== "string") throw new UserError("host must be a string");
  let value = raw.trim().toLowerCase();
  if (value.endsWith(".")) value = value.slice(0, -1);
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const family = net.isIP(value);
  if (family) return { kind: "ip", value, family };
  if (!HOST_RE.test(value)) throw new UserError(`"${raw}" is not a valid hostname or IP address`);
  return { kind: "domain", value };
}

export const TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161, 389, 443, 445, 465,
  514, 515, 543, 548, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181,
  2375, 2376, 3000, 3128, 3306, 3389, 3690, 4443, 4444, 5000, 5060, 5432, 5601, 5672, 5900, 5984,
  5985, 5986, 6379, 6443, 7001, 7077, 8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9042,
  9090, 9092, 9200, 9300, 9418, 10000, 11211, 15672, 27017, 27018, 50000,
];

/**
 * Parse a port spec: an array of integers, "top", or a string like "80,443,8000-8010".
 * Result is a sorted, de-duplicated array. Throws UserError when invalid or above `max`.
 */
export function parsePorts(spec, max) {
  let ports = [];
  if (spec === undefined || spec === "top") {
    ports = [...TOP_PORTS];
  } else if (Array.isArray(spec)) {
    ports = spec.map((p) => Number(p));
  } else if (typeof spec === "string") {
    for (const part of spec.split(",")) {
      const t = part.trim();
      if (!t) continue;
      const m = /^(\d+)(?:-(\d+))?$/.exec(t);
      if (!m) throw new UserError(`invalid port expression "${t}"`);
      const lo = Number(m[1]);
      const hi = m[2] === undefined ? lo : Number(m[2]);
      if (hi < lo) throw new UserError(`invalid port range "${t}"`);
      if (hi - lo + 1 > max) throw new UserError(`port range "${t}" exceeds the limit of ${max}`);
      for (let p = lo; p <= hi; p++) ports.push(p);
    }
  } else {
    throw new UserError("ports must be an array, a string, or 'top'");
  }
  for (const p of ports) {
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new UserError(`invalid port ${p}`);
  }
  ports = [...new Set(ports)].sort((a, b) => a - b);
  if (ports.length === 0) throw new UserError("no ports to scan");
  if (ports.length > max) {
    throw new UserError(`${ports.length} ports requested; the scope limit is ${max}`);
  }
  return ports;
}

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

export function parseGithubOwner(raw) {
  if (typeof raw !== "string" || !OWNER_RE.test(raw)) {
    throw new UserError(`"${String(raw)}" is not a valid GitHub owner name`);
  }
  return raw;
}

export function parseGithubRepo(raw) {
  if (typeof raw !== "string" || !REPO_RE.test(raw) || raw === "." || raw === "..") {
    throw new UserError(`"${String(raw)}" is not a valid GitHub repository name`);
  }
  return raw;
}

/** Parse "owner/repo". */
export function parseRepoSlug(raw) {
  if (typeof raw !== "string" || !raw.includes("/")) {
    throw new UserError("repo must look like owner/name");
  }
  const [owner, repo, ...rest] = raw.split("/");
  if (rest.length) throw new UserError("repo must look like owner/name");
  return { owner: parseGithubOwner(owner), repo: parseGithubRepo(repo) };
}

/** Small JSON-Schema subset validator (object properties, required, type, enum, bounds). */
export function validateArgs(schema, args) {
  const errors = [];
  const input = args ?? {};
  if (typeof input !== "object" || Array.isArray(input)) return ["arguments must be an object"];
  for (const key of schema.required ?? []) {
    if (input[key] === undefined) errors.push(`missing required argument "${key}"`);
  }
  const props = schema.properties ?? {};
  for (const [key, value] of Object.entries(input)) {
    const def = props[key];
    if (!def) {
      errors.push(`unknown argument "${key}"`);
      continue;
    }
    errors.push(...checkValue(key, def, value));
  }
  return errors;
}

function checkValue(key, def, value) {
  const types = Array.isArray(def.type) ? def.type : def.type ? [def.type] : [];
  const kind = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
  const ok =
    types.length === 0 ||
    types.some((t) =>
      t === "integer" ? Number.isInteger(value) : t === "number" ? kind === "number" : t === kind,
    );
  if (!ok) return [`argument "${key}" must be ${types.join(" or ")}`];
  const errors = [];
  if (def.enum && !def.enum.includes(value)) {
    errors.push(`argument "${key}" must be one of: ${def.enum.join(", ")}`);
  }
  if (typeof value === "number") {
    if (def.minimum !== undefined && value < def.minimum) errors.push(`"${key}" must be >= ${def.minimum}`);
    if (def.maximum !== undefined && value > def.maximum) errors.push(`"${key}" must be <= ${def.maximum}`);
  }
  if (typeof value === "string" && def.maxLength !== undefined && value.length > def.maxLength) {
    errors.push(`"${key}" is longer than ${def.maxLength} characters`);
  }
  if (Array.isArray(value)) {
    if (def.maxItems !== undefined && value.length > def.maxItems) errors.push(`"${key}" has more than ${def.maxItems} items`);
    if (def.items) value.forEach((v, i) => errors.push(...checkValue(`${key}[${i}]`, def.items, v)));
  }
  return errors;
}
