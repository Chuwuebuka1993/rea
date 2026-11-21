import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

/** Make a trap credential. Plant it where an intruder looks (old .env, a decoy config, a fake admin API key). It grants nothing. */
export function makeCanary(label, kind = "api_key") {
  const body = crypto.randomBytes(24).toString("hex");
  const value = kind === "password" ? `Tr@p-${body.slice(0, 16)}` : kind === "token" ? `tok_${body}` : `key_${body}`;
  return { label, kind, value, sha256: sha(value) };
}

export class CanaryStore {
  constructor(dir) { this.file = path.join(dir, "canaries.json"); fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  load() { return fs.existsSync(this.file) ? JSON.parse(fs.readFileSync(this.file, "utf8")) : []; }
  /** Only hashes are stored, so a leaked store does not reveal usable values. Show the value once. */
  add(c) {
    const list = this.load();
    list.push({ label: c.label, kind: c.kind, sha256: c.sha256, created: new Date().toISOString() });
    fs.writeFileSync(this.file, JSON.stringify(list, null, 2), { mode: 0o600 });
  }
}

/** Returns the label if `value` is a registered trap, else undefined. */
export function canaryLabel(value, canaries) {
  if (typeof value !== "string" || value.length < 8 || value.length > 512) return undefined;
  const h = sha(value);
  return canaries.find((c) => c.sha256 === h)?.label;
}
