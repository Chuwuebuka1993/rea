import fs from "node:fs";
import path from "node:path";
import { tag } from "./csf.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", "__pycache__", "vendor"]);
const EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".py", ".go", ".java", ".rs", ".php"]);

// [regex, severity, kind, title, advice]
const RULES = [
  [/createHash\(\s*['"](md5|sha1)['"]|hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"/i, "medium", "weak_crypto", "Weak hash (MD5/SHA-1)", "Use SHA-256 or better. For passwords use Argon2id, scrypt or bcrypt."],
  [/\b(des|3des|des-ede3|rc4|arcfour|rc2)\b['"(]|DES\.new|Cipher\.getInstance\(\s*"(DES|RC4)/i, "high", "weak_crypto", "Broken cipher (DES/3DES/RC4)", "Use AES-256-GCM or ChaCha20-Poly1305."],
  [/aes-\d+-ecb|MODE_ECB|AES\/ECB/i, "high", "weak_crypto", "ECB mode leaks patterns", "Use an authenticated mode such as GCM."],
  [/modulusLength\s*:\s*(512|768|1024)\b|RSA\.generate\(\s*(512|768|1024)\b|rsa\.GenerateKey\([^,]+,\s*(512|768|1024)\b/, "high", "weak_crypto", "RSA key shorter than 2048 bits", "Use at least 3072-bit RSA or move to modern curves, and plan post-quantum migration."],
  [/rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/, "high", "tls_validation", "TLS certificate validation disabled", "Remove it. Fix the certificate or trust the right CA instead."],
  [/-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/, "high", "secrets", "Private key embedded in source", "Remove it from the repo, rotate the key, and load it from a secret store."],
  [/Math\.random\(\)[^;\n]*(token|secret|password|session|nonce|key)|(token|secret|password|session|nonce|key)[^;\n]*Math\.random\(\)/i, "medium", "weak_crypto", "Math.random used for a security value", "Use crypto.randomBytes / secrets.token_bytes."],
];
// Public-key algorithms that a future quantum computer breaks (NIST IR 8547 plans deprecation by 2035).
const QUANTUM = /generateKeyPair(Sync)?\(\s*['"](rsa|ec|dsa|dh|ed25519|x25519)['"]|createECDH|createDiffieHellman|ECDSA|ecdsa\.|rsa\.|RSA\.generate|ec\.generate_private_key|ed25519/i;

export function scanCrypto(root, { maxFiles = 4000, maxBytes = 500_000 } = {}) {
  const findings = [];
  const quantum = new Map();
  let files = 0;
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (files >= maxFiles) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(p); continue; }
      if (!e.isFile() || !EXT.has(path.extname(e.name)) || fs.statSync(p).size > maxBytes) continue;
      files++;
      const rel = path.relative(root, p);
      fs.readFileSync(p, "utf8").split(/\r?\n/).forEach((line, i) => {
        for (const [re, sev, kind, title, advice] of RULES) if (re.test(line)) findings.push(tag({ severity: sev, title, detail: `${rel}:${i + 1}. ${advice}`, target: rel }, kind));
        if (QUANTUM.test(line)) quantum.set(rel, (quantum.get(rel) ?? 0) + 1);
      });
    }
  })(root);
  if (quantum.size) {
    findings.push(tag({
      severity: "info", title: `Quantum-vulnerable public-key crypto in ${quantum.size} file(s)`,
      detail: `${[...quantum.keys()].slice(0, 8).join(", ")}. Inventory it now; plan migration to ML-KEM (FIPS 203) and ML-DSA (FIPS 204), ideally hybrid. Data that must stay secret for years is exposed to harvest-now-decrypt-later.`,
      target: "crypto-inventory",
    }, "quantum"));
  }
  return { files_scanned: files, quantum_files: [...quantum.keys()], findings };
}
