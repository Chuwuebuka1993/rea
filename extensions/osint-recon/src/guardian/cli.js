#!/usr/bin/env node
// Guardian CLI for Termux / any shell. Zero dependencies. Usage: node src/guardian/cli.js <command>
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { auditGithub, diffSnapshots } from "./githubAudit.js";
import { pwnedCount, passwordVerdict } from "./hibp.js";
import { triageAndroid, COLLECT_COMMANDS } from "./android.js";
import { FIRST_HOUR, getPlaybook, listPlatforms } from "./playbooks.js";
import { assessRegistry, loadRegistry, saveRegistry, upsertAccount } from "./registry.js";

const REGISTRY = process.env.GUARDIAN_REGISTRY ?? "guardian-accounts.json";
const BASELINE = process.env.GUARDIAN_BASELINE ?? "guardian-github-baseline.json";

const HELP = `Guardian: defensive account watcher (your own accounts only)
  readiness                      score every registered account and list next actions
  add '<json>'                   add/update an account (no secrets), e.g. '{"id":"gmail-main","platform":"google","twofa":"totp"}'
  playbook <platform>            recovery steps (${listPlatforms().join(", ")})
  first-hour                     what to do in the first hour after a hack
  pwcheck                        check a password against known breaches (hidden prompt; only a 5-char hash prefix is sent)
  github-audit                   audit your GitHub account (env GUARDIAN_GITHUB_TOKEN); first run saves a baseline
  watch [minutes]                repeat the GitHub audit and alert on anything new (default 60)
  android-commands               adb commands to collect data
  android <dir> [iocs.txt]       triage files accessibility.txt, notification_listeners.txt, device_admins.txt, third_party_packages.txt`;

function print(sev, title, detail) { console.log(`[${sev.toUpperCase()}] ${title}${detail ? `: ${detail}` : ""}`); }

function notify(title, text) {
  try { execFileSync("termux-notification", ["--title", title, "--content", text, "--priority", "high"], { stdio: "ignore" }); } catch { /* not in Termux */ }
}

function askHidden(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(s); };
    rl.question(prompt, (a) => { rl.output.write("\n"); rl.close(); resolve(a); });
  });
}

async function githubCycle() {
  const r = await auditGithub({ token: process.env.GUARDIAN_GITHUB_TOKEN });
  console.log(r.summary);
  r.findings.forEach((f) => print(f.severity, f.title, f.detail));
  let alerts = [];
  if (fs.existsSync(BASELINE)) {
    alerts = diffSnapshots(JSON.parse(fs.readFileSync(BASELINE, "utf8")), r.snapshot);
    alerts.forEach((a) => { print(a.severity, a.title, a.detail); notify(`Guardian: ${a.title}`, a.detail); });
    if (!alerts.length) console.log("No changes since baseline.");
  } else {
    fs.writeFileSync(BASELINE, JSON.stringify(r.snapshot, null, 2), { mode: 0o600 });
    console.log(`Baseline saved to ${BASELINE}. Review the items above: anything you do not recognize is a warning sign.`);
  }
  return { r, alerts };
}

async function main([cmd, ...args]) {
  switch (cmd) {
    case "readiness": {
      const res = assessRegistry(loadRegistry(REGISTRY));
      console.log(`Overall recovery readiness: ${res.overall}/100`);
      for (const a of res.accounts) { console.log(`\n${a.label} [${a.platform}] ${a.score}/100 ${a.grade}`); a.actions.slice(0, 4).forEach((x) => console.log(`  - ${x}`)); }
      return;
    }
    case "add": {
      const reg = loadRegistry(REGISTRY);
      const acc = upsertAccount(reg, JSON.parse(args[0] ?? "{}"));
      saveRegistry(REGISTRY, reg);
      console.log(`Saved ${acc.id}`);
      return;
    }
    case "playbook": {
      const pb = getPlaybook(args[0]);
      if (!pb) throw new Error(`Unknown platform. Choose: ${listPlatforms().join(", ")}`);
      console.log(`${pb.name} (verified ${pb.verified_on})\nStart here: ${pb.entry ?? "n/a"}\nSource: ${pb.source}`);
      for (const k of ["prepare", "recover", "after", "notes"]) if (pb[k]?.length) { console.log(`\n${k.toUpperCase()}`); pb[k].forEach((x, i) => console.log(`  ${i + 1}. ${x}`)); }
      return;
    }
    case "first-hour": FIRST_HOUR.forEach((x, i) => console.log(`${i + 1}. ${x}`)); return;
    case "pwcheck": {
      const pw = await askHidden("Password to check (hidden): ");
      const v = passwordVerdict(await pwnedCount(pw));
      console.log(v.message);
      process.exitCode = v.safe ? 0 : 2;
      return;
    }
    case "github-audit": await githubCycle(); return;
    case "watch": {
      const mins = Number(args[0] ?? 60);
      if (!(mins >= 1)) throw new Error("minutes must be >= 1");
      for (;;) {
        try { await githubCycle(); } catch (e) { console.error(`watch error: ${e.message}`); }
        await new Promise((r) => setTimeout(r, mins * 60000));
      }
    }
    case "android-commands": Object.entries(COLLECT_COMMANDS).forEach(([k, v]) => console.log(`${k}: ${v}`)); return;
    case "android": {
      const dir = args[0];
      if (!dir) throw new Error("give the folder holding the collected text files");
      const rd = (n) => { const p = path.join(dir, `${n}.txt`); return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : undefined; };
      const iocs = args[1] ? fs.readFileSync(args[1], "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean) : [];
      const r = triageAndroid({ accessibility: rd("accessibility"), notification_listeners: rd("notification_listeners"), device_admins: rd("device_admins"), third_party_packages: rd("third_party_packages") }, { iocs });
      console.log(r.summary);
      r.findings.forEach((f) => print(f.severity, f.title, f.detail));
      r.limits.forEach((l) => console.log(`NOTE: ${l}`));
      return;
    }
    default: console.log(HELP);
  }
}

main(process.argv.slice(2)).catch((e) => { console.error(`Error: ${e.message}`); process.exit(1); });
