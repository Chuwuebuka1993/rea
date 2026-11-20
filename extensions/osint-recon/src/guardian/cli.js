#!/usr/bin/env node
// Guardian CLI for Termux / any shell. Zero dependencies. Usage: node src/guardian/cli.js <command>
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { auditGithub, diffSnapshots } from "./githubAudit.js";
import { approve, loadState, respond, saveState } from "./respond.js";
import { pwnedCount, passwordVerdict } from "./hibp.js";
import { triageAndroid, COLLECT_COMMANDS } from "./android.js";
import { FIRST_HOUR, getPlaybook, listPlatforms } from "./playbooks.js";
import { assessRegistry, loadRegistry, saveRegistry, upsertAccount } from "./registry.js";

const REGISTRY = process.env.GUARDIAN_REGISTRY ?? "guardian-accounts.json";
const STATE = process.env.GUARDIAN_STATE ?? "guardian-state.json";

const HELP = `Guardian: defensive account watcher (your own accounts only)
  readiness                      score every registered account and list next actions
  add '<json>'                   add/update an account (no secrets), e.g. '{"id":"gmail-main","platform":"google","twofa":"totp"}'
  playbook <platform>            recovery steps (${listPlatforms().join(", ")})
  first-hour                     what to do in the first hour after a hack
  pwcheck                        check a password against known breaches (hidden prompt; only a 5-char hash prefix is sent)
  github-audit                   audit GitHub (env GUARDIAN_GITHUB_TOKEN); alerts on anything not approved
  approve all|<key>              trust what is currently on the account, or one pending item
  pending                        items waiting for your approval
  watch [minutes] [--enforce]    repeat the audit; with --enforce, revoke unapproved keys/hooks after a 10 min grace (default 15 min cycle)
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

async function githubCycle({ enforce = false, graceMinutes = 10 } = {}) {
  const token = process.env.GUARDIAN_GITHUB_TOKEN;
  const r = await auditGithub({ token });
  console.log(r.summary);
  r.findings.forEach((f) => print(f.severity, f.title, f.detail));
  const state = loadState(STATE);
  state.last_snapshot = r.snapshot;
  const alerts = state.approved ? diffSnapshots(state.approved, r.snapshot) : r.snapshot.ssh_keys.map((k) => ({ title: "Existing SSH key", detail: `${k.title} ${k.fingerprint}`, key: `ssh:${k.fingerprint}`, ref: { type: "ssh" } }));
  const { events } = await respond({ alerts, state, enforce, graceMs: graceMinutes * 60000, token });
  events.forEach((e) => { print(e.level, e.text); if (["alert", "action", "critical"].includes(e.level)) notify(`Guardian ${e.level}`, e.text); });
  if (!state.approved) console.log('No approved baseline yet. Review the list above, then run: guardian approve all');
  else if (!events.length) console.log("No unapproved changes.");
  saveState(STATE, state);
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
    case "approve": {
      const state = loadState(STATE);
      if (args[0] === "all" && !state.last_snapshot) throw new Error("run github-audit first");
      console.log(approve(state, state.last_snapshot, args[0] ?? ""));
      saveState(STATE, state);
      return;
    }
    case "pending": {
      const p = Object.entries(loadState(STATE).pending);
      if (!p.length) console.log("Nothing pending.");
      p.forEach(([k, v]) => console.log(`${k}  first seen ${new Date(v.first_seen).toISOString()}  ${v.alert.detail}`));
      return;
    }
    case "watch": {
      const enforce = args.includes("--enforce");
      const rest = args.filter((a) => a !== "--enforce");
      const mins = Number(rest[0] ?? 15);
      if (!(mins >= 1)) throw new Error("minutes must be >= 1");
      for (;;) {
        try { await githubCycle({ enforce }); } catch (e) { console.error(`watch error: ${e.message}`); }
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
