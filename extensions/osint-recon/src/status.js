import fs from "node:fs";
import { assessRegistry, loadRegistry } from "./guardian/registry.js";
import { loadState } from "./guardian/respond.js";
import { Ledger } from "./sentinel/ledger.js";
import { Books } from "./assurance/books.js";
import { controlTests } from "./assurance/evidence.js";

/**
 * One offline summary of everything the family knows. It makes no network calls and changes nothing: it reads local files only.
 * Each line says what is wrong and what to do next. Missing data is reported as "not set up", never as "all clear".
 */
export function gatherStatus({ env = process.env } = {}) {
  const items = [];
  const add = (area, level, text, next) => items.push({ area, level, text, next });
  const reg = env.GUARDIAN_REGISTRY ?? "guardian-accounts.json";
  if (!fs.existsSync(reg)) add("accounts", "setup", "No account registry yet.", "guardian add '{\"id\":\"gmail-main\",\"platform\":\"google\"}'");
  else {
    const r = assessRegistry(loadRegistry(reg));
    const weak = r.accounts.filter((a) => a.score < 60);
    add("accounts", weak.length ? "warn" : "ok", `Recovery readiness ${r.overall}/100; ${weak.length} account(s) below 60${weak.length ? `: ${weak.map((a) => a.label).join(", ")}` : ""}.`, weak.length ? "guardian readiness" : undefined);
  }
  const st = env.GUARDIAN_STATE ?? "guardian-state.json";
  if (!fs.existsSync(st)) add("github", "setup", "GitHub watch not started.", "guardian github-audit, then guardian approve all");
  else {
    const s = loadState(st), n = Object.keys(s.pending ?? {}).length;
    add("github", !s.approved ? "warn" : n ? "alert" : "ok", !s.approved ? "No approved baseline: nothing is being compared." : n ? `${n} unapproved item(s) waiting.` : "No unapproved changes at last check.", !s.approved ? "guardian approve all" : n ? "guardian pending" : undefined);
  }
  const gb = env.GUARDIAN_GMAIL_BASELINE ?? "guardian-gmail-baseline.json";
  add("gmail", fs.existsSync(gb) ? "ok" : "setup", fs.existsSync(gb) ? "Gmail baseline approved (run gmail-audit to compare)." : "Gmail audit not set up.", fs.existsSync(gb) ? undefined : "guardian gmail-audit");
  const sd = env.SENTINEL_DIR ?? "sentinel-data";
  if (!fs.existsSync(`${sd}/ledger.jsonl`)) add("sentinel", "setup", "No Sentinel event log yet.", "guardian sentinel serve");
  else { const v = new Ledger({ dir: sd, key: env.SENTINEL_LEDGER_KEY }).verify(); add("sentinel", v.ok ? "ok" : "alert", v.ok ? `Event log intact (${v.entries} entries).` : `EVENT LOG TAMPERED: ${v.error}`, v.ok ? `Record head ${v.head?.slice(0, 16)} off this phone.` : "Treat the server as compromised: see first-hour list."); }
  const bd = env.ASSURANCE_DIR ?? "assurance-books";
  if (!fs.existsSync(`${bd}/ledger.jsonl`)) add("books", "setup", "No finance books yet.", "use Books in your app; see ASSURANCE.md");
  else {
    const bad = controlTests({ books: new Books({ dir: bd, key: env.ASSURANCE_LEDGER_KEY }) }).filter((r) => !r.ok);
    add("books", bad.length ? "alert" : "ok", bad.length ? `${bad.length} money control(s) FAILED: ${bad.map((b) => b.title).join("; ")}` : "Books intact and balanced.", bad.length ? "Stop payouts and investigate before anything else." : undefined);
  }
  const rank = { alert: 0, warn: 1, setup: 2, ok: 3 };
  items.sort((a, b) => rank[a.level] - rank[b.level]);
  const alerts = items.filter((i) => i.level === "alert").length, warns = items.filter((i) => i.level === "warn").length, setups = items.filter((i) => i.level === "setup").length;
  return { items, summary: alerts ? `${alerts} ALERT(S) need you now` : warns ? `${warns} thing(s) to fix` : setups ? `OK so far; ${setups} area(s) not set up (not the same as safe)` : "All checks passed at last run", note: "Reflects only what these tools can see. A clean status is not proof of safety." };
}
