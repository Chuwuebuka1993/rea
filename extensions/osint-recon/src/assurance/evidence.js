import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Books } from "./books.js";
import { PayoutDesk } from "./desk.js";

/** Runs the controls against live objects and probes that they actually refuse what they should. A control that cannot be shown to work is reported as failing. */
export function controlTests({ books, desk }) {
  const results = [];
  const t = (id, csf, title, fn) => { let ok = false, detail = ""; try { const r = fn(); ok = r === true || r?.ok === true; detail = r?.detail ?? ""; } catch (e) { detail = e.message; } results.push({ id, csf, title, ok, detail }); };
  t("books-chain", "PR.DS", "Books are tamper-evident (hash chain intact)", () => { const v = books.verify(); return { ok: v.ok, detail: v.ok ? `${v.entries} entries, head ${v.head.slice(0, 16)}` : v.error }; });
  t("books-balanced", "PR.DS", "Debits equal credits across all accounts", () => ({ ok: books.trialBalance().balanced, detail: `total ${books.trialBalance().total}` }));
  t("books-nonnegative", "PR.DS", "No protected account is below zero", () => { const bad = [...books.accounts].filter(([id, a]) => a.nonNegative && (a.kind === "asset" ? books.balance(id) < 0 : books.balance(id) > 0)).map(([id]) => id); return { ok: !bad.length, detail: bad.join(", ") }; });
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), "assure-probe-"));
  try {
    const pb = new Books({ dir: probeDir });
    pb.openAccount("bank:main", "asset", { nonNegative: true }); pb.openAccount("payable:wallets", "liability");
    t("probe-unbalanced", "PR.DS", "An unbalanced journal is refused", () => { try { pb.post({ id: "x", lines: [{ account: "bank:main", amount: 100 }, { account: "payable:wallets", amount: -90 }] }); return false; } catch { return true; } });
    t("probe-overdraw", "PR.DS", "Overdrawing a protected account is refused", () => { try { pb.post({ id: "y", lines: [{ account: "payable:wallets", amount: 100 }, { account: "bank:main", amount: -100 }] }); return false; } catch { return true; } });
    t("probe-idempotent", "PR.DS", "Retrying the same journal id does not double-post", () => { const j = { id: "z", lines: [{ account: "bank:main", amount: 100 }, { account: "payable:wallets", amount: -100 }] }; pb.post(j); return pb.post(j).duplicate === true && pb.balance("bank:main") === 100; });
    if (desk) {
      const pd = new PayoutDesk({ books: pb, now: () => 1e12, coolOffMs: 0 });
      pd.addDestination("o", "d", "t");
      t("probe-maker-checker", "PR.AA", "A maker cannot approve their own payout", () => { const p = pd.request({ owner: "o", amount: "1.00", dest: "d", maker: "a" }); try { pd.approve(p.id, "a"); return false; } catch { return true; } });
    }
  } finally { fs.rmSync(probeDir, { recursive: true, force: true }); }
  if (desk) t("breaker-state", "DE.CM", "Velocity breaker is not tripped", () => ({ ok: !desk.tripped, detail: desk.tripped?.why ?? "" }));
  return results;
}
export function evidenceMarkdown(results, { title = "Control evidence", at = new Date().toISOString() } = {}) {
  const pass = results.filter((r) => r.ok).length;
  return [`# ${title}`, `Generated ${at}. ${pass}/${results.length} controls passed.`, "", "| Control | NIST CSF | Result | Detail |", "|---|---|---|---|", ...results.map((r) => `| ${r.title} | ${r.csf} | ${r.ok ? "PASS" : "FAIL"} | ${r.detail} |`), "", "This is evidence that the software's own controls behaved as designed on this date. It is not an audit, a licence or a compliance certificate."].join("\n");
}
