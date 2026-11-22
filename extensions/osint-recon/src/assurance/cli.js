#!/usr/bin/env node
// Assurance CLI. Usage: node src/assurance/cli.js recon <ledger.csv> <bank.csv> | evidence [dir]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Books } from "./books.js";
import { PayoutDesk } from "./desk.js";
import { controlTests, evidenceMarkdown } from "./evidence.js";
import { reconcile } from "./recon.js";
import { formatNaira, toKobo } from "./money.js";
import { renderReconHtml } from "./report.js";

/** Minimal CSV: header row, comma separated, no quoted commas. Columns: id,ref,amount,date[,batch,fee]. Amounts in naira like 1234.50. */
export function parseCsv(text) {
  const [head, ...rows] = String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const cols = head.split(",").map((c) => c.trim().toLowerCase());
  for (const need of ["id", "ref", "amount", "date"]) if (!cols.includes(need)) throw new Error(`CSV needs a "${need}" column`);
  return rows.map((r, i) => {
    const v = Object.fromEntries(r.split(",").map((x, j) => [cols[j], x.trim()]));
    if (Number.isNaN(Date.parse(v.date))) throw new Error(`row ${i + 2}: bad date "${v.date}"`);
    return { id: v.id, ref: v.ref, amount: toKobo(v.amount), date: v.date, ...(v.batch ? { batch: v.batch } : {}), ...(v.fee ? { fee: toKobo(v.fee) } : {}) };
  });
}
const line = (r) => `${r.id ?? r.bank?.id} ${r.ref ?? r.bank?.ref} ${formatNaira(r.amount ?? r.bank?.amount)}`;

async function main([cmd, a, b, c, d]) {
  if (cmd === "recon") {
    if (!a || !b) throw new Error("usage: recon <ledger.csv> <bank.csv>");
    const r = reconcile(parseCsv(fs.readFileSync(a, "utf8")), parseCsv(fs.readFileSync(b, "utf8")));
    if (c === "--html") { if (!d) throw new Error("usage: recon <ledger.csv> <bank.csv> --html <out.html>"); fs.writeFileSync(d, renderReconHtml(r)); console.log(`Report written to ${d}`); }
    console.log(r.summary);
    r.settlements.forEach((s) => console.log(`SETTLED  ${s.bank.ref}: ${s.ledger.length} sales, fees ${formatNaira(s.fees)}`));
    r.needs_review.forEach((x) => console.log(`REVIEW   ${line(x)} ${x.why}${x.difference ? ` (difference ${formatNaira(x.difference)})` : ""}`));
    r.duplicates.forEach((x) => console.log(`DUPLICATE ${line(x.duplicate)} ${x.why}`));
    r.missing_at_bank.forEach((x) => console.log(`NOT ON BANK STATEMENT ${line(x)} (${x.age_days} days)`));
    r.missing_in_ledger.forEach((x) => console.log(`NOT IN YOUR BOOKS     ${line(x)} (${x.age_days} days)`));
    process.exitCode = /, 0 item\(s\)/.test(r.summary) ? 0 : 2;
    return;
  }
  if (cmd === "evidence") {
    const dir = a ?? fs.mkdtempSync(path.join(os.tmpdir(), "assure-"));
    const books = new Books({ dir, key: process.env.ASSURANCE_LEDGER_KEY });
    console.log(evidenceMarkdown(controlTests({ books, desk: new PayoutDesk({ books }) })));
    return;
  }
  console.log("Assurance: recon <ledger.csv> <bank.csv> | evidence [books-dir]");
}
if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).catch((e) => { console.error(`Error: ${e.message}`); process.exit(1); });
