import fs from "node:fs";
import path from "node:path";
import { UserError } from "../validate.js";
import { parseCsv } from "./cli.js";
import { reconcile } from "./recon.js";
import { Books } from "./books.js";
import { controlTests } from "./evidence.js";

const LOCAL = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
function inside(cwd, rel) {
  const p = path.resolve(cwd, rel);
  if (path.relative(cwd, p).startsWith("..") || !fs.existsSync(p)) throw new UserError("file must exist inside the working directory");
  return p;
}

export function createAssuranceTools({ cwd = process.cwd() } = {}) {
  return [
    {
      name: "assurance_reconcile",
      description: "Reconcile your books against a bank/processor statement. Reads two CSV files (columns id,ref,amount,date[,batch,fee]; amounts in naira). Matches exact references and batch settlements less fees; anything uncertain is returned for a person to decide. Read-only.",
      annotations: LOCAL,
      inputSchema: { type: "object", required: ["ledger_csv", "bank_csv"], properties: { ledger_csv: { type: "string", maxLength: 200 }, bank_csv: { type: "string", maxLength: 200 } } },
      async handler({ ledger_csv, bank_csv }) {
        let r;
        try { r = reconcile(parseCsv(fs.readFileSync(inside(cwd, ledger_csv), "utf8")), parseCsv(fs.readFileSync(inside(cwd, bank_csv), "utf8"))); }
        catch (e) { if (e instanceof UserError) throw e; throw new UserError(e.message); }
        return { summary: r.summary, data: { needs_review: r.needs_review, duplicates: r.duplicates, missing_at_bank: r.missing_at_bank, missing_in_ledger: r.missing_in_ledger, aging: r.aging } };
      },
    },
    {
      name: "assurance_verify_books",
      description: "Verify a books folder: hash chain intact, debits equal credits, no protected account below zero. Read-only; reports tampering, cannot prove the first entry was honest.",
      annotations: LOCAL,
      inputSchema: { type: "object", required: ["dir"], properties: { dir: { type: "string", maxLength: 200 } } },
      async handler({ dir }) {
        const p = inside(cwd, dir);
        const books = new Books({ dir: p, key: process.env.ASSURANCE_LEDGER_KEY });
        const res = controlTests({ books }).filter((r) => r.id.startsWith("books-"));
        const bad = res.filter((r) => !r.ok);
        return { summary: bad.length ? `${bad.length} control(s) FAILED: ${bad.map((b) => b.title).join("; ")}` : "Books verified: chain intact, balanced, no protected account below zero", data: { results: res } };
      },
    },
  ];
}
