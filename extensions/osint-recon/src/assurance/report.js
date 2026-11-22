import { formatNaira } from "./money.js";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** One self-contained, phone-friendly HTML page (no scripts, no network). Open it in the phone browser. */
export function renderReconHtml(r, { title = "Reconciliation report", at = new Date().toISOString() } = {}) {
  const card = (label, n, cls) => `<div class="c ${cls}"><b>${n}</b><span>${label}</span></div>`;
  const sec = (head, rows, fmt) => rows.length ? `<h2>${head} (${rows.length})</h2>${rows.map((x) => `<div class="row">${fmt(x)}</div>`).join("")}` : "";
  const money = (x) => formatNaira(x);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>:root{color-scheme:light dark;--bg:#fafaf7;--fg:#1d1d1b;--mut:#6b6b66;--ok:#1a7f4b;--warn:#b26a00;--bad:#c0392b;--card:#fff;--line:#e3e3dc}@media(prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecece6;--mut:#9a9a92;--card:#1d1d1b;--line:#333}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif;max-width:720px;margin-inline:auto}h1{font-size:1.3rem}h2{font-size:1.05rem;margin-top:1.6rem}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px}.c b{display:block;font-size:1.5rem}.c span{color:var(--mut);font-size:.85rem}.ok b{color:var(--ok)}.warn b{color:var(--warn)}.bad b{color:var(--bad)}
.row{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;margin:8px 0;word-break:break-word}.m{color:var(--mut);font-size:.85rem}footer{color:var(--mut);font-size:.8rem;margin-top:2rem}</style></head><body>
<h1>${esc(title)}</h1><p class="m">${esc(at)} · ${esc(r.summary)}</p>
<div class="grid">${card("matched", r.matched.length, "ok")}${card("settlements", r.settlements.length, "ok")}${card("need review", r.needs_review.length + r.duplicates.length, r.needs_review.length + r.duplicates.length ? "warn" : "ok")}${card("missing", r.missing_at_bank.length + r.missing_in_ledger.length, r.missing_at_bank.length + r.missing_in_ledger.length ? "bad" : "ok")}</div>
${sec("Needs a person", r.needs_review, (x) => `<b>${esc(x.bank?.ref)}</b> ${money(x.bank?.amount ?? 0)}<br><span class="m">${esc(x.why)}${x.difference ? ` Difference ${money(x.difference)}.` : ""}</span>`)}
${sec("Possible duplicates", r.duplicates, (x) => `<b>${esc(x.duplicate.ref)}</b> ${money(x.duplicate.amount)}<br><span class="m">${esc(x.why)}</span>`)}
${sec("In your books, not on the bank statement", r.missing_at_bank, (x) => `<b>${esc(x.ref)}</b> ${money(x.amount)}<br><span class="m">${x.age_days} days old</span>`)}
${sec("On the bank statement, not in your books", r.missing_in_ledger, (x) => `<b>${esc(x.ref)}</b> ${money(x.amount)}<br><span class="m">${x.age_days} days old</span>`)}
<footer>Software cannot decide what an unexplained item is. Each line above needs a person to confirm or correct it. Not an audit.</footer></body></html>`;
}
