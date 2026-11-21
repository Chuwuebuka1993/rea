// Reconciliation between your books and the bank/processor statement. Nothing is ever auto-matched on a guess:
// exact reference+amount matches and explained batch settlements match; everything else goes to a person.
const DAY = 86400000;
const days = (a, b) => Math.round(Math.abs(new Date(a) - new Date(b)) / DAY);

/**
 * @param ledger rows {id, ref, amount, date, batch?, fee?}  (kobo, integers)
 * @param bank   rows {id, ref, amount, date}
 * Settlement rule: ledger rows sharing a `batch` equal one bank row whose ref === batch and whose amount === sum(amount) - sum(fee).
 */
export function reconcile(ledger, bank, { now = new Date(), dateToleranceDays = 3 } = {}) {
  const out = { matched: [], settlements: [], needs_review: [], duplicates: [], missing_at_bank: [], missing_in_ledger: [] };
  const lUsed = new Set(), bUsed = new Set();

  // 1. duplicate bank lines (same ref + amount twice)
  const seen = new Map();
  for (const b of bank) {
    const k = `${b.ref}|${b.amount}`;
    if (seen.has(k)) { out.duplicates.push({ first: seen.get(k), duplicate: b, why: "Same reference and amount appear twice on the statement. Possible double credit/debit." }); bUsed.add(b.id); }
    else seen.set(k, b);
  }
  // 2. exact ref + amount
  for (const b of bank) {
    if (bUsed.has(b.id)) continue;
    const l = ledger.find((x) => !lUsed.has(x.id) && !x.batch && x.ref === b.ref && x.amount === b.amount);
    if (l) { lUsed.add(l.id); bUsed.add(b.id); out.matched.push({ ledger: l, bank: b, rule: "exact_reference" }); }
  }
  // 3. batch settlements
  const batches = new Map();
  for (const l of ledger) if (l.batch && !lUsed.has(l.id)) batches.set(l.batch, [...(batches.get(l.batch) ?? []), l]);
  for (const [batch, rows] of batches) {
    const b = bank.find((x) => !bUsed.has(x.id) && x.ref === batch);
    if (!b) continue;
    const gross = rows.reduce((s, r) => s + r.amount, 0), fees = rows.reduce((s, r) => s + (r.fee ?? 0), 0);
    if (gross - fees === b.amount) { rows.forEach((r) => lUsed.add(r.id)); bUsed.add(b.id); out.settlements.push({ bank: b, ledger: rows, gross, fees, rule: "batch_settlement" }); }
    else { rows.forEach((r) => lUsed.add(r.id)); bUsed.add(b.id); out.needs_review.push({ bank: b, ledger: rows, expected: gross - fees, difference: b.amount - (gross - fees), why: "Settlement total differs from the sum of its transactions less fees." }); }
  }
  // 4. same ref but different amount, or same amount+close date with different ref => a person decides
  for (const b of bank) {
    if (bUsed.has(b.id)) continue;
    const byRef = ledger.find((x) => !lUsed.has(x.id) && x.ref === b.ref);
    if (byRef) { lUsed.add(byRef.id); bUsed.add(b.id); out.needs_review.push({ bank: b, ledger: [byRef], difference: b.amount - byRef.amount, why: "Reference matches but the amount differs." }); continue; }
    const byAmt = ledger.find((x) => !lUsed.has(x.id) && x.amount === b.amount && days(x.date, b.date) <= dateToleranceDays);
    if (byAmt) { lUsed.add(byAmt.id); bUsed.add(b.id); out.needs_review.push({ bank: b, ledger: [byAmt], why: "Amount and date are close but the reference differs. Confirm it is the same transaction." }); }
  }
  // 5. leftovers, with age
  for (const l of ledger) if (!lUsed.has(l.id)) out.missing_at_bank.push({ ...l, age_days: days(now, l.date) });
  for (const b of bank) if (!bUsed.has(b.id)) out.missing_in_ledger.push({ ...b, age_days: days(now, b.date) });
  const aging = (rows) => ({ "0-7": rows.filter((r) => r.age_days <= 7).length, "8-30": rows.filter((r) => r.age_days > 7 && r.age_days <= 30).length, "30+": rows.filter((r) => r.age_days > 30).length });
  const open = out.missing_at_bank.length + out.missing_in_ledger.length + out.needs_review.length + out.duplicates.length;
  return { ...out, aging: { missing_at_bank: aging(out.missing_at_bank), missing_in_ledger: aging(out.missing_in_ledger) }, summary: `${out.matched.length} matched, ${out.settlements.length} settlements, ${open} item(s) need a person` };
}
