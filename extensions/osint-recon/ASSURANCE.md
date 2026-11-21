# Ledger Assurance: money controls for a small fintech/marketplace

Built for apps that hold or move other people's money (wallets, payouts, marketplace settlements). Zero dependencies, Node 22, runs in Termux. It reuses Sentinel's tamper-evident ledger.

| Risk (from competitor/Nigeria research) | Control | Module |
|---|---|---|
| Books edited after the fact | Hash-chained, append-only journal; fixes are reversals, never edits | `books.js` |
| Float/rounding errors | Integer kobo only; floats rejected | `money.js` |
| Double posting on retries | Idempotency key per journal | `books.js` |
| Unbalanced entries, overdrawn accounts | Debits must equal credits; protected accounts cannot go below zero | `books.js` |
| Bank vs books drift, settlement fees, duplicates | Reconciliation: exact match, batch settlement less fees, "needs a person" for anything guessed, aging | `recon.js` |
| One person moves money | Maker-checker; amounts above a threshold need two other approvers | `desk.js` |
| Account takeover cash-out | New payout destinations wait a cooling-off period; Sentinel alerts freeze an owner | `desk.js` + Sentinel |
| Runaway or scripted drain | Velocity breaker that stays tripped until a named person recovers it | `desk.js` |
| Breach notification | 72-hour clock; a person assesses risk, software never decides | `incidents.js` |
| "Prove your controls work" | Live control tests that probe refusals, exportable as Markdown | `evidence.js` |

## Use

```sh
node src/assurance/cli.js recon ledger.csv bank.csv   # columns: id,ref,amount,date[,batch,fee]; amounts in naira
node src/assurance/cli.js evidence                    # control self-test report
```

MCP tools: `assurance_reconcile`, `assurance_verify_books` (read-only, confined to the working directory).

Wire Sentinel to the desk: `notify: (a) => desk.onSentinelAlert(a)`. In code: `import { Books, PayoutDesk, reconcile, IncidentLog } from "./src/assurance/index.js"`.

## Honest limits

- This is **not** a compliance certificate, an audit, or a licence. Holding or moving customer money in Nigeria may require CBN authorisation or a licensed partner (bank/PSP). That was not verified here: consult a Nigerian fintech lawyer before launch.
- The NDPA 72-hour breach notice rule comes from search sources, not legal advice. Confirm it with counsel.
- The ledger proves *tampering by edit or deletion*, not honesty of the first entry. Someone with both the files and the key can rewrite history: copy the head hash off the machine regularly (`sentinel verify` style).
- Reconciliation depends on clean references. Anything uncertain goes to a person by design.
- No bank or payment-processor connection is built. Feed it CSV exports; never give it bank credentials.
- Approver names are labels, not authentication. In a real app, tie them to your logged-in, MFA-protected users.
