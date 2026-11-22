# Start here (plain-language guide, Termux)

This toolkit has four parts. You do not need all of them on day one.

| Part | Protects | First command |
|---|---|---|
| **Guardian** | Your own accounts: recovery readiness, GitHub and Gmail takeover signs, phone spyware triage | `node src/guardian/cli.js readiness` |
| **Sentinel** | Your own apps: signed event log, attack detection, trap passwords | `node src/guardian/cli.js sentinel serve` |
| **Shield** | Your code: risky dependencies, weak crypto | MCP tools `shield_*` |
| **Assurance** | Money: tamper-evident books, bank reconciliation, payout controls | `node src/assurance/cli.js evidence` |

## Setup once
```sh
pkg install nodejs git
git clone -b feat/guardian https://github.com/Chuwuebuka1993/rea.git
cd rea/extensions/osint-recon
alias guardian='node src/guardian/cli.js'
```

## Every morning (offline, 5 seconds)
```sh
guardian status
```
It lists what needs you now, what to fix, and what is **not set up** (not set up is not the same as safe). Each line says the next command.

## Week one checklist
1. `guardian add '{"id":"gmail-main","platform":"google","twofa":"totp"}'` for each important account, then `guardian readiness` and fix the lowest scores (backup codes, recovery phone, a second owner).
2. `guardian playbook google` and print or save the steps *before* you need them.
3. GitHub: set `GUARDIAN_GITHUB_TOKEN`, run `guardian github-audit`, review, `guardian approve all`.
4. Gmail: set `GUARDIAN_GMAIL_TOKEN`, run `guardian gmail-audit`, review, `guardian gmail-approve all`.
5. Money: export your sales and the bank statement as CSV and run `node src/assurance/cli.js recon ledger.csv bank.csv --html report.html`.

## Rules that keep you safe
- Never paste passwords, tokens or keys into any AI chat. Tokens go in environment variables only.
- Only check phones and accounts you own or have permission to check.
- Nobody can guarantee safety or recover a hacked account for you. Recovery works because of factors you prepared *before* (backup codes, recovery email/phone, second owner).
- Anyone who offers to "recover" your account for money is a scammer.
- Details and limits: GUARDIAN.md, SENTINEL.md, SHIELD.md, ASSURANCE.md, INTEGRATIONS.md.
