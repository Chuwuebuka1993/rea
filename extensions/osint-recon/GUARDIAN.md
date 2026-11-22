# Guardian: defensive account watcher

Guardian protects **your own** accounts. It sits beside the scope-gated OSINT/Kali-style tools in this extension, but it is defensive only and needs no scope file. Zero dependencies, Node 22, works in Termux.

## What it does

| Need | Feature | How |
|---|---|---|
| Know which accounts are weak | Recovery-readiness score per account (2FA type, backup codes, recovery email/phone, passkey, second owner), capped by the email that can reset it | `guardian_readiness` / `cli readiness` |
| Warn about takeover signs | GitHub audit: 2FA flag, SSH/GPG keys, deploy keys, webhooks, emails; baseline diff alerts on anything new | `guardian_github_audit` / `cli github-audit`, `cli watch 60` |
| Warn about spyware | Android triage of adb output: accessibility services, notification listeners, device admins, sideloaded apps, your own IOC list | `guardian_android_triage` / `cli android <dir>` |
| Stop reused/breached passwords | Pwned Passwords k-anonymity check (only 5 hash characters leave the device) | `cli pwcheck` (hidden prompt) |
| Recover after a hack | Official-source playbooks: Google, GitHub, WhatsApp, Facebook, Instagram, Telegram, X, plus a generic one for your own apps; first-hour checklist | `guardian_recovery_playbook` / `cli playbook <name>` |

Playbooks were checked against official pages on 2026-11-19 and each carries its source URL. Vendors change flows: confirm on the linked page.

## Quick start (Termux)

```sh
pkg install nodejs git
git clone -b feat/guardian https://github.com/Chuwuebuka1993/rea.git
cd rea/extensions/osint-recon
alias guardian='node src/guardian/cli.js'
guardian add '{"id":"gmail-main","platform":"google","twofa":"totp","backup_codes_saved":true,"recovery_phone":true}'
guardian readiness
export GUARDIAN_GITHUB_TOKEN=...   # read-only scopes, your own account
guardian github-audit              # first run saves a baseline
guardian watch 60                  # alerts via termux-notification if Termux:API is installed
```

## Honest limits

- No software can guarantee safety, and none can recover a hacked account alone: recovery works only with factors you prepared before (backup codes, recovery email/phone, passkeys, a second owner). The readiness score exists to make you prepare them.
- Android triage is not a malware scan. Termux cannot see other apps, so you collect adb output and Guardian reads it. Advanced spyware can evade it; a clean result is not proof. For suspected targeted surveillance use a forensic tool such as MVT with a trained helper.
- Stalkerware removal can alert the person who installed it: plan your safety first.
- The GitHub public API cannot list personal access tokens, authorized OAuth apps, or the security log. Review github.com/settings/security-log and /settings/applications by hand.
- Do not paste passwords or tokens into any AI chat. The registry rejects secret-like fields; tokens come only from environment variables.
- Anyone offering to "recover" an account for money is a scam.

## Not built yet

Facebook/Google/WhatsApp have no public API for login history, so Guardian cannot watch them automatically: it can only keep them in the readiness registry and walk you through the checks. Ideas for later: Have I Been Pwned email breach checks (needs a paid key), encrypted offline recovery-kit vault, team mode for SSNG / Igboukwu Labs / AFA Alpha / Apex Mall.

## Auto-response (GitHub)

`guardian watch 15 --enforce` repeats the audit and compares it with what **you approved**.

1. Run `github-audit`, review the list, then `approve all`. Until you do, Guardian only alerts: it will not trust keys that may already belong to an intruder.
2. Anything new and unapproved (SSH/GPG key, deploy key, webhook) raises an immediate alert, with a Termux notification.
3. You have a 10-minute grace period to run `approve <key>` for something you added yourself.
4. After that, with `--enforce`, Guardian revokes it through the GitHub API. Without `--enforce` it only reports "would revoke".
5. If more than 5 items are due at once, it revokes nothing and escalates: that pattern looks like a mass compromise or a bug.

It never changes passwords, never deletes repositories, and cannot remove emails. Token needs admin:public_key, admin:gpg_key, admin:repo_hook and repo to revoke. Approve things you add on purpose, or they will be removed.

## Spyware indicator lists (MVT-compatible)

`guardian android-qf <acquisition-folder> --iocs list.stix2` reads an AndroidQF-style folder (packages.json, ps.txt, getprop.txt, settings_*.txt, files.json) and checks it against STIX2 indicator files: app ids, signing-certificate and file hashes, domains, processes, file paths and device properties. Every hit names the indicator set it came from, and anything not provided is reported as "Not checked" instead of silently passing.

- Guardian ships no indicator lists. Get current ones from trusted public sources and check their licences.
- Only examine a phone you own, or whose owner has freely consented knowing what is collected. MVT's licence makes this a condition of use.
- Lists only catch known samples. A clean result is not proof the phone is safe.

## Gmail takeover audit

`guardian gmail-audit` reads your Gmail settings and flags the tricks attackers use to keep access: auto-forwarding, forwarding addresses, filters that forward mail or hide security alerts (skip inbox / trash), and delegates.

1. Create an OAuth access token for your own account yourself (scope `gmail.readonly`) and put it in `GUARDIAN_GMAIL_TOKEN`. Access tokens expire in about an hour. Never paste it into chat.
2. Run `gmail-audit`, review the list, then `gmail-approve all` (or one key). Later runs only report what is new.
3. `gmail-audit --enforce` deletes unapproved forwarding or hiding **filters** only (needs scope `gmail.settings.basic`). It never touches mail, and does not turn off auto-forwarding or remove delegates: do that by hand in Gmail settings.

Limits: this reads settings only. It cannot see sign-in history or devices; check myaccount.google.com/security by hand. A new filter you create yourself will alert until you approve it.
