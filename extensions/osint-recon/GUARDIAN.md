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

Facebook/Google/WhatsApp have no public API for login history, so Guardian cannot watch them automatically: it can only keep them in the readiness registry and walk you through the checks. Ideas for later: Have I Been Pwned email breach checks (needs a paid key), encrypted offline recovery-kit vault, Gmail forwarding-rule audit via OAuth, team mode for SSNG / Igboukwu Labs / AFA Alpha / Apex Mall.
