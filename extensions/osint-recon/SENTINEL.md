# Sentinel: watch your own apps from the inside

Guardian cannot see inside SSNG, Igboukwu Labs, AFA Alpha or Apex Mall from outside. Sentinel is the part that can: each app reports security events, Sentinel records them tamper-evidently, detects takeover patterns, and tells the app what to do.

```
 your app ──signed event──▶ collector ──▶ ledger (hash chain + signed head)
    ▲                          │
    └── alerts + actions ◀─────┴── detector (brute force, stuffing, takeover, payout fraud, canary)
```

## Run it (Termux or any server with Node 22)

```sh
export SENTINEL_SECRET_SSNG=$(openssl rand -hex 32)   # one per app; name after SECRET_ is the app id
export SENTINEL_SECRET_APEXMALL=$(openssl rand -hex 32)
export SENTINEL_LEDGER_KEY=$(openssl rand -hex 32)     # signs the ledger head
node src/guardian/cli.js sentinel serve                # 127.0.0.1:7070
node src/guardian/cli.js sentinel verify               # is the log intact? record the head hash off-box
node src/guardian/cli.js sentinel canary old-env-file  # trap credential, shown once
```

## Wire an app (about ten lines)

```js
import { SentinelClient } from "./src/sentinel/sdk.js";
const sentinel = new SentinelClient({ url: "http://127.0.0.1:7070", app: "ssng", secret: process.env.SENTINEL_SECRET_SSNG,
  canaries: JSON.parse(fs.readFileSync("sentinel-data/canaries.json")),
  onAlert: (a) => { if (a.action === "hold_payout_and_confirm_out_of_band") holdPayouts(a.actor); } });

await sentinel.report({ type: "login_failure", actor: userId, ip: req.ip });           // in your login route
await sentinel.report({ type: "payout_change", actor: userId, ip: req.ip, device });   // when bank details change
await sentinel.checkCredential(req.headers["x-api-key"], { ip: req.ip });              // wherever a key fails validation
```

Events: login_success/failure, logout, password_reset, mfa_enabled/disabled, role_change, api_key_created/used, config_change, payout_change, data_export, admin_action, session_revoked, canary_touch. Send identifiers, never secrets: keys such as password, token, cookie or card are rejected.

## What it detects

| Rule | Trigger | Recommended action |
|---|---|---|
| brute_force | 5 failed logins for one user in 10 min | lock_user_temporarily |
| credential_stuffing | 10 different users failing from one IP in 10 min | block_ip |
| takeover_suspected | success right after 5 failures | force_reauth_with_mfa |
| payout_after_reset | payout change within 24h of password reset or MFA disabled | hold_payout_and_confirm_out_of_band |
| new_device_admin | admin-type action from a device never seen logging in | require_reauth_and_notify_owner |
| privilege_grant, bulk_export, off_hours_admin | admin role granted, large export, night-time admin work | review |
| canary | a registered trap credential is used | revoke_all_sessions_and_rotate_secrets |

Sentinel recommends; your app decides. It never reaches into your app or accounts on its own.

## Security design

- HMAC-SHA256 over timestamp, nonce and body; 5-minute clock window; replayed nonces rejected; constant-time comparison.
- Body limit 16 KB; per-app rate limit counted only after authentication; unauthenticated floods limited per source and cannot use up an app's quota (found and fixed in review).
- Ledger entries are chained by SHA-256; edits, deletions, insertions and tail truncation are detected; the head file is HMAC-signed.
- Trap credentials are stored as hashes only.
- Binds to loopback by default; if other hosts must reach it, put it behind TLS (a reverse proxy) because the HTTP server here is plain.
- If Sentinel is down, apps keep working: monitoring fails open, so never make a security decision depend on its reply alone.

## Honest limits

- Whoever controls the machine and the ledger key can rewrite the log. Copy the head hash to another place regularly.
- It sees only what your apps report. An app that does not call report() is invisible.
- Rules are simple thresholds and will need tuning; expect some false alarms until you set the limits for your traffic.
- The ledger is read fully at startup, fine for thousands of events, not millions.
- Not a replacement for a full SIEM, penetration testing or incident-response practice.
