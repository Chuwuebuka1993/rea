# Payout demo: how to wire Sentinel into a real app

A small service (register, login, change password, set payout account, admin roles) that reports to Sentinel and obeys its recommended actions. Copy the wiring pattern into Apex Mall, EarnBridge or SSNG.

| Pattern | Where in `app.js` |
|---|---|
| Report every security-relevant event with actor, ip and device | `report(...)` calls in each route |
| Apply Sentinel's actions: lock user, block IP, sign out, hold payout, revoke all sessions on a trap hit | `report()` |
| Hold a risky payout change and send the confirmation code to the owner's OTHER verified channel, never in the response | `holdPayout()` and `notifyOwner` |
| Recover an owner whose password was changed by an attacker, using that code | `POST /recover` |
| Discard the attacker's pending payout account; only the owner's own session can approve a held change | `POST /payout/confirm` |
| Guess-limit the code (5 wrong tries destroy it) | `checkCode()` |
| Fail closed for money: if Sentinel is unreachable, hold payout changes (logins still work) | `failClosed` |
| Same response for unknown user and wrong password, with equal hashing work | `POST /login` |
| scrypt password hashing, timing-safe compare, re-enter password for payout changes, body limit, no-store headers | throughout |

Run its tests: `node --test tests/payout-demo.test.js` from the extension folder.

## Not production-ready on purpose

In-memory storage (use a database), plain HTTP (use TLS), console/callback notification (use SMS, WhatsApp or email to a contact verified earlier), no CSRF or cookie handling (it uses bearer tokens), no password-breach check at signup (add the Guardian Pwned Passwords check), no account-recovery path for a lost phone, and no support workflow for the destroyed-code case.
