# Guardian + AFIR (optional, local, advisory)

Status: PROPOSED integration, IMPLEMENTED client, TESTED with mock fetch only. LOCALLY VERIFIED. Not CI VERIFIED. It has never been run against a live AFIR or a live model.

Guardian is an independent tenant ("rea") of your own local AFIR router. It is **off** unless you set `REA_AFIR_URL`.

## What it can do
Ask a local model to *explain* one finding in plain words (`AfirClient.explain`). The answer is labelled advisory and unverified. Nothing is executed, approved or changed because of it.

## What it cannot do (by design)
- No approvals, deployments, permission changes, control changes or paid usage: the client has only `connect` and `explain` (a test enforces this).
- No private data to hosted providers: it always sends `data_class: "private"`, and refuses to work unless AFIR reports the `rea` policy as private-only with no hosted providers.
- No network exposure: the URL must be plain-http loopback; redirects are refused; the AFIR owner token is never used or needed.
- Only `id`, `severity`, `title`, `detail` leave Guardian, with token-shaped strings masked. Nothing is written to disk or logs by this module.

## Setup (owner, on the same machine)
1. In AFIR's tenant policy file: `"rea": { "dataClass": "private", "hosted": false, "limits": { "rpd": 50, "tpd": 100000 } }`.
2. Issue REA its own token (`afir gen-token`, set `AFIR_TOKEN_REA`). Give Guardian only that value as `REA_AFIR_TOKEN`; `REA_AFIR_URL=http://127.0.0.1:8787`.
3. Private requests are served only by a **local** model (e.g. a small model in Ollama/llama.cpp that you install yourself; nothing is downloaded automatically). Without one, AFIR refuses and Guardian works as before.
4. `node src/guardian/cli.js afir-check` confirms the policy; it sends no finding data.

## Known limits
- A model can be wrong or be steered by text inside a finding (treated as data in the prompt, but this is not a guarantee). Treat output as a hint.
- Local small models on a phone may be slow or poor; that is a hardware limit, not tested here.
- Not wired into the MCP tool list yet (kept out to avoid widening Guardian's tool surface without your approval).
