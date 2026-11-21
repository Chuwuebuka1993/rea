# Where outside projects fit Guardian

Checked on 2026-11-21 from each project's GitHub page. Licences are noted only where the page showed them. Always read the licence and vet any third-party skill (a poisoned SKILL.md is a prompt-injection route) before installing it.

| Project | What it is | Use in Guardian | Caution |
|---|---|---|---|
| **mvt-project/mvt** | Forensic toolkit for phones; reads STIX2 indicator files | Done: Guardian reads the same STIX2 lists and AndroidQF folders (`android-qf`), written independently | MVT License 1.1 requires the device owner's informed, uncoerced consent. No MVT code is copied here; if you run or redistribute MVT itself, its licence applies |
| **mukul975/Anthropic-Cybersecurity-Skills** | 818 agent skills mapped to MITRE ATT&CK, NIST CSF 2.0, D3FEND, ATLAS (Apache-2.0, not affiliated with Anthropic) | Use the defensive skills (incident response, forensics, detection) as agent knowledge; reuse its D3FEND and ATLAS tags in Shield | Contains offensive material; load only defensive domains, pin a release |
| **browser-use/browser-use** | Open-source browser agent (Python/TypeScript) | Later: guided recovery walkthroughs on the official pages and checks of settings pages that have no API | A browser agent acting on your logged-in accounts must never hold passwords unattended; keep a human approval step |
| **volcengine/OpenViking** | Context database for agent memory, knowledge and skills (AGPLv3 badge) | Later: shared memory for a team of Guardian agents | AGPLv3: run it as a separate service, do not embed |
| **mem0ai/mem0, rohitg00/agentmemory** | Agent memory layers | Alternatives to OpenViking for remembering past incidents | Never store secrets in agent memory |
| **ai-boost/awesome-harness-engineering** | Curated harness patterns: sandboxing, permissions, approval gates, append-only ledgers, prompt-injection screening | Design reference: Guardian's approve-then-revoke loop, circuit breaker and tamper-evident log follow the same ideas | Reading list, not code |
| **K-Dense-AI/scientific-agent-skills** (MIT) | 177 science skills | Little direct use for security; useful for the research and statistics side of the finance assurance work | None specific |
| **cathrynlavery/diagram-design** | Skill that draws diagrams as one HTML+SVG file | Draw Guardian's architecture, attack paths and incident timelines for audits | Check licence before copying templates |
| **ripienaar/free-for-dev** | List of free tiers for developers | Pick free hosting, monitoring and alerting for Guardian's server-side parts | From general knowledge, not re-read today |
| **public-apis/public-apis** | Directory of free APIs | Find free threat-intel and breach APIs to add | Same; vet each API's terms and privacy |
| **awesome-selfhosted** | Self-hostable software list | Pick self-hosted password manager, SIEM and uptime tools | Same |
| **ossu/computer-science** | Free CS curriculum | Not part of the product: a learning path for you and the team | None |
