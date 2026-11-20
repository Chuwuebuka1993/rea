# Guardian Shield: layered defence for apps, services and teams

Shield is the "protect and identify" layer next to Guardian (accounts) and the recon tools (attack-surface view). Everything is mapped to **NIST CSF 2.0** (Govern, Identify, Protect, Detect, Respond, Recover) so results speak the language auditors, banks and governments use.

## Built now

| Layer | Tool | Maps to |
|---|---|---|
| Supply chain: known-vulnerable dependencies (npm lockfile, pinned pip) via OSV.dev; only names and versions are sent | `shield_dependency_audit` | GV.SC, MITRE T1195 |
| Crypto hygiene: MD5/SHA-1, DES/RC4, ECB, short RSA, disabled TLS validation, embedded private keys, weak randomness | `shield_crypto_scan` | PR.DS, PR.AA, T1600, T1552, T1557 |
| Post-quantum readiness: inventory of RSA/ECC/DH use to plan migration to ML-KEM and ML-DSA (FIPS 203/204, FIPS 205 hash-based signatures); NIST IR 8547 plans to deprecate quantum-vulnerable algorithms by 2035, high-risk systems sooner | in `shield_crypto_scan` | PR.DS |
| One-call summary by CSF function, with the list of what it does not cover | `shield_posture` | all |
| Account protection and auto-response | Guardian (`GUARDIAN.md`) | PR.AA, DE.CM, RS.MI, RC.RP |
| Attack-surface view of your own hosts, headers, exposed secrets, workflows | recon tools (scope-gated) | ID.AM, ID.RA |

## Why these gaps (from the research)

- Reviewers of open-source monitoring stacks (Wazuh, Security Onion) say setup and rule tuning are hard. Shield keeps zero dependencies and one command, and explains each finding with the fix.
- Threat reports (WEF Global Cybersecurity Outlook 2026, CrowdStrike 2026) put ransomware, supply-chain compromise, cyber-enabled fraud and AI-assisted attacks at the top, and sub-Saharan Africa high on fraud. So Shield starts with supply chain, credentials and crypto, which stop the most common entry routes.

## Not built (be honest about it)

- **Runtime detection** (host and network monitoring): use Wazuh, Falco (eBPF) and Suricata. A later Shield module can generate their configs and ingest their alerts.
- **Cloud and container configuration**, SBOM generation, signed builds, secrets scanning in git history.
- **Policy, training, incident-response drills and backups** (CSF Govern and Recover): software cannot replace these. Test restoring your backups.
- **Military, government and critical infrastructure**: this tool is a developer and small-business aid. Those environments need accredited products and processes (for example Common Criteria, FedRAMP or national equivalents), formal risk management and vetted people. Do not use Shield as a substitute.
- A static scan finds patterns, not proof of safety, and can miss or over-report.
