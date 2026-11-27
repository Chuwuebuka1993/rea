# Scan My Code (Guardian)

Read-only, offline check of **your own** project folder. It never prints a secret's value, never follows symlinks, never uses the network.

    node src/guardian/cli.js scan-code ~/alpha-cloud-workshop
    node src/guardian/cli.js scanners                 # which open-source scanners you installed
    node src/guardian/cli.js scan-with gitleaks ~/alpha-cloud-workshop

What it finds: private keys and common token formats, `.env` files not ignored by git, `eval`, shell strings, switched-off TLS checks, MD5/SHA-1, services bound to 0.0.0.0, `curl | sh`, install scripts, unpinned dependencies.
A line you have reviewed can be marked `// guardian-scan: allow <rule-id> (reason)`. Secrets cannot be allowed this way.

Limits: pattern matching only, so it misses things and can flag harmless lines. A clean result is not proof of safety.

Optional scanners (installed by you, from their official pages; Guardian downloads nothing):
gitleaks (MIT), semgrep (LGPL-2.1 engine; rule licences vary), osv-scanner (Apache-2.0), trivy (Apache-2.0). Their Termux support is untested here.

Deliberately not included: offensive or exploit tools. Strix (Apache-2.0) is an AI pentest agent that needs Docker and a paid model key; run it only from a computer, only against systems you own or have written permission to test.
