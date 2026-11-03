# rea-osint-recon

A companion MCP server for REA that puts **GitHub OSINT** and **Kali-style recon** in one app.
It runs beside REA, so your agent can reverse engineer a binary with REA and then check the
organization, repositories and infrastructure around it with these tools.

Zero dependencies. Node.js 22.18+ only. Works on Kali, Debian, macOS and Windows.

## Authorization comes first

Every network tool refuses to run until you declare who authorized the testing and what is in scope.
Copy `osint-scope.example.json` to `osint-scope.json`, fill it in, and point `OSINT_SCOPE_FILE` at it.

- Targets outside the scope are refused before any packet is sent.
- IP literals must be listed explicitly in `hosts` or `cidrs`.
- Domains match the listed domain and its subdomains only.
- A name that resolves to a loopback, private, link-local or cloud-metadata address is blocked unless
  that address is explicitly in scope. This is checked at connect time, so DNS rebinding cannot bypass it.
- Port-scan size, concurrency and timeout are capped by the scope file (hard maximums: 1024 ports,
  100 workers, 10 s).
- Authorization can expire (`authorization.expires`); the scope file is re-read on every call.

Only test assets you own or have written permission to test.

## Tools

| Tool | What it does | Kali equivalent |
| --- | --- | --- |
| `scope_status` | Shows the enforced authorization and scope | n/a |
| `recon_dns` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA, SPF and DMARC checks | dig, dnsrecon |
| `recon_whois` | RDAP registration data (registrar, status, dates, nameservers) | whois |
| `recon_tls` | Protocol, cipher, certificate chain facts, expiry, trust | sslscan, sslyze |
| `recon_http_headers` | Security headers, server banner, cookie flags (no body, no redirects) | curl, nikto (headers only), whatweb |
| `recon_port_scan` | Bounded TCP connect scan, no banners, no exploitation | nmap (basic) |
| `github_org_overview` | Public repos, languages, archived/stale repos for an in-scope org | gh |
| `github_repo_overview` | Languages, license, security policy, manifests, CI workflows | gh |
| `github_exposure_scan` | Local checkout scan for leaked credentials, optionally in git history; values are masked and fingerprinted | trufflehog, gitleaks |
| `github_workflow_audit` | GitHub Actions risks: `pull_request_target` misuse, script injection, unpinned actions, broad permissions | n/a |
| `kali_tool_catalog` | Maps common Kali tools to these tools and shows which are installed | n/a |
| `report_export` | Exports all findings from the session as Markdown or JSON | n/a |

Each result carries its `limitations` so a conclusion is never stronger than its evidence.

## What it deliberately does not do

- No exploitation, password guessing, brute forcing, or wireless attacks. Those Kali tools appear in the
  catalog for orientation and are marked "not wrapped by design".
- No profiling of individuals: GitHub tools work on organizations and repositories, never member lists,
  and RDAP output omits registrant and contact details.
- Secret scanning never returns a full secret.

## Register it with your agent

Alongside REA (after `npx rea-agents setup`), add this MCP server to your agent's configuration:

```json
{
  "mcpServers": {
    "rea-osint-recon": {
      "command": "node",
      "args": ["/path/to/rea/extensions/osint-recon/src/server.js"],
      "env": { "OSINT_SCOPE_FILE": "/path/to/osint-scope.json", "GITHUB_TOKEN": "optional, raises API limits" }
    }
  }
}
```

For Claude Code: `claude mcp add rea-osint-recon -e OSINT_SCOPE_FILE=/path/to/osint-scope.json -- node /path/to/rea/extensions/osint-recon/src/server.js`

## Example workflow

1. `scope_status` to confirm what is authorized.
2. `github_org_overview` on your org, then `github_repo_overview` on the interesting repos.
3. Clone a repo you own, then `github_exposure_scan` (with `history_commits`) and `github_workflow_audit`.
4. `recon_dns`, `recon_tls`, `recon_http_headers`, `recon_port_scan` on your domains.
5. `report_export` for a Markdown report.

## Development

```bash
npm test        # node --test, no install needed
```

This package lives in `extensions/` and is independent of REA's tool catalog, so it does not change
REA's generated contracts or catalog digests.
