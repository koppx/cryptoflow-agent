# Weekly Maintenance Plan

This repository is configured for weekly maintenance on Mondays.

## Automated tasks

- GitHub Actions `weekly-maintenance` runs every Monday at 10:00 Asia/Shanghai.
- The workflow runs lint, tests, and CLI smoke checks.
- If weekly maintenance fails, it opens a GitHub issue with a triage checklist.
- Dependabot checks Python and GitHub Actions dependencies every Monday.

## Manual weekly review checklist

1. Review Dependabot pull requests.
2. Check CI failures and newly opened maintenance issues.
3. Review false-positive or false-negative reports from users.
4. Add new protocol fixtures only when they are synthetic or sanitized.
5. Update the roadmap if a limitation becomes operationally important.

## Optimization backlog

High priority:

- Add PCAPNG support.
- Add IPv6 and VLAN support in the built-in parser.
- Add Zeek `conn.log` and `ssl.log` importers.
- Add more robust TLS handshake reassembly across multiple TCP packets.

Medium priority:

- Add JA3/JA4-style TLS fingerprint fields when complete handshakes are available.
- Add QUIC version and ALPN extraction.
- Add allowlist and suppression rules for known internal services.
- Add a streaming JSONL mode for long-running pipelines.

Low priority:

- Add optional ML model training examples under the `ml` extra.
- Add packaged sample dashboards for CSV/JSON reports.
- Publish signed releases after the first stable API milestone.
