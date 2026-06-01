# Usage Guide

## Input options

CryptoFlow Agent supports two input paths:

1. Classic PCAP files containing Ethernet/IPv4 TCP or UDP packets.
2. JSONL packet summaries for pipeline integration.
3. Suricata EVE JSONL for IDS pipeline integration.

For large production pipelines, convert events from Zeek, Suricata, a packet broker, or an internal collector into the JSONL schema described in the README.

## Tuning

The default entropy heuristic is intentionally conservative:

```bash
cryptoflow-agent traffic.jsonl --format jsonl --entropy-threshold 6.6 --min-payload-bytes 128
```

Lower the entropy threshold only when you can tolerate more false positives. Increase `--min-payload-bytes` when your environment has many tiny binary control messages.

## Interpreting confidence

- `0.90+`: strong signature match, such as TLS record header or SSH banner.
- `0.55-0.89`: port-based or heuristic evidence; inspect reasons.
- `<0.55`: weak evidence; usually not labeled encrypted unless additional signals exist.

## Operational recommendations

- Run on authorized captures only.
- Store JSON reports separately from raw packet data.
- Use allowlists for expected encrypted services before alerting on unknown encrypted flows.
- Review false positives after major application or protocol changes.

## Suricata EVE JSONL

```bash
cryptoflow-agent eve.json --format eve --output json
```

When EVE events include `payload` as base64 or `payload_printable`, CryptoFlow Agent uses those bytes for signatures. Without payload fields, detection falls back to ports and flow metadata.

## TLS metadata

When a TLS ClientHello record is present in packet payloads, JSON output includes a nested `features.tls` object with fields such as `sni`, `alpn`, `client_version`, `record_version`, and `supported_versions`.
