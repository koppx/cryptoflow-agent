# Detection Notes

CryptoFlow Agent combines deterministic protocol signatures with conservative heuristics.

## Strong signatures

- TLS: record content type plus TLS version bytes. ClientHello metadata extraction can add SNI, ALPN, and supported TLS versions.
- SSH: plaintext SSH protocol banner.
- QUIC: UDP long-header shape with a non-zero version field.

## Weak indicators

- Well-known encrypted service ports.
- High payload entropy over a minimum payload size.
- Low printable byte ratio.
- Multiple non-trivial payload packets.
- Directional asymmetry, direction changes, flow rate, and inter-arrival timing.
- Endpoint context such as private/global IP scope and well-known/registered/dynamic ports.

Weak indicators are useful for triage but can produce false positives for compressed, binary, or proprietary protocols. They should not be treated as proof of encryption without additional context.

## Known limitations

- The built-in PCAP parser supports classic PCAP, Ethernet, IPv4, TCP, and UDP only.
- PCAPNG, IPv6, VLAN tags, fragmented IP packets, and full TLS fingerprinting are future work.
- The agent does not decrypt traffic and cannot identify application-layer content inside encryption.

## Flow feature groups

The extractor emits these feature families for each bidirectional flow:

- Volume: packet and byte counters.
- Size distribution: min, max, mean, standard deviation, percentiles, and coefficient of variation.
- Timing: duration, inter-arrival statistics, bytes per second, and packets per second.
- Directionality: forward/reverse counters, ratios, asymmetry, and direction changes.
- Endpoint context: port class and IP scope flags.
- Payload shape: entropy and printable byte ratio.

These features are intentionally numeric and JSON/CSV-friendly so they can feed SIEM rules, notebooks, dashboards, or optional ML experiments.
