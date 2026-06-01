"""Feature extraction for encrypted traffic detection."""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List

from .models import Flow


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte for a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _safe_mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def extract_flow_features(flow: Flow) -> Dict[str, float]:
    """Extract stable, explainable flow features without external dependencies."""
    payloads = list(flow.payloads())
    joined = b"".join(payloads[:20])
    lengths = [packet.length for packet in flow.packets]
    payload_lengths = [len(payload) for payload in payloads]
    timestamps = sorted(packet.timestamp for packet in flow.packets)
    inter_arrival = [b - a for a, b in zip(timestamps, timestamps[1:]) if b >= a]

    printable = 0
    total_payload = sum(payload_lengths)
    if total_payload:
        printable = sum(1 for byte in joined if 32 <= byte <= 126)

    return {
        "packet_count": float(flow.packet_count),
        "byte_count": float(flow.byte_count),
        "duration": float(flow.duration),
        "mean_packet_size": _safe_mean([float(value) for value in lengths]),
        "mean_payload_size": _safe_mean([float(value) for value in payload_lengths]),
        "payload_entropy": shannon_entropy(joined),
        "printable_ratio": float(printable / len(joined)) if joined else 0.0,
        "mean_inter_arrival": _safe_mean(inter_arrival),
        "dst_port": float(flow.key[3]),
        "src_port": float(flow.key[1]),
    }
