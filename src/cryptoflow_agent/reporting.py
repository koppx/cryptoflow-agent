"""Report rendering helpers."""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable, List

from .models import DetectionResult


def results_to_json(results: Iterable[DetectionResult], indent: int = 2) -> str:
    """Render results as JSON."""
    return json.dumps([result.as_dict() for result in results], indent=indent, sort_keys=True)


def results_to_csv(results: Iterable[DetectionResult]) -> str:
    """Render results as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "encrypted",
            "protocol",
            "confidence",
            "transport",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "packet_count",
            "byte_count",
            "payload_entropy",
            "reasons",
        ],
    )
    writer.writeheader()
    for result in results:
        src_ip, src_port, dst_ip, dst_port, transport = result.flow_key
        writer.writerow(
            {
                "encrypted": result.encrypted,
                "protocol": result.protocol,
                "confidence": f"{result.confidence:.4f}",
                "transport": transport,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_count": int(result.features.get("packet_count", 0)),
                "byte_count": int(result.features.get("byte_count", 0)),
                "payload_entropy": f"{float(result.features.get('payload_entropy', 0.0)):.4f}",
                "reasons": "; ".join(result.reasons),
            }
        )
    return output.getvalue()


def results_to_table(results: List[DetectionResult]) -> str:
    """Render results as a human-readable table."""
    lines = []
    header = f"{'encrypted':<10} {'protocol':<18} {'confidence':<10} flow"
    lines.append(header)
    lines.append("-" * len(header))
    for result in results:
        src_ip, src_port, dst_ip, dst_port, proto = result.flow_key
        flow = f"{proto} {src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
        lines.append(f"{str(result.encrypted):<10} {result.protocol:<18} {result.confidence:<10.2f} {flow}")
        for reason in result.reasons:
            lines.append(f"  - {reason}")
    return "\n".join(lines)
