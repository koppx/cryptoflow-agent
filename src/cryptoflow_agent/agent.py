"""Encrypted traffic detection agent."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .features import extract_flow_features
from .models import DetectionResult, Flow, Packet
from .signatures import identify_by_signature
from .tls import first_client_hello_metadata


class CryptoFlowAgent:
    """Detect and identify encrypted traffic using signatures plus explainable heuristics.

    The agent is designed as a defensive security component: it summarizes flows,
    flags likely encrypted sessions, and emits human-readable reasons.
    """

    def __init__(self, entropy_threshold: float = 6.6, min_payload_bytes: int = 128) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_payload_bytes = min_payload_bytes

    def build_flows(self, packets: Iterable[Packet]) -> List[Flow]:
        flows: Dict[tuple, Flow] = {}
        for packet in packets:
            key = packet.canonical_key
            if key not in flows:
                flows[key] = Flow(key=key)
            flows[key].add(packet)
        return list(flows.values())

    def analyze_packets(self, packets: Iterable[Packet]) -> List[DetectionResult]:
        return [self.analyze_flow(flow) for flow in self.build_flows(packets)]

    def analyze_flow(self, flow: Flow) -> DetectionResult:
        features = extract_flow_features(flow)
        payloads = list(flow.payloads())
        tls_metadata = first_client_hello_metadata(payloads)
        if tls_metadata:
            features["tls"] = tls_metadata

        protocol, confidence, reasons = identify_by_signature(flow)
        encrypted = protocol is not None

        payload_bytes = sum(len(payload) for payload in payloads)
        entropy = features["payload_entropy"]
        printable_ratio = features["printable_ratio"]

        heuristic_score = 0.0
        heuristic_reasons: List[str] = []
        if payload_bytes >= self.min_payload_bytes and entropy >= self.entropy_threshold:
            heuristic_score += 0.38
            heuristic_reasons.append(f"high payload entropy ({entropy:.2f} bits/byte)")
        if payload_bytes >= self.min_payload_bytes and printable_ratio < 0.25:
            heuristic_score += 0.18
            heuristic_reasons.append(f"low printable byte ratio ({printable_ratio:.2f})")
        if features["packet_count"] >= 3 and features["mean_payload_size"] > 80:
            heuristic_score += 0.08
            heuristic_reasons.append("multiple non-trivial payload packets observed")

        if heuristic_score >= 0.42 and not encrypted:
            encrypted = True
            protocol = "unknown-encrypted"
            confidence = min(0.78, heuristic_score)
            reasons = heuristic_reasons
        elif heuristic_score > 0 and encrypted:
            confidence = min(0.99, confidence + heuristic_score / 3)
            reasons = reasons + heuristic_reasons

        if protocol is None:
            protocol = "unknown"
            reasons = ["no encrypted protocol signature or strong entropy signal observed"]

        return DetectionResult(
            flow_key=flow.key,
            encrypted=encrypted,
            protocol=protocol,
            confidence=confidence,
            reasons=reasons,
            features=features,
        )

    def explain(self, result: DetectionResult) -> str:
        state = "encrypted" if result.encrypted else "not encrypted"
        reason_text = "; ".join(result.reasons)
        return f"{result.protocol} ({state}, confidence={result.confidence:.2f}): {reason_text}"
