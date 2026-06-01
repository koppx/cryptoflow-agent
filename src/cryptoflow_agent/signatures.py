"""Protocol signatures for common encrypted protocols."""

from __future__ import annotations

from typing import List, Optional, Tuple

from .models import Flow

TLS_CONTENT_TYPES = {20, 21, 22, 23}
TLS_VERSIONS = {b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"}
TLS_PORTS = {443, 465, 563, 587, 636, 853, 989, 990, 993, 995, 8443}
QUIC_PORTS = {443, 784, 853, 8853}
SSH_PORTS = {22, 2222}


def _ports(flow: Flow) -> set[int]:
    return {flow.key[1], flow.key[3]}


def looks_like_tls_record(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    return payload[0] in TLS_CONTENT_TYPES and payload[1:3] in TLS_VERSIONS


def looks_like_quic_initial(payload: bytes) -> bool:
    # QUIC long header: header form bit set. This is intentionally conservative.
    if len(payload) < 6:
        return False
    first = payload[0]
    version = payload[1:5]
    return bool(first & 0x80) and version != b"\x00\x00\x00\x00"


def identify_by_signature(flow: Flow) -> Tuple[Optional[str], float, List[str]]:
    """Identify encrypted protocol from payload signatures and well-known ports."""
    reasons: List[str] = []
    payloads = list(flow.payloads())[:10]
    ports = _ports(flow)

    if any(payload.startswith(b"SSH-") for payload in payloads):
        return "ssh", 0.98, ["SSH banner observed"]

    if any(looks_like_tls_record(payload) for payload in payloads):
        confidence = 0.95 if ports & TLS_PORTS else 0.88
        reasons.append("TLS record header observed")
        if ports & TLS_PORTS:
            reasons.append("well-known TLS port observed")
        return "tls", confidence, reasons

    if flow.protocol == "UDP" and any(looks_like_quic_initial(payload) for payload in payloads):
        confidence = 0.92 if ports & QUIC_PORTS else 0.82
        reasons.append("QUIC long-header packet observed")
        if ports & QUIC_PORTS:
            reasons.append("well-known QUIC port observed")
        return "quic", confidence, reasons

    if ports & SSH_PORTS:
        return "ssh-like", 0.62, ["SSH well-known port observed"]

    if ports & TLS_PORTS:
        return "tls-like", 0.58, ["TLS well-known port observed"]

    if flow.protocol == "UDP" and ports & QUIC_PORTS:
        return "quic-like", 0.55, ["QUIC well-known UDP port observed"]

    return None, 0.0, []
