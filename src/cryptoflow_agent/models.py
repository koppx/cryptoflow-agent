"""Core data models used by cryptoflow-agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

FlowKey = Tuple[str, int, str, int, str]


@dataclass(frozen=True)
class Packet:
    """A minimal packet representation independent of packet-capture libraries."""

    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    payload: bytes = b""
    size: Optional[int] = None

    @property
    def length(self) -> int:
        """Return packet length, preferring explicit on-wire size when supplied."""
        return int(self.size if self.size is not None else len(self.payload))

    @property
    def canonical_key(self) -> FlowKey:
        """Return a direction-independent 5-tuple key."""
        proto = self.protocol.upper()
        left = (self.src_ip, int(self.src_port))
        right = (self.dst_ip, int(self.dst_port))
        if left <= right:
            return (left[0], left[1], right[0], right[1], proto)
        return (right[0], right[1], left[0], left[1], proto)


@dataclass
class Flow:
    """Bidirectional network flow."""

    key: FlowKey
    packets: List[Packet] = field(default_factory=list)

    def add(self, packet: Packet) -> None:
        self.packets.append(packet)

    @property
    def protocol(self) -> str:
        return self.key[4]

    @property
    def endpoints(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        return (self.key[0], self.key[1]), (self.key[2], self.key[3])

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def byte_count(self) -> int:
        return sum(packet.length for packet in self.packets)

    @property
    def duration(self) -> float:
        if len(self.packets) < 2:
            return 0.0
        timestamps = [packet.timestamp for packet in self.packets]
        return max(timestamps) - min(timestamps)

    def payloads(self) -> Iterable[bytes]:
        for packet in self.packets:
            if packet.payload:
                yield packet.payload


@dataclass(frozen=True)
class DetectionResult:
    """Classification output for a flow."""

    flow_key: FlowKey
    encrypted: bool
    protocol: str
    confidence: float
    reasons: List[str]
    features: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "flow_key": list(self.flow_key),
            "encrypted": self.encrypted,
            "protocol": self.protocol,
            "confidence": round(float(self.confidence), 4),
            "reasons": list(self.reasons),
            "features": self.features,
        }
