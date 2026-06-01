"""Feature extraction for encrypted traffic detection."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from typing import Dict, List, Tuple

from .models import Flow, Packet

WELL_KNOWN_PORT_MAX = 1023
REGISTERED_PORT_MAX = 49151


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte for a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _safe_mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _safe_min(values: List[float]) -> float:
    return min(values) if values else 0.0


def _safe_max(values: List[float]) -> float:
    return max(values) if values else 0.0


def _safe_stddev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = _safe_mean(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _safe_percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[int(rank)]
    lower = ordered[low] * (high - rank)
    upper = ordered[high] * (rank - low)
    return lower + upper


def _coefficient_of_variation(values: List[float]) -> float:
    mean = _safe_mean(values)
    if mean == 0:
        return 0.0
    return _safe_stddev(values) / mean


def _bytes_per_second(byte_count: float, duration: float) -> float:
    if duration <= 0:
        return 0.0
    return byte_count / duration


def _packets_per_second(packet_count: float, duration: float) -> float:
    if duration <= 0:
        return 0.0
    return packet_count / duration


def _packet_direction(packet: Packet, endpoint_a: Tuple[str, int]) -> int:
    return 1 if (packet.src_ip, int(packet.src_port)) == endpoint_a else -1


def _ip_flags(ip: str) -> Tuple[float, float, float, float]:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return 0.0, 0.0, 0.0, 1.0
    return (
        float(parsed.version == 6),
        float(parsed.is_private),
        float(parsed.is_global),
        0.0,
    )


def _port_class(port: int) -> Tuple[float, float, float]:
    return (
        float(port <= WELL_KNOWN_PORT_MAX),
        float(WELL_KNOWN_PORT_MAX < port <= REGISTERED_PORT_MAX),
        float(port > REGISTERED_PORT_MAX),
    )


def extract_flow_features(flow: Flow) -> Dict[str, float]:
    """Extract stable, explainable flow features without external dependencies."""
    packets = sorted(flow.packets, key=lambda packet: packet.timestamp)
    payloads = [packet.payload for packet in packets if packet.payload]
    joined = b"".join(payloads[:20])
    lengths = [float(packet.length) for packet in packets]
    payload_lengths = [float(len(payload)) for payload in payloads]
    timestamps = [packet.timestamp for packet in packets]
    inter_arrival = [b - a for a, b in zip(timestamps, timestamps[1:]) if b >= a]

    endpoint_a, _endpoint_b = flow.endpoints
    forward_packets = [packet for packet in packets if _packet_direction(packet, endpoint_a) == 1]
    reverse_packets = [packet for packet in packets if _packet_direction(packet, endpoint_a) == -1]
    forward_bytes = float(sum(packet.length for packet in forward_packets))
    reverse_bytes = float(sum(packet.length for packet in reverse_packets))
    forward_payload_bytes = float(sum(len(packet.payload) for packet in forward_packets))
    reverse_payload_bytes = float(sum(len(packet.payload) for packet in reverse_packets))

    printable = 0
    total_payload = sum(payload_lengths)
    if total_payload:
        printable = sum(1 for byte in joined if 32 <= byte <= 126)

    duration = float(flow.duration)
    byte_count = float(flow.byte_count)
    packet_count = float(flow.packet_count)
    total_directional_bytes = forward_bytes + reverse_bytes
    total_directional_packets = len(forward_packets) + len(reverse_packets)
    src_is_ipv6, src_is_private, src_is_global, src_ip_parse_error = _ip_flags(flow.key[0])
    dst_is_ipv6, dst_is_private, dst_is_global, dst_ip_parse_error = _ip_flags(flow.key[2])
    src_well_known, src_registered, src_dynamic = _port_class(flow.key[1])
    dst_well_known, dst_registered, dst_dynamic = _port_class(flow.key[3])

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "mean_packet_size": _safe_mean(lengths),
        "min_packet_size": _safe_min(lengths),
        "max_packet_size": _safe_max(lengths),
        "stddev_packet_size": _safe_stddev(lengths),
        "p25_packet_size": _safe_percentile(lengths, 0.25),
        "p50_packet_size": _safe_percentile(lengths, 0.50),
        "p75_packet_size": _safe_percentile(lengths, 0.75),
        "packet_size_cv": _coefficient_of_variation(lengths),
        "mean_payload_size": _safe_mean(payload_lengths),
        "min_payload_size": _safe_min(payload_lengths),
        "max_payload_size": _safe_max(payload_lengths),
        "stddev_payload_size": _safe_stddev(payload_lengths),
        "payload_bytes": float(total_payload),
        "payload_packet_ratio": float(len(payloads) / len(packets)) if packets else 0.0,
        "payload_entropy": shannon_entropy(joined),
        "printable_ratio": float(printable / len(joined)) if joined else 0.0,
        "mean_inter_arrival": _safe_mean(inter_arrival),
        "min_inter_arrival": _safe_min(inter_arrival),
        "max_inter_arrival": _safe_max(inter_arrival),
        "stddev_inter_arrival": _safe_stddev(inter_arrival),
        "inter_arrival_cv": _coefficient_of_variation(inter_arrival),
        "bytes_per_second": _bytes_per_second(byte_count, duration),
        "packets_per_second": _packets_per_second(packet_count, duration),
        "forward_packet_count": float(len(forward_packets)),
        "reverse_packet_count": float(len(reverse_packets)),
        "forward_byte_count": forward_bytes,
        "reverse_byte_count": reverse_bytes,
        "forward_payload_bytes": forward_payload_bytes,
        "reverse_payload_bytes": reverse_payload_bytes,
        "forward_packet_ratio": (
            float(len(forward_packets) / total_directional_packets)
            if total_directional_packets
            else 0.0
        ),
        "forward_byte_ratio": (
            float(forward_bytes / total_directional_bytes) if total_directional_bytes else 0.0
        ),
        "byte_asymmetry": (
            float(abs(forward_bytes - reverse_bytes) / total_directional_bytes)
            if total_directional_bytes
            else 0.0
        ),
        "packet_asymmetry": (
            float(abs(len(forward_packets) - len(reverse_packets)) / total_directional_packets)
            if total_directional_packets
            else 0.0
        ),
        "direction_changes": float(
            sum(
                1
                for previous, current in zip(packets, packets[1:])
                if _packet_direction(previous, endpoint_a) != _packet_direction(current, endpoint_a)
            )
        ),
        "dst_port": float(flow.key[3]),
        "src_port": float(flow.key[1]),
        "src_port_well_known": src_well_known,
        "src_port_registered": src_registered,
        "src_port_dynamic": src_dynamic,
        "dst_port_well_known": dst_well_known,
        "dst_port_registered": dst_registered,
        "dst_port_dynamic": dst_dynamic,
        "src_ip_is_ipv6": src_is_ipv6,
        "src_ip_is_private": src_is_private,
        "src_ip_is_global": src_is_global,
        "src_ip_parse_error": src_ip_parse_error,
        "dst_ip_is_ipv6": dst_is_ipv6,
        "dst_ip_is_private": dst_is_private,
        "dst_ip_is_global": dst_is_global,
        "dst_ip_parse_error": dst_ip_parse_error,
    }
