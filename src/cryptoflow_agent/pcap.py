"""Small PCAP reader for Ethernet/IPv4 TCP and UDP packets.

This parser intentionally supports the common PCAP subset needed for examples
and CI tests. For production capture pipelines, feed Packet objects from a
well-maintained packet library such as Scapy, dpkt, or PyShark.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Iterator, Optional, Union

from .models import Packet

PCAP_MAGIC_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microsecond timestamps
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microsecond timestamps
}

ETHERNET_HEADER_LEN = 14
IPV4_ETHERTYPE = 0x0800
TCP_PROTO = 6
UDP_PROTO = 17


class PcapError(ValueError):
    """Raised when a PCAP file cannot be parsed by the lightweight reader."""


def read_pcap(path: Union[str, Path]) -> Iterator[Packet]:
    """Yield Packet objects from a classic PCAP file."""
    with Path(path).open("rb") as handle:
        magic = handle.read(4)
        endian = PCAP_MAGIC_ENDIAN.get(magic)
        if endian is None:
            raise PcapError("unsupported capture format: expected classic PCAP")

        rest = handle.read(20)
        if len(rest) != 20:
            raise PcapError("truncated PCAP global header")

        pkt_header = struct.Struct(endian + "IIII")
        while True:
            raw_header = handle.read(pkt_header.size)
            if not raw_header:
                break
            if len(raw_header) != pkt_header.size:
                raise PcapError("truncated PCAP packet header")
            ts_sec, ts_usec, incl_len, _orig_len = pkt_header.unpack(raw_header)
            frame = handle.read(incl_len)
            if len(frame) != incl_len:
                raise PcapError("truncated PCAP packet data")
            packet = _parse_ethernet_ipv4(frame, ts_sec + ts_usec / 1_000_000)
            if packet is not None:
                yield packet


def _parse_ethernet_ipv4(frame: bytes, timestamp: float) -> Optional[Packet]:
    if len(frame) < ETHERNET_HEADER_LEN + 20:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != IPV4_ETHERTYPE:
        return None

    ip_offset = ETHERNET_HEADER_LEN
    first = frame[ip_offset]
    version = first >> 4
    ihl = (first & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < ip_offset + ihl:
        return None

    total_len = struct.unpack("!H", frame[ip_offset + 2 : ip_offset + 4])[0]
    proto = frame[ip_offset + 9]
    src_ip = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
    dst_ip = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
    transport_offset = ip_offset + ihl
    ip_end = min(len(frame), ip_offset + total_len)

    if proto == TCP_PROTO:
        if len(frame) < transport_offset + 20:
            return None
        src_port, dst_port = struct.unpack("!HH", frame[transport_offset : transport_offset + 4])
        data_offset = (frame[transport_offset + 12] >> 4) * 4
        payload_offset = transport_offset + data_offset
        if data_offset < 20 or payload_offset > ip_end:
            return None
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            payload=frame[payload_offset:ip_end],
            size=max(0, ip_end - ip_offset),
        )

    if proto == UDP_PROTO:
        if len(frame) < transport_offset + 8:
            return None
        src_port, dst_port, udp_len = struct.unpack(
            "!HHH", frame[transport_offset : transport_offset + 6]
        )
        payload_offset = transport_offset + 8
        udp_end = min(ip_end, transport_offset + udp_len)
        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="UDP",
            payload=frame[payload_offset:udp_end],
            size=max(0, udp_end - ip_offset),
        )

    return None
