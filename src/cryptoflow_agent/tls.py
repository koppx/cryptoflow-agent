"""Minimal TLS ClientHello metadata extraction.

The parser is intentionally small and defensive. It extracts useful metadata
from a single TLS record when available, without trying to be a complete TLS
implementation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

TLS_HANDSHAKE = 22
CLIENT_HELLO = 1
EXT_SERVER_NAME = 0
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43

TLS_VERSION_NAMES = {
    b"\x03\x00": "SSLv3",
    b"\x03\x01": "TLSv1.0",
    b"\x03\x02": "TLSv1.1",
    b"\x03\x03": "TLSv1.2",
    b"\x03\x04": "TLSv1.3",
}


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _u24(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 3], "big")


def _version_name(raw: bytes) -> str:
    return TLS_VERSION_NAMES.get(raw, raw.hex())


def parse_tls_client_hello(record: bytes) -> Optional[Dict[str, Any]]:
    """Parse basic metadata from a TLS ClientHello record.

    Returns None when the payload is not a complete-enough ClientHello.
    """
    if len(record) < 9 or record[0] != TLS_HANDSHAKE:
        return None

    record_version = record[1:3]
    record_len = _u16(record, 3)
    record_end = min(len(record), 5 + record_len)
    if record_end < 9 or record[5] != CLIENT_HELLO:
        return None

    hello_len = _u24(record, 6)
    hello_start = 9
    hello_end = min(record_end, hello_start + hello_len)
    if hello_end < hello_start + 34:
        return None

    offset = hello_start
    client_version = record[offset : offset + 2]
    offset += 2 + 32  # version + random

    if offset >= hello_end:
        return None
    session_len = record[offset]
    offset += 1 + session_len

    if offset + 2 > hello_end:
        return None
    cipher_len = _u16(record, offset)
    offset += 2 + cipher_len

    if offset >= hello_end:
        return None
    compression_len = record[offset]
    offset += 1 + compression_len

    result: Dict[str, Any] = {
        "record_version": _version_name(record_version),
        "client_version": _version_name(client_version),
    }

    if offset + 2 > hello_end:
        return result

    extensions_len = _u16(record, offset)
    offset += 2
    extensions_end = min(hello_end, offset + extensions_len)

    alpn: List[str] = []
    supported_versions: List[str] = []
    sni: Optional[str] = None

    while offset + 4 <= extensions_end:
        ext_type = _u16(record, offset)
        ext_len = _u16(record, offset + 2)
        offset += 4
        ext_data = record[offset : offset + ext_len]
        offset += ext_len

        if ext_type == EXT_SERVER_NAME and len(ext_data) >= 5:
            list_len = _u16(ext_data, 0)
            pos = 2
            list_end = min(len(ext_data), 2 + list_len)
            while pos + 3 <= list_end:
                name_type = ext_data[pos]
                name_len = _u16(ext_data, pos + 1)
                pos += 3
                name = ext_data[pos : pos + name_len]
                pos += name_len
                if name_type == 0:
                    try:
                        sni = name.decode("idna")
                    except UnicodeError:
                        sni = name.decode("utf-8", errors="replace")
                    break
        elif ext_type == EXT_ALPN and len(ext_data) >= 2:
            list_len = _u16(ext_data, 0)
            pos = 2
            list_end = min(len(ext_data), 2 + list_len)
            while pos < list_end:
                proto_len = ext_data[pos]
                pos += 1
                proto = ext_data[pos : pos + proto_len]
                pos += proto_len
                if proto:
                    alpn.append(proto.decode("ascii", errors="replace"))
        elif ext_type == EXT_SUPPORTED_VERSIONS and ext_data:
            version_len = ext_data[0]
            pos = 1
            end = min(len(ext_data), 1 + version_len)
            while pos + 2 <= end:
                supported_versions.append(_version_name(ext_data[pos : pos + 2]))
                pos += 2

    if sni:
        result["sni"] = sni
    if alpn:
        result["alpn"] = alpn
    if supported_versions:
        result["supported_versions"] = supported_versions
    return result


def first_client_hello_metadata(payloads: List[bytes]) -> Dict[str, Any]:
    """Return metadata from the first parsable ClientHello payload."""
    for payload in payloads:
        metadata = parse_tls_client_hello(payload)
        if metadata:
            return metadata
    return {}
