"""Import helpers for common security event formats."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Iterable, TextIO, Union

from .models import Packet


def load_suricata_eve_jsonl(path: Union[str, Path]) -> Iterable[Packet]:
    """Load packets or flows from Suricata EVE JSONL.

    EVE events usually do not include raw payloads unless configured. When no
    payload is present, the agent can still use ports and flow metadata, but
    signatures that require payload bytes will be unavailable.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        yield from iter_suricata_eve_jsonl(handle)


def iter_suricata_eve_jsonl(handle: TextIO) -> Iterable[Packet]:
    for line_number, line in enumerate(handle, 1):
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        src_ip = item.get("src_ip")
        dst_ip = item.get("dest_ip") or item.get("dst_ip")
        src_port = item.get("src_port", 0)
        dst_port = item.get("dest_port", item.get("dst_port", 0))
        proto = str(item.get("proto", item.get("protocol", "TCP"))).upper()
        timestamp = item.get("timestamp")
        payload = _payload_from_eve(item)
        size = None
        if isinstance(item.get("flow"), dict):
            size = item["flow"].get("bytes_toserver") or item["flow"].get("bytes_toclient")
        if not src_ip or not dst_ip:
            continue
        yield Packet(
            timestamp=float(
                line_number if timestamp is None else _timestamp_to_float(timestamp, line_number)
            ),
            src_ip=str(src_ip),
            src_port=int(src_port or 0),
            dst_ip=str(dst_ip),
            dst_port=int(dst_port or 0),
            protocol=proto,
            payload=payload,
            size=size,
        )


def _payload_from_eve(item: dict) -> bytes:
    payload = item.get("payload")
    if isinstance(payload, str):
        try:
            return base64.b64decode(payload, validate=True)
        except ValueError:
            return payload.encode()
    printable = item.get("payload_printable")
    if isinstance(printable, str):
        return printable.encode()
    return b""


def _timestamp_to_float(value: object, fallback: int) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    # Keep timestamp parsing dependency-free. ISO-8601 strings get stable order
    # from line number; packet timing is not critical for protocol signatures.
    return float(fallback)
