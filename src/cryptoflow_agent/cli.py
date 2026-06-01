"""Command-line interface for cryptoflow-agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional, TextIO, Union

from .agent import CryptoFlowAgent
from .importers import load_suricata_eve_jsonl
from .models import DetectionResult, Packet
from .pcap import PcapError, read_pcap
from .reporting import results_to_csv, results_to_json, results_to_table


def _iter_jsonl(handle: TextIO) -> Iterable[Packet]:
    for line_number, line in enumerate(handle, 1):
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        payload = item.get("payload", "")
        if isinstance(payload, str):
            payload_bytes = (
                bytes.fromhex(payload)
                if item.get("payload_encoding") == "hex"
                else payload.encode()
            )
        else:
            payload_bytes = bytes(payload)
        yield Packet(
            timestamp=float(item.get("timestamp", line_number)),
            src_ip=str(item["src_ip"]),
            src_port=int(item["src_port"]),
            dst_ip=str(item["dst_ip"]),
            dst_port=int(item["dst_port"]),
            protocol=str(item.get("protocol", "TCP")).upper(),
            payload=payload_bytes,
            size=item.get("size"),
        )


def _load_jsonl(path: Union[str, Path]) -> Iterable[Packet]:
    with Path(path).open("r", encoding="utf-8") as handle:
        yield from _iter_jsonl(handle)


def _load_stdin_jsonl() -> Iterable[Packet]:
    yield from _iter_jsonl(sys.stdin)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoflow-agent",
        description="Detect and identify encrypted traffic from PCAP or JSONL packet summaries.",
    )
    parser.add_argument(
        "input", help="Path to .pcap/.jsonl/.eve.json input, or '-' for JSONL stdin"
    )
    parser.add_argument(
        "--format",
        choices=["auto", "pcap", "jsonl", "eve"],
        default="auto",
        help="Input format. Default: auto based on suffix.",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument("--json", action="store_true", help="Deprecated alias for --output json")
    parser.add_argument(
        "--only-encrypted",
        action="store_true",
        help="Only show flows classified as encrypted.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only show flows with confidence greater than or equal to this value.",
    )
    parser.add_argument("--entropy-threshold", type=float, default=6.6)
    parser.add_argument("--min-payload-bytes", type=int, default=128)
    return parser


def _detect_format(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        name = path.name.lower()
        if "eve" in name:
            return "eve"
        return "jsonl"
    return "pcap"


def _filter_results(
    results: List[DetectionResult], only_encrypted: bool, min_confidence: float
) -> List[DetectionResult]:
    filtered = [result for result in results if result.confidence >= min_confidence]
    if only_encrypted:
        filtered = [result for result in filtered if result.encrypted]
    return filtered


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.input)
    output_format = "json" if args.json else args.output
    agent = CryptoFlowAgent(
        entropy_threshold=args.entropy_threshold,
        min_payload_bytes=args.min_payload_bytes,
    )

    try:
        if args.input == "-":
            if args.format == "pcap":
                raise ValueError("stdin input only supports JSONL")
            packets = _load_stdin_jsonl()
        else:
            input_format = _detect_format(path, args.format)
            packets = (
                _load_jsonl(path)
                if input_format == "jsonl"
                else load_suricata_eve_jsonl(path)
                if input_format == "eve"
                else read_pcap(path)
            )
        results = agent.analyze_packets(packets)
        results = _filter_results(results, args.only_encrypted, args.min_confidence)
    except (OSError, json.JSONDecodeError, KeyError, ValueError, PcapError) as exc:
        print(f"cryptoflow-agent: {exc}", file=sys.stderr)
        return 2

    if output_format == "json":
        print(results_to_json(results))
    elif output_format == "csv":
        print(results_to_csv(results), end="")
    else:
        print(results_to_table(results))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
