import struct

from cryptoflow_agent.pcap import read_pcap


def _tcp_ipv4_frame(payload: bytes) -> bytes:
    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0800)
    total_len = 20 + 20 + len(payload)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", total_len)
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = b"\x0a\x00\x00\x01"
    ip[16:20] = b"\x0a\x00\x00\x02"
    tcp = bytearray(20)
    tcp[0:4] = struct.pack("!HH", 12345, 443)
    tcp[12] = 0x50
    return eth + bytes(ip) + bytes(tcp) + payload


def test_read_pcap_tcp_payload(tmp_path):
    payload = b"\x16\x03\x03\x00\x01x"
    frame = _tcp_ipv4_frame(payload)
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 500000, len(frame), len(frame))
        + frame
    )

    packets = list(read_pcap(pcap))

    assert len(packets) == 1
    assert packets[0].src_ip == "10.0.0.1"
    assert packets[0].dst_port == 443
    assert packets[0].payload == payload
