from cryptoflow_agent import CryptoFlowAgent, Packet


def test_detects_tls_from_record_header():
    packets = [
        Packet(
            timestamp=1.0,
            src_ip="10.0.0.2",
            src_port=53000,
            dst_ip="93.184.216.34",
            dst_port=443,
            protocol="TCP",
            payload=b"\x16\x03\x01\x00.\x01" + b"\x00" * 80,
        )
    ]

    result = CryptoFlowAgent().analyze_packets(packets)[0]

    assert result.encrypted is True
    assert result.protocol == "tls"
    assert result.confidence >= 0.9


def test_detects_ssh_banner():
    packet = Packet(
        timestamp=1.0,
        src_ip="10.0.0.2",
        src_port=52000,
        dst_ip="10.0.0.3",
        dst_port=22,
        protocol="TCP",
        payload=b"SSH-2.0-OpenSSH_9.0\r\n",
    )

    result = CryptoFlowAgent().analyze_packets([packet])[0]

    assert result.encrypted is True
    assert result.protocol == "ssh"


def test_unknown_plaintext_is_not_encrypted():
    packet = Packet(
        timestamp=1.0,
        src_ip="10.0.0.2",
        src_port=52000,
        dst_ip="10.0.0.3",
        dst_port=80,
        protocol="TCP",
        payload=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )

    result = CryptoFlowAgent().analyze_packets([packet])[0]

    assert result.encrypted is False
    assert result.protocol == "unknown"


def test_groups_bidirectional_packets_into_one_flow():
    packets = [
        Packet(1.0, "10.0.0.2", 1111, "10.0.0.3", 443, "TCP", b"\x16\x03\x03\x00\x01x"),
        Packet(1.1, "10.0.0.3", 443, "10.0.0.2", 1111, "TCP", b"\x17\x03\x03\x00\x01y"),
    ]

    flows = CryptoFlowAgent().build_flows(packets)

    assert len(flows) == 1
    assert flows[0].packet_count == 2
