from cryptoflow_agent import CryptoFlowAgent, Packet
from cryptoflow_agent.features import extract_flow_features


def test_extract_flow_features_directional_and_statistical_values():
    packets = [
        Packet(1.0, "10.0.0.2", 50000, "93.184.216.34", 443, "TCP", b"a" * 10),
        Packet(1.2, "93.184.216.34", 443, "10.0.0.2", 50000, "TCP", b"b" * 30),
        Packet(1.5, "10.0.0.2", 50000, "93.184.216.34", 443, "TCP", b"c" * 20),
    ]
    flow = CryptoFlowAgent().build_flows(packets)[0]

    features = extract_flow_features(flow)

    assert features["packet_count"] == 3.0
    assert features["byte_count"] == 60.0
    assert features["min_packet_size"] == 10.0
    assert features["max_packet_size"] == 30.0
    assert features["p50_packet_size"] == 20.0
    assert features["forward_packet_count"] == 2.0
    assert features["reverse_packet_count"] == 1.0
    assert features["forward_byte_count"] == 30.0
    assert features["reverse_byte_count"] == 30.0
    assert features["direction_changes"] == 2.0
    assert features["dst_port_well_known"] == 1.0
    assert features["src_port_dynamic"] == 1.0
    assert features["src_ip_is_private"] == 1.0


def test_analyze_packets_includes_expanded_features():
    packet = Packet(
        1.0,
        "10.0.0.2",
        53000,
        "93.184.216.34",
        443,
        "TCP",
        b"\x16\x03\x03\x00\x01x",
    )

    result = CryptoFlowAgent().analyze_packets([packet])[0]

    assert "packet_size_cv" in result.features
    assert "forward_byte_ratio" in result.features
    assert "dst_ip_is_global" in result.features
