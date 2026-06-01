"""Minimal Python API example."""

from cryptoflow_agent import CryptoFlowAgent, Packet

packets = [
    Packet(
        timestamp=1.0,
        src_ip="10.0.0.10",
        src_port=54500,
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="TCP",
        payload=b"\x16\x03\x03\x00\x2e" + b"\x00" * 60,
    )
]

agent = CryptoFlowAgent()
for result in agent.analyze_packets(packets):
    print(agent.explain(result))
