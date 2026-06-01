from io import StringIO

from cryptoflow_agent.importers import iter_suricata_eve_jsonl


def test_iter_suricata_eve_jsonl_payload_printable():
    data = StringIO(
        '{"src_ip":"1.1.1.1","src_port":1,"dest_ip":"2.2.2.2",'
        '"dest_port":443,"proto":"TCP","payload_printable":"hello"}\n'
    )

    packet = list(iter_suricata_eve_jsonl(data))[0]

    assert packet.src_ip == "1.1.1.1"
    assert packet.dst_port == 443
    assert packet.payload == b"hello"
