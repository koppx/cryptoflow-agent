import csv
import io
import json

from cryptoflow_agent import CryptoFlowAgent, Packet
from cryptoflow_agent.reporting import results_to_csv, results_to_json, results_to_table


def _result():
    packet = Packet(1.0, "10.0.0.1", 12345, "10.0.0.2", 443, "TCP", b"\x16\x03\x03\x00\x01x")
    return CryptoFlowAgent().analyze_packets([packet])[0]


def test_results_to_json():
    data = json.loads(results_to_json([_result()]))

    assert data[0]["protocol"] == "tls"


def test_results_to_csv():
    rows = list(csv.DictReader(io.StringIO(results_to_csv([_result()]))))

    assert rows[0]["protocol"] == "tls"
    assert rows[0]["encrypted"] == "True"


def test_results_to_table():
    table = results_to_table([_result()])

    assert "tls" in table
    assert "TLS record header observed" in table
