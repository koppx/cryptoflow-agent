import json

from cryptoflow_agent.cli import main


def test_cli_json_output(capsys):
    code = main(["examples/sample_packets.jsonl", "--format", "jsonl", "--output", "json"])

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output[0]["encrypted"] is True
    assert output[0]["protocol"] == "tls"


def test_cli_missing_file(capsys):
    code = main(["does-not-exist.jsonl", "--format", "jsonl"])

    assert code == 2
    assert "does-not-exist" in capsys.readouterr().err


def test_cli_csv_output(capsys):
    code = main(
        [
            "examples/sample_packets.jsonl",
            "--format",
            "jsonl",
            "--output",
            "csv",
            "--only-encrypted",
        ]
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "protocol" in out
    assert "tls" in out
    assert "unknown" not in out
