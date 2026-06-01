.PHONY: test lint smoke

test:
	pytest -q

lint:
	ruff check src tests

smoke:
	PYTHONPATH=src python -m cryptoflow_agent.cli examples/sample_packets.jsonl --format jsonl
