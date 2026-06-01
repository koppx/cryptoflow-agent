# Contributing

Thanks for helping improve CryptoFlow Agent.

## Development setup

```bash
python -m pip install -e '.[dev]'
ruff check src tests
pytest -q
```

The core runtime intentionally has no mandatory third-party dependencies. Please keep new dependencies optional unless they are essential.

## Pull request guidelines

- Keep changes focused and explain the detection impact.
- Add tests for new signatures, features, parsers, and edge cases.
- Avoid committing packet captures that contain sensitive or private network data.
- Prefer synthetic fixtures or heavily sanitized captures.
- Document false-positive and false-negative tradeoffs for detection changes.

## Detection philosophy

CryptoFlow Agent should be:

- defensive and privacy-conscious;
- explainable by default;
- conservative when confidence is low;
- useful without decrypting traffic or handling secrets.
