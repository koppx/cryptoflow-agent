from cryptoflow_agent.tls import parse_tls_client_hello


def _client_hello() -> bytes:
    body = bytearray()
    body += b"\x03\x03"  # legacy version
    body += b"\x11" * 32
    body += b"\x00"  # session id length
    body += b"\x00\x02\x13\x01"  # cipher suites
    body += b"\x01\x00"  # compression methods

    sni_name = b"example.com"
    sni = b"\x00" + len(sni_name).to_bytes(2, "big") + sni_name
    sni_ext = (
        b"\x00\x00"
        + (len(sni) + 2).to_bytes(2, "big")
        + len(sni).to_bytes(2, "big")
        + sni
    )

    alpn_body = b"\x02h2\x08http/1.1"
    alpn_ext = (
        b"\x00\x10"
        + (len(alpn_body) + 2).to_bytes(2, "big")
        + len(alpn_body).to_bytes(2, "big")
        + alpn_body
    )

    versions = b"\x04\x03\x04\x03\x03"
    versions_ext = b"\x00\x2b" + len(versions).to_bytes(2, "big") + versions

    extensions = sni_ext + alpn_ext + versions_ext
    body += len(extensions).to_bytes(2, "big") + extensions

    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_parse_tls_client_hello_metadata():
    metadata = parse_tls_client_hello(_client_hello())

    assert metadata["sni"] == "example.com"
    assert metadata["alpn"] == ["h2", "http/1.1"]
    assert metadata["supported_versions"] == ["TLSv1.3", "TLSv1.2"]
