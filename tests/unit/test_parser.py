"""Unit tests for Zeek JSON and TSV line parsing."""

from threatsense.ingestion.parser import ZeekParser


def test_parse_valid_json_line():
    parser = ZeekParser()
    json_line = '{"ts": 1697040100.1, "uid": "C01A01", "id.orig_h": "192.168.1.101", "id.orig_p": 49152, "id.resp_h": "10.0.0.10", "id.resp_p": 80, "proto": "tcp", "orig_bytes": 1024, "resp_bytes": 8192}'
    res = parser.parse_line(json_line)
    assert res.success is True
    assert res.event is not None
    assert res.event.src_ip == "192.168.1.101"
    assert res.event.dst_port == 80
    assert res.event.orig_bytes == 1024


def test_parse_nested_dict():
    parser = ZeekParser()
    data = {
        "id": {
            "orig_h": "192.168.1.50",
            "orig_p": 50000,
            "resp_h": "8.8.8.8",
            "resp_p": 53,
        },
        "proto": "udp",
        "duration": 0.05,
    }
    res = parser.parse_dict(data)
    assert res.success is True
    assert res.event.src_ip == "192.168.1.50"
    assert res.event.dst_port == 53
    assert res.event.protocol == "UDP"


def test_parse_malformed_json_graceful_failure():
    parser = ZeekParser()
    res = parser.parse_line('{"ts": 1697040100, "malformed')
    assert res.success is False
    assert "Invalid JSON string" in res.error


def test_parse_comment_line_ignored():
    parser = ZeekParser()
    res = parser.parse_line("#separator \\x09")
    assert res.success is False
    assert "Comment" in res.error
