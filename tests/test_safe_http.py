import socket

import pytest

from phishguard import safe_http


def test_private_ip_address_rejected(monkeypatch):
    monkeypatch.setattr(
        safe_http.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", 443),
            )
        ],
    )

    with pytest.raises(ValueError):
        safe_http.resolve_public_addresses(
            "example.com"
        )


def test_public_ip_address_accepted(monkeypatch):
    monkeypatch.setattr(
        safe_http.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("8.8.8.8", 443),
            )
        ],
    )

    result = safe_http.resolve_public_addresses(
        "example.com"
    )

    assert result == ["8.8.8.8"]


def test_dns_resolution_failure_rejected(monkeypatch):
    def fail_dns(*args, **kwargs):
        raise OSError("DNS failure")

    monkeypatch.setattr(
        safe_http.socket,
        "getaddrinfo",
        fail_dns,
    )

    with pytest.raises(ValueError):
        safe_http.resolve_public_addresses(
            "example.com"
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://another-site.com",
        "https://user:password@example.com",
        "https://example.com:8443",
    ],
)
def test_invalid_url_rejected(url):
    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url=url,
            expected_host="example.com",
            max_bytes=1000,
        )


@pytest.mark.parametrize(
    "max_bytes",
    [
        0,
        -1,
        True,
        "100",
    ],
)
def test_invalid_size_limit_rejected(max_bytes):
    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url="https://example.com",
            expected_host="example.com",
            max_bytes=max_bytes,
        )


def test_fetch_uses_pinned_ip_and_original_host(
    monkeypatch,
):
    captured = {}

    class FakeResponse:
        status = 200

        headers = {
            "Content-Type": "text/html",
            "Content-Encoding": "identity",
            "Content-Length": "5",
        }

        def read(self, size):
            captured["read_size"] = size
            return b"hello"

    class FakeConnection:
        def __init__(self, hostname, pinned_ip):
            captured["hostname"] = hostname
            captured["pinned_ip"] = pinned_ip

        def request(self, method, path, headers):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers

        def getresponse(self):
            return FakeResponse()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(
        safe_http,
        "resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        safe_http,
        "PinnedHTTPSConnection",
        FakeConnection,
    )

    result = safe_http.fetch_https(
        url="https://example.com/training?page=1",
        expected_host="example.com",
        max_bytes=100,
    )

    assert captured["hostname"] == "example.com"
    assert captured["pinned_ip"] == "8.8.8.8"
    assert captured["method"] == "GET"
    assert captured["path"] == "/training?page=1"
    assert captured["headers"]["Host"] == "example.com"
    assert captured["read_size"] == 101
    assert captured["closed"] is True

    assert result["content"] == b"hello"
    assert result["connected_ip"] == "8.8.8.8"


def test_oversized_response_rejected(monkeypatch):
    class FakeResponse:
        status = 200

        headers = {
            "Content-Type": "text/html",
            "Content-Encoding": "identity",
        }

        def read(self, size):
            return b"123456"

    class FakeConnection:
        def __init__(self, hostname, pinned_ip):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        safe_http,
        "resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        safe_http,
        "PinnedHTTPSConnection",
        FakeConnection,
    )

    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url="https://example.com",
            expected_host="example.com",
            max_bytes=5,
        )


def test_compressed_response_rejected(monkeypatch):
    class FakeResponse:
        status = 200

        headers = {
            "Content-Type": "text/html",
            "Content-Encoding": "gzip",
        }

        def read(self, size):
            raise AssertionError(
                "Compressed response must not be read."
            )

    class FakeConnection:
        def __init__(self, hostname, pinned_ip):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        safe_http,
        "resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        safe_http,
        "PinnedHTTPSConnection",
        FakeConnection,
    )

    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url="https://example.com",
            expected_host="example.com",
            max_bytes=100,
        )
