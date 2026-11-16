
import pytest

from phishguard import safe_http


def test_private_ip_address_rejected(monkeypatch):
    monkeypatch.setattr(
        safe_http.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("127.0.0.1", 443))
        ],
    )

    with pytest.raises(ValueError):
        safe_http.resolve_public_addresses("example.com")


def test_public_ip_address_accepted(monkeypatch):
    monkeypatch.setattr(
        safe_http.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("8.8.8.8", 443))
        ],
    )

    result = safe_http.resolve_public_addresses("example.com")

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
        safe_http.resolve_public_addresses("example.com")


@pytest.mark.parametrize(
    "url, expected_host",
    [
        ("http://example.com", "example.com"),
        ("https://other.com", "example.com"),
        ("https://user:pass@example.com", "example.com"),
        ("https://example.com:8443", "example.com"),
        ("https://example.com", "other.com"),
    ],
)
def test_invalid_https_urls_rejected(url, expected_host):
    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url=url,
            expected_host=expected_host,
            max_bytes=1000,
        )


@pytest.mark.parametrize(
    "max_bytes",
    [
        0,
        -1,
        True,
        "100",
        None,
    ],
)
def test_invalid_size_limit_rejected(max_bytes):
    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url="https://example.com",
            expected_host="example.com",
            max_bytes=max_bytes,
        )


def test_invalid_expected_hostname_rejected():
    with pytest.raises(ValueError):
        safe_http.fetch_https(
            url="https://example.com",
            expected_host="",
            max_bytes=1000,
        )


def test_response_exceeding_size_limit_rejected(monkeypatch):
    class FakeResponse:
        status = 200
        headers = {
            "Content-Length": "20",
            "Content-Encoding": "identity",
        }

    class FakeConnection:
        def __init__(self, *args, **kwargs):
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
            max_bytes=10,
        )


def test_redirect_is_returned_not_followed(monkeypatch):
    class FakeResponse:
        status = 302
        headers = {
            "Location": "https://other.com",
            "Content-Length": "0",
            "Content-Encoding": "identity",
        }

        def read(self, amount):
            return b""

    class FakeConnection:
        def __init__(self, *args, **kwargs):
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

    result = safe_http.fetch_https(
        url="https://example.com",
        expected_host="example.com",
        max_bytes=1000,
    )

    assert result["status_code"] == 302
    assert result["headers"]["Location"] == "https://other.com"


def test_response_body_size_limit_enforced(monkeypatch):
    class FakeResponse:
        status = 200
        headers = {
            "Content-Length": "2",
            "Content-Encoding": "identity",
        }

        def read(self, amount):
            assert amount == 11
            return b"01234567890"

    class FakeConnection:
        def __init__(self, *args, **kwargs):
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
            max_bytes=10,
        )


def test_compressed_response_rejected(monkeypatch):
    class FakeResponse:
        status = 200
        headers = {
            "Content-Encoding": "gzip",
            "Content-Length": "10",
        }

    class FakeConnection:
        def __init__(self, *args, **kwargs):
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
