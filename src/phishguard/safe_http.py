import http.client
import ipaddress
import socket
import ssl

from urllib.parse import urlsplit


REQUEST_TIMEOUT = 10
USER_AGENT = "PhishGuard-Pro-Authorized-Lab/0.1"


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, pinned_ip, timeout=REQUEST_TIMEOUT):
        context = ssl.create_default_context()

        super().__init__(
            hostname,
            port=443,
            timeout=timeout,
            context=context,
        )

        self.pinned_ip = pinned_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise


def resolve_public_addresses(hostname: str) -> list:
    try:
        results = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as error:
        raise ValueError(
            "Website hostname could not be resolved."
        ) from error

    addresses = []

    for result in results:
        try:
            address = ipaddress.ip_address(result[4][0])
        except ValueError as error:
            raise ValueError(
                "Invalid DNS address returned."
            ) from error

        if not address.is_global:
            raise ValueError(
                "Private or non-public IP addresses are blocked."
            )

        normalized = str(address)

        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise ValueError(
            "No public IP addresses were found."
        )

    return addresses


def fetch_https(
    url: str,
    expected_host: str,
    max_bytes: int,
) -> dict:

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    if not isinstance(expected_host, str) or not expected_host:
        raise ValueError("Expected hostname is required.")

    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < 1
    ):
        raise ValueError("Invalid response size limit.")

    try:
        parsed = urlsplit(url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.hostname.lower().rstrip(".")
            != expected_host.lower().rstrip(".")
        ):
            raise ValueError("Invalid authorized HTTPS URL.")

        hostname = parsed.hostname.lower().rstrip(".")

        if parsed.fragment:
            url = url.split("#", 1)[0]

        addresses = resolve_public_addresses(hostname)

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

    except (ValueError, UnicodeError) as error:
        raise ValueError(
            "Website URL validation failed."
        ) from error

    last_error = None

    for pinned_ip in addresses:
        connection = PinnedHTTPSConnection(
            hostname,
            pinned_ip,
        )

        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": hostname,
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html, text/css, image/*",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )

            response = connection.getresponse()

            headers = response.headers

            content_encoding = (
                headers.get("Content-Encoding", "identity")
                .strip()
                .lower()
            )

            if content_encoding not in {"", "identity"}:
                raise ValueError(
                    "Compressed responses are not accepted."
                )

            content_length = headers.get("Content-Length")

            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        "Invalid response Content-Length."
                    ) from error

                if declared_size < 0:
                    raise ValueError(
                        "Invalid response Content-Length."
                    )

                if declared_size > max_bytes:
                    raise ValueError(
                        "Website response exceeds the size limit."
                    )

            content = response.read(max_bytes + 1)

            if len(content) > max_bytes:
                raise ValueError(
                    "Website response exceeds the size limit."
                )

            return {
                "status_code": response.status,
                "headers": headers,
                "content": content,
                "connected_ip": pinned_ip,
            }

        except ValueError:
            raise

        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as error:
            last_error = error

        finally:
            connection.close()

    raise RuntimeError(
        "Unable to establish a secure connection to the website."
    ) from last_error
