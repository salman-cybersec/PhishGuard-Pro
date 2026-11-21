"""Passive analysis of publicly exposed website code and language indicators."""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from phishguard.safe_http import fetch_https
from phishguard.technology_detector import detect_technologies


MAX_ASSETS = 12
MAX_ASSET_BYTES = 384_000

CODE_TYPES = {
    "javascript": {
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
    },
    "css": {"text/css"},
}

SOURCE_MAP_PATTERN = re.compile(
    r"(?://[#@]\s*sourceMappingURL=|/\*[#@]\s*sourceMappingURL=)"
    r"\s*([^\s*]+)",
    re.IGNORECASE,
)

CONFIG_REFERENCE_PATTERN = re.compile(
    r"""(?i)(?:["'])([^"'<> ]{1,180}
    (?:\.env(?:\.[a-z0-9_-]+)?|config\.json|settings\.json|
    secrets\.json|credentials\.json))["']""",
    re.VERBOSE,
)

API_REFERENCE_PATTERN = re.compile(
    r"""(?i)["']((?:/api/|/graphql(?:[/?#]|$))[^"' ]{0,160})["']"""
)


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.stylesheets = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.html_language = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag.lower() == "html":
            language = attrs.get("lang")
            if language:
                self.html_language = language[:40]

        elif tag.lower() == "script":
            source = attrs.get("src")
            if source:
                self.scripts.append(source)
            else:
                self.inline_scripts += 1

        elif tag.lower() == "link":
            rel = (attrs.get("rel") or "").lower().split()
            href = attrs.get("href")
            if href and "stylesheet" in rel:
                self.stylesheets.append(href)

        elif tag.lower() == "style":
            self.inline_styles += 1


def _same_host_asset_url(base_url, reference, hostname):
    if not isinstance(reference, str) or not reference.strip():
        return None

    try:
        absolute = urljoin(base_url, reference.strip())
        parsed = urlsplit(absolute)

        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.hostname.lower().rstrip(".") != hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            return None

        return f"https://{hostname}{parsed.path or '/'}" + (
            f"?{parsed.query}" if parsed.query else ""
        )

    except (ValueError, UnicodeError):
        return None


def _content_type(headers):
    return (
        headers.get("Content-Type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )


def _decode_content(content):
    return content.decode("utf-8", errors="replace")


def analyze_code_language(
    url: str,
    hostname: str,
    html_content,
    response_headers,
) -> dict:
    """Inspect HTML and a bounded set of same-host public code assets."""

    if not isinstance(html_content, (bytes, str)):
        raise ValueError("Invalid HTML content.")

    hostname = hostname.lower().rstrip(".")
    html_text = (
        html_content.decode("utf-8", errors="replace")
        if isinstance(html_content, bytes)
        else html_content
    )

    parser = _AssetParser()
    parser.feed(html_text)
    parser.close()

    assets = []
    seen_urls = set()

    for kind, references in (
        ("javascript", parser.scripts),
        ("css", parser.stylesheets),
    ):
        for reference in references:
            asset_url = _same_host_asset_url(url, reference, hostname)

            if not asset_url or asset_url in seen_urls:
                continue

            seen_urls.add(asset_url)
            assets.append({"url": asset_url, "type": kind})

            if len(assets) >= MAX_ASSETS:
                break

        if len(assets) >= MAX_ASSETS:
            break

    asset_results = []
    source_maps = []
    config_references = set()
    api_references = set()
    languages = {}
    errors = []

    if parser.inline_scripts:
        languages["JavaScript"] = {
            "evidence": ["Inline script elements in HTML"]
        }

    if parser.inline_styles:
        languages["CSS"] = {
            "evidence": ["Inline style elements in HTML"]
        }

    if parser.html_language:
        languages["HTML"] = {
            "evidence": [f"HTML lang attribute: {parser.html_language}"]
        }

    for asset in assets:
        try:
            response = fetch_https(
                asset["url"],
                expected_host=hostname,
                max_bytes=MAX_ASSET_BYTES,
            )

            if response["status_code"] != 200:
                asset_results.append({
                    "type": asset["type"],
                    "path": urlsplit(asset["url"]).path,
                    "status": "unavailable",
                })
                continue

            content_type = _content_type(response["headers"])
            allowed = CODE_TYPES[asset["type"]]

            if content_type not in allowed:
                asset_results.append({
                    "type": asset["type"],
                    "path": urlsplit(asset["url"]).path,
                    "status": "skipped",
                    "reason": "Unexpected content type",
                })
                continue

            text = _decode_content(response["content"])

            asset_results.append({
                "type": asset["type"],
                "path": urlsplit(asset["url"]).path,
                "status": "analyzed",
                "size": len(response["content"]),
            })

            language_name = (
                "JavaScript" if asset["type"] == "javascript" else "CSS"
            )
            languages.setdefault(
                language_name, {"evidence": []}
            )["evidence"].append(
                f"Public {asset['type'].upper()} asset"
            )

            for match in SOURCE_MAP_PATTERN.findall(text):
                if match.startswith(("https://", "http://", "//", "data:")):
                    source_maps.append({
                        "asset": urlsplit(asset["url"]).path,
                        "reference": "External or embedded source map reference",
                    })
                else:
                    source_maps.append({
                        "asset": urlsplit(asset["url"]).path,
                        "reference": "Relative source map reference",
                    })

            for match in CONFIG_REFERENCE_PATTERN.findall(text):
                config_references.add(
                    urlsplit(match).path.rsplit("/", 1)[-1][:100]
                )

            for match in API_REFERENCE_PATTERN.findall(text):
                api_references.add(match[:160])

        except (ValueError, RuntimeError, OSError) as error:
            errors.append({
                "asset": urlsplit(asset["url"]).path,
                "error": type(error).__name__,
            })

    technology_analysis = detect_technologies(
        response_headers,
        html_text,
    )

    return {
        "status": "completed",
        "html": {
            "language_attribute": parser.html_language,
            "inline_scripts": parser.inline_scripts,
            "inline_styles": parser.inline_styles,
        },
        "languages": [
            {
                "name": name,
                "evidence": details["evidence"],
            }
            for name, details in sorted(languages.items())
        ],
        "technologies": technology_analysis["technologies"],
        "assets": asset_results,
        "assets_discovered": len(assets),
        "source_map_references": source_maps,
        "configuration_references": sorted(config_references),
        "api_references": sorted(api_references),
        "errors": errors,
        "limits": {
            "maximum_assets": MAX_ASSETS,
            "maximum_asset_bytes": MAX_ASSET_BYTES,
            "external_hosts_fetched": 0,
            "source_code_stored": False,
        },
    }
