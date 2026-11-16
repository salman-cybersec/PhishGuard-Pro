from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from phishguard.website_importer import analyze_website
from phishguard.website_assets import download_asset
from phishguard.website_preview import save_safe_preview


MAX_ASSETS = 30


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag.lower() == "link":
            rel = attributes.get("rel", "").lower().split()
            value = (
                attributes.get("href")
                if "stylesheet" in rel
                else None
            )

        elif tag.lower() == "img":
            value = attributes.get("src")

        else:
            value = None

        if value:
            self.assets.append(value)


def import_website(url: str) -> dict:
    if not isinstance(url, str):
        raise ValueError("Website URL must be a string.")

    parsed = urlsplit(url)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise ValueError("A valid HTTPS website URL is required.")

    html = analyze_website(url)

    if not isinstance(html, str):
        raise ValueError("Website analyzer returned an invalid response.")

    preview = save_safe_preview(html)

    parser = AssetParser()
    parser.feed(html)
    parser.close()

    unique_assets = list(dict.fromkeys(parser.assets))
    selected_assets = unique_assets[:MAX_ASSETS]

    imported_assets = []
    skipped_assets = []

    for reference in selected_assets:
        asset_url = urljoin(url, reference)

        try:
            result = download_asset(
                asset_url,
                parsed.hostname,
            )
            imported_assets.append(result)

        except (ValueError, RuntimeError):
            skipped_assets.append(reference)

    skipped_assets.extend(unique_assets[MAX_ASSETS:])

    return {
        "website": url,
        "page_size": len(html.encode("utf-8")),
        "preview_id": preview["preview_id"],
        "preview_filename": preview["filename"],
        "preview_path": preview["path"],
        "preview_size": preview["size"],
        "preview_status": preview["status"],
        "preview_type": "sanitized_static_html",
        "javascript_executed": False,
        "credentials_collected": False,
        "assets_found": len(parser.assets),
        "unique_assets_found": len(unique_assets),
        "assets_imported": len(imported_assets),
        "assets_skipped": len(skipped_assets),
        "imported_files": imported_assets,
        "skipped_files": skipped_assets,
        "status": "import_completed",
    }
