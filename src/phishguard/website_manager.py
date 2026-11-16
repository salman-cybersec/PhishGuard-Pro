
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from phishguard.website_importer import analyze_website
from phishguard.website_assets import download_asset


MAX_ASSETS = 30


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "link":
            rel = attributes.get("rel", "").lower().split()

            if "stylesheet" in rel:
                value = attributes.get("href")

            else:
                value = None

        elif tag == "img":
            value = attributes.get("src")

        else:
            value = None

        if value:
            self.assets.append(value)


def import_website(url: str) -> dict:
    analysis = analyze_website(url)

    original_host = urlsplit(url).hostname

    parser = AssetParser()
    parser.feed(analysis["html"])

    imported_assets = []
    skipped_assets = []

    for asset_reference in parser.assets[:MAX_ASSETS]:
        asset_url = urljoin(url, asset_reference)

        try:
            result = download_asset(
                asset_url,
                original_host,
            )

            imported_assets.append(result)

        except (ValueError, RuntimeError):
            skipped_assets.append(asset_reference)

    return {
        "website": analysis["website"],
        "page_size": analysis["page_size"],
        "assets_found": len(parser.assets),
        "assets_imported": len(imported_assets),
        "assets_skipped": len(skipped_assets),
        "imported_files": imported_assets,
        "skipped_files": skipped_assets,
        "status": "import_completed",
    }
