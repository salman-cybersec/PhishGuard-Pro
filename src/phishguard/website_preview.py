from html.parser import HTMLParser
from html import escape
from pathlib import Path
import secrets

from phishguard.config import DATA_DIR


MAX_HTML_SIZE = 2 * 1024 * 1024
PREVIEW_DIR = DATA_DIR / "website_previews"

ALLOWED_TAGS = {
    "html", "head", "body", "title",
    "main", "header", "footer", "section",
    "article", "div", "span", "p",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "strong", "b", "em", "i", "u",
    "br", "hr",
    "table", "thead", "tbody", "tr", "th", "td",
    "img",
}

VOID_TAGS = {"br", "hr", "img"}

BLOCKED_CONTENT_TAGS = {
    "script", "style", "iframe", "frame",
    "frameset", "object", "embed", "form",
    "svg", "math", "template", "noscript",
}

ALLOWED_ATTRIBUTES = {
    "class", "id", "title", "alt",
    "width", "height", "colspan", "rowspan",
}


class WebsiteSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.blocked_stack = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if self.blocked_stack:
            if tag in BLOCKED_CONTENT_TAGS:
                self.blocked_stack.append(tag)
            return

        if tag in BLOCKED_CONTENT_TAGS:
            self.blocked_stack.append(tag)
            return

        if tag not in ALLOWED_TAGS:
            return

        safe_attributes = []

        for name, value in attrs:
            name = name.lower()

            if value is None or name not in ALLOWED_ATTRIBUTES:
                continue

            safe_attributes.append(
                f'{name}="{escape(value, quote=True)}"'
            )

        attributes = ""

        if safe_attributes:
            attributes = " " + " ".join(safe_attributes)

        self.output.append(f"<{tag}{attributes}>")

    def handle_endtag(self, tag):
        tag = tag.lower()

        if self.blocked_stack:
            if tag == self.blocked_stack[-1]:
                self.blocked_stack.pop()
            return

        if tag in ALLOWED_TAGS and tag not in VOID_TAGS:
            self.output.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.blocked_stack:
            self.output.append(escape(data))

    def get_html(self):
        return "".join(self.output)


def create_safe_preview(html: str) -> str:
    if not isinstance(html, str):
        raise ValueError("HTML content must be a string.")

    if len(html.encode("utf-8")) > MAX_HTML_SIZE:
        raise ValueError("HTML preview exceeds the 2 MB limit.")

    sanitizer = WebsiteSanitizer()
    sanitizer.feed(html)
    sanitizer.close()

    safe_content = sanitizer.get_html()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorized Security Awareness Preview</title>
</head>
<body>
<div style="padding:14px;background:#fff3cd;color:#664d03;
font-family:Arial,sans-serif;text-align:center;">
<strong>AUTHORIZED SECURITY AWARENESS SIMULATION</strong>
<br>
This is a sanitized static preview. No passwords or credentials
are collected.
</div>
{safe_content}
</body>
</html>"""


def save_safe_preview(html: str) -> dict:
    safe_html = create_safe_preview(html)

    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)

    preview_id = secrets.token_urlsafe(18)
    filename = f"{preview_id}.html"

    output_path = (PREVIEW_DIR / filename).resolve()
    safe_directory = PREVIEW_DIR.resolve()

    if output_path.parent != safe_directory:
        raise ValueError("Invalid preview output path.")

    output_path.write_text(
        safe_html,
        encoding="utf-8",
    )

    return {
        "preview_id": preview_id,
        "filename": filename,
        "path": str(output_path),
        "size": len(safe_html.encode("utf-8")),
        "status": "saved",
    }
