
from html.parser import HTMLParser
from html import escape


BLOCKED_TAGS = {
    "script",
    "iframe",
    "frame",
    "frameset",
    "object",
    "embed",
    "form",
    "base",
}


VOID_TAGS = {
    "area",
    "br",
    "col",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


ALLOWED_URL_ATTRIBUTES = {
    "href",
    "src",
}


class WebsiteSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.blocked_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if self.blocked_depth:
            if tag in BLOCKED_TAGS:
                self.blocked_depth += 1
            return

        if tag in BLOCKED_TAGS:
            self.blocked_depth = 1
            return

        safe_attributes = []

        for name, value in attrs:
            name = name.lower()

            if value is None:
                continue

            if name.startswith("on"):
                continue

            if name in {"style", "srcdoc"}:
                continue

            if name in ALLOWED_URL_ATTRIBUTES:
                normalized = value.strip().lower()

                if normalized.startswith(
                    ("javascript:", "data:", "vbscript:")
                ):
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

        if self.blocked_depth:
            if tag in BLOCKED_TAGS:
                self.blocked_depth -= 1
            return

        if tag not in VOID_TAGS and tag not in BLOCKED_TAGS:
            self.output.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.blocked_depth:
            self.output.append(escape(data))

    def get_html(self):
        return "".join(self.output)


def create_safe_preview(html: str) -> str:
    if not isinstance(html, str):
        raise ValueError("HTML content must be a string.")

    if len(html.encode("utf-8")) > 2 * 1024 * 1024:
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
