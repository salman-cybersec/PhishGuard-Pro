
import re

import tinycss2


MAX_CSS_SIZE = 1_000_000

ALLOWED_PROPERTIES = {
    "color",
    "background-color",
    "font-size",
    "font-family",
    "font-weight",
    "font-style",
    "text-align",
    "text-decoration",
    "text-transform",
    "line-height",
    "letter-spacing",
    "word-spacing",
    "white-space",
    "width",
    "max-width",
    "min-width",
    "height",
    "max-height",
    "min-height",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-width",
    "border-style",
    "border-color",
    "border-radius",
    "display",
    "flex",
    "flex-direction",
    "flex-wrap",
    "justify-content",
    "align-items",
    "gap",
    "grid-template-columns",
    "grid-template-rows",
    "overflow",
    "overflow-wrap",
    "box-sizing",
    "vertical-align",
    "list-style",
    "list-style-type",
    "opacity",
    "cursor",
}

UNSAFE_VALUE_PATTERN = re.compile(
    r"(expression\s*\(|javascript\s*:|behavior\s*:|"
    r"-moz-binding|@import|url\s*\()",
    re.IGNORECASE,
)

SAFE_SCOPE_PATTERN = re.compile(
    r"^\.[a-zA-Z_][a-zA-Z0-9_-]*$"
)


def _validate_css(css):
    if not isinstance(css, str):
        raise ValueError("CSS input must be a string.")

    if len(css.encode("utf-8")) > MAX_CSS_SIZE:
        raise ValueError("CSS exceeds the maximum size.")

    if "\x00" in css:
        raise ValueError("CSS contains invalid characters.")


def _safe_declaration(declaration):
    if declaration.type != "declaration":
        return None

    name = declaration.lower_name

    if name not in ALLOWED_PROPERTIES:
        return None

    if declaration.important:
        return None

    value = tinycss2.serialize(
        declaration.value
    ).strip()

    if not value:
        return None

    if UNSAFE_VALUE_PATTERN.search(value):
        return None

    if any(
        token.type == "error"
        for token in declaration.value
    ):
        return None

    return f"{name}: {value}"


def sanitize_css(css):
    _validate_css(css)

    if not css.strip():
        return ""

    rules = tinycss2.parse_stylesheet(
        css,
        skip_comments=True,
        skip_whitespace=True,
    )

    output = []

    for rule in rules:
        if rule.type != "qualified-rule":
            continue

        selector = tinycss2.serialize(
            rule.prelude
        ).strip()

        if not selector:
            continue

        if any(
            token.type == "error"
            for token in rule.prelude
        ):
            continue

        declarations = tinycss2.parse_declaration_list(
            rule.content,
            skip_comments=True,
            skip_whitespace=True,
        )

        safe_declarations = []

        for declaration in declarations:
            safe = _safe_declaration(declaration)

            if safe:
                safe_declarations.append(safe)

        if safe_declarations:
            output.append(
                f"{selector} {{ "
                + "; ".join(safe_declarations)
                + "; }"
            )

    return "\n".join(output)


def _split_selectors(tokens):
    selectors = []
    current = []

    for token in tokens:
        if token.type == "literal" and token.value == ",":
            value = tinycss2.serialize(current).strip()

            if value:
                selectors.append(value)

            current = []
        else:
            current.append(token)

    value = tinycss2.serialize(current).strip()

    if value:
        selectors.append(value)

    return selectors


def scope_css(css, scope=".phishguard-preview"):
    _validate_css(css)

    if (
        not isinstance(scope, str)
        or not SAFE_SCOPE_PATTERN.fullmatch(scope)
    ):
        raise ValueError("Invalid CSS scope.")

    if not css.strip():
        return ""

    rules = tinycss2.parse_stylesheet(
        css,
        skip_comments=True,
        skip_whitespace=True,
    )

    output = []

    for rule in rules:
        if rule.type != "qualified-rule":
            continue

        selectors = _split_selectors(rule.prelude)

        if not selectors:
            continue

        scoped_selectors = []

        for selector in selectors:
            normalized = selector.strip()

            if not normalized:
                continue

            if normalized.lower() in {"html", "body", ":root"}:
                scoped_selectors.append(scope)
            elif normalized.startswith(scope):
                scoped_selectors.append(normalized)
            else:
                scoped_selectors.append(
                    f"{scope} {normalized}"
                )

        if not scoped_selectors:
            continue

        declarations = tinycss2.parse_declaration_list(
            rule.content,
            skip_comments=True,
            skip_whitespace=True,
        )

        safe_declarations = []

        for declaration in declarations:
            safe = _safe_declaration(declaration)

            if safe:
                safe_declarations.append(safe)

        if safe_declarations:
            output.append(
                ", ".join(scoped_selectors)
                + " { "
                + "; ".join(safe_declarations)
                + "; }"
            )

    return "\n".join(output)
