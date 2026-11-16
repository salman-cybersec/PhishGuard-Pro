
import re

import tinycss2


MAX_CSS_SIZE = 1_000_000

ALLOWED_PROPERTIES = {
    "color",
    "background-color",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "text-align",
    "text-decoration",
    "text-transform",
    "line-height",
    "letter-spacing",
    "word-spacing",
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
    "border-color",
    "border-width",
    "border-style",
    "border-radius",
    "display",
    "width",
    "height",
    "max-width",
    "max-height",
    "min-width",
    "min-height",
    "box-sizing",
    "object-fit",
    "vertical-align",
    "list-style-type",
    "white-space",
    "overflow",
    "flex",
    "flex-direction",
    "flex-wrap",
    "justify-content",
    "align-items",
    "gap",
    "row-gap",
    "column-gap",
}

BLOCKED_FUNCTIONS = {
    "url",
    "expression",
    "var",
    "image",
    "image-set",
    "element",
    "paint",
    "attr",
}

SAFE_SELECTOR_PATTERN = re.compile(
    r"""^[a-zA-Z0-9_*#.\[\]="' :>+~\-():]+$"""
)

SAFE_SCOPE_PATTERN = re.compile(
    r"^\.[a-zA-Z][a-zA-Z0-9_-]{0,63}$"
)


def _contains_unsafe_token(tokens):
    for token in tokens:
        if token.type == "url":
            return True

        if token.type == "function":
            if token.lower_name in BLOCKED_FUNCTIONS:
                return True

            if _contains_unsafe_token(token.arguments):
                return True

        if token.type == "error":
            return True

        if token.type == "() block":
            if _contains_unsafe_token(token.content):
                return True

        if token.type == "[] block":
            if _contains_unsafe_token(token.content):
                return True

        if token.type == "{} block":
            if _contains_unsafe_token(token.content):
                return True

    return False


def _safe_declarations(content):
    declarations = tinycss2.parse_declaration_list(
        content,
        skip_comments=True,
        skip_whitespace=True,
    )

    safe_declarations = []

    for declaration in declarations:
        if declaration.type != "declaration":
            continue

        property_name = declaration.lower_name

        if property_name not in ALLOWED_PROPERTIES:
            continue

        if declaration.important:
            continue

        if _contains_unsafe_token(declaration.value):
            continue

        value = tinycss2.serialize(
            declaration.value
        ).strip()

        if not value or len(value) > 500:
            continue

        safe_declarations.append(
            f"{property_name}: {value}"
        )

    return safe_declarations


def _split_selectors(selector_text):
    selectors = []
    current = []

    depth = 0
    quote = None
    escaped = False

    for character in selector_text:
        if escaped:
            current.append(character)
            escaped = False
            continue

        if character == "\\":
            current.append(character)
            escaped = True
            continue

        if quote:
            current.append(character)

            if character == quote:
                quote = None

            continue

        if character in {"'", '"'}:
            quote = character
            current.append(character)
            continue

        if character == "(" or character == "[":
            depth += 1
            current.append(character)
            continue

        if character == ")" or character == "]":
            depth -= 1

            if depth < 0:
                return []

            current.append(character)
            continue

        if character == "," and depth == 0:
            selectors.append(
                "".join(current).strip()
            )
            current = []
            continue

        current.append(character)

    if depth != 0 or quote or escaped:
        return []

    selectors.append(
        "".join(current).strip()
    )

    return selectors


def _scope_selector(selector, scope):
    normalized = selector.strip().lower()

    if normalized in {"html", "body", ":root"}:
        return scope

    return f"{scope} {selector}"


def sanitize_css(css: str) -> str:
    if not isinstance(css, str):
        raise ValueError("CSS content must be text.")

    if len(css.encode("utf-8")) > MAX_CSS_SIZE:
        raise ValueError("CSS content exceeds the size limit.")

    try:
        rules = tinycss2.parse_stylesheet(
            css,
            skip_comments=True,
            skip_whitespace=True,
        )

        safe_rules = []

        for rule in rules:
            if rule.type != "qualified-rule":
                continue

            selector = tinycss2.serialize(
                rule.prelude
            ).strip()

            if (
                not selector
                or len(selector) > 1000
                or "@" in selector
                or "<" in selector
                or ">" in selector
            ):
                continue

            declarations = _safe_declarations(
                rule.content
            )

            if declarations:
                safe_rules.append(
                    selector
                    + " { "
                    + "; ".join(declarations)
                    + "; }"
                )

        return "\n".join(safe_rules)

    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(
            "CSS sanitization failed."
        ) from error


def scope_css(
    css: str,
    scope: str = ".phishguard-preview",
) -> str:
    if not isinstance(css, str):
        raise ValueError("CSS content must be text.")

    if (
        not isinstance(scope, str)
        or not SAFE_SCOPE_PATTERN.fullmatch(scope)
    ):
        raise ValueError("Invalid CSS scope.")

    if len(css.encode("utf-8")) > MAX_CSS_SIZE:
        raise ValueError("CSS content exceeds the size limit.")

    try:
        rules = tinycss2.parse_stylesheet(
            css,
            skip_comments=True,
            skip_whitespace=True,
        )

        scoped_rules = []

        for rule in rules:
            if rule.type != "qualified-rule":
                continue

            selector_text = tinycss2.serialize(
                rule.prelude
            ).strip()

            if not selector_text or len(selector_text) > 1000:
                continue

            selectors = _split_selectors(
                selector_text
            )

            if not selectors:
                continue

            if any(
                not selector
                or len(selector) > 300
                or not SAFE_SELECTOR_PATTERN.fullmatch(selector)
                for selector in selectors
            ):
                continue

            declarations = _safe_declarations(
                rule.content
            )

            if not declarations:
                continue

            scoped_selectors = [
                _scope_selector(selector, scope)
                for selector in selectors
            ]

            scoped_rules.append(
                ", ".join(scoped_selectors)
                + " { "
                + "; ".join(declarations)
                + "; }"
            )

        return "\n".join(scoped_rules)

    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError(
            "CSS scoping failed."
        ) from error
