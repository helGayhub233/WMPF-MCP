"""Safe beautifiers for decompiled mini-program text files.

- ``.js`` / ``.wxs``: jsbeautifier (mature, semantics-preserving).
- ``.json``: parse + re-dump (falls back to original text on parse errors).
- ``.wxss`` / ``.css``: conservative token-level reflow done outside strings.
- ``.wxml``: line-level indentation only — inner-line content is never
  rewritten, because WXML text nodes carry whitespace semantics.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsbeautifier

JS_EXTENSIONS = {".js", ".wxs"}
JSON_EXTENSIONS = {".json"}
CSS_EXTENSIONS = {".wxss", ".css"}
MARKUP_EXTENSIONS = {".wxml", ".html"}

BEAUTIFY_EXTENSIONS = JS_EXTENSIONS | JSON_EXTENSIONS | CSS_EXTENSIONS | MARKUP_EXTENSIONS

_TAG_RE = re.compile(r"<[a-zA-Z][^>]*>")
_CLOSE_TAG_RE = re.compile(r"</")


def _js_options() -> jsbeautifier.BeautifierOptions:
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 2
    opts.end_with_newline = True
    return opts


def beautify_js(text: str) -> str:
    return jsbeautifier.beautify(text, _js_options())


def beautify_json(text: str) -> str:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text
    return json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"


def beautify_css(text: str) -> str:
    """Reflow ``{}``/``;`` outside string literals onto their own lines."""
    out: list[str] = []
    depth = 0
    buffer: list[str] = []
    in_string: str | None = None

    def flush() -> None:
        token = "".join(buffer).strip()
        buffer.clear()
        if token:
            out.append("  " * depth + token)

    for ch in text:
        if in_string is not None:
            buffer.append(ch)
            if ch == in_string:
                in_string = None
            continue
        if ch in ("'", '"'):
            in_string = ch
            buffer.append(ch)
        elif ch == "{":
            flush()
            out.append("  " * depth + "{")
            depth += 1
        elif ch == "}":
            flush()
            depth = max(0, depth - 1)
            out.append("  " * depth + "}")
        elif ch == ";":
            buffer.append(";")
            flush()
        elif ch == "\n":
            flush()
        else:
            buffer.append(ch)
    flush()
    return "\n".join(line for line in out if line.strip()) + "\n"


def beautify_markup(text: str) -> str:
    """Line-level indent normalisation for WXML; keeps inner-line text intact."""
    lines_out: list[str] = []
    depth = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            lines_out.append("")
            continue
        if stripped.startswith("</"):
            depth = max(0, depth - 1)
        lines_out.append("  " * depth + stripped)
        opens = len(_TAG_RE.findall(stripped))
        closes = len(_CLOSE_TAG_RE.findall(stripped))
        self_closing = stripped.count("/>")
        delta = opens - closes - self_closing
        if delta > 0 and not stripped.endswith("/>"):
            depth += delta
        elif delta < 0:
            depth = max(0, depth + delta)
    return "\n".join(lines_out) + "\n"


def beautify_in_place(path: Path, max_bytes: int = 4 * 1024 * 1024) -> bool:
    """Beautify one extracted file in place. Returns True when rewritten."""
    ext = path.suffix.lower()
    if ext not in BEAUTIFY_EXTENSIONS:
        return False
    try:
        if path.stat().st_size > max_bytes:
            return False
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    try:
        if ext in JS_EXTENSIONS:
            new_text = beautify_js(text)
        elif ext in JSON_EXTENSIONS:
            new_text = beautify_json(text)
        elif ext in CSS_EXTENSIONS:
            new_text = beautify_css(text)
        else:
            new_text = beautify_markup(text)
    except Exception:  # noqa: BLE001 - a beautifier must never break extraction
        return False
    if new_text == text:
        return False
    try:
        path.write_text(new_text, encoding="utf-8")
        return True
    except OSError:
        return False
