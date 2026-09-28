"""Markdown -> HTML rendering with server-side syntax highlighting.

Everything is rendered locally: no CDN, no network at view time.  That matters
because you may well be using this on a CTF network with no egress.
"""
from __future__ import annotations

import html
import re
from functools import lru_cache

from markdown_it import MarkdownIt
from mdit_py_plugins.dollarmath import dollarmath_plugin
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.util import ClassNotFound

ANCHOR_STRIP = re.compile(r"[^a-z0-9\s-]")

LANG_ALIASES = {
    "sh": "bash", "shell": "bash", "console": "bash", "sh-session": "bash",
    "py": "python", "python3": "python", "sage": "python", "sagemath": "python",
    "js": "javascript", "node": "javascript", "ts": "typescript",
    "c++": "cpp", "asm": "nasm", "assembly": "nasm", "x86asm": "nasm",
    "sol": "solidity", "smali": "text", "wat": "lisp", "yml": "yaml",
    "dockerfile": "docker", "ps1": "powershell", "psh": "powershell",
    "http": "http", "sql": "sql", "php": "php", "java": "java", "go": "go",
    "rb": "ruby", "rs": "rust", "pl": "perl", "re": "text", "txt": "text",
    "": "text",
}


def slugify(text: str) -> str:
    text = ANCHOR_STRIP.sub("", text.strip().lower())
    return re.sub(r"[\s-]+", "-", text).strip("-") or "section"


@lru_cache(maxsize=256)
def _lexer(lang: str):
    try:
        return get_lexer_by_name(LANG_ALIASES.get(lang, lang), stripnl=False)
    except ClassNotFound:
        return None


def _highlight(code: str, lang: str) -> str:
    lexer = _lexer((lang or "").strip().lower().split()[0] if lang.strip() else "")
    if lexer is None:
        try:
            lexer = guess_lexer(code)
        except ClassNotFound:
            return f'<pre class="hl"><code>{html.escape(code)}</code></pre>'
    formatter = HtmlFormatter(nowrap=False, cssclass="hl", wrapcode=True)
    return highlight(code, lexer, formatter)


def _fence_renderer(self, tokens, idx, options, env):
    # markdown-it binds render rules as methods, hence the leading `self`.
    token = tokens[idx]
    lang = (token.info or "").strip()
    rendered = _highlight(token.content, lang)
    label = html.escape(lang.split()[0]) if lang else "text"
    return (
        f'<div class="codeblock" data-lang="{label}">'
        f'<div class="codebar"><span class="lang">{label}</span>'
        f'<button class="copy" type="button" aria-label="Copy code">copy</button></div>'
        f"{rendered}</div>"
    )


# ---------------------------------------------------------------------- math
# LaTeX is converted to MathML on the server. Browsers render MathML natively,
# so there is no JS to load and no font bundle to vendor, which keeps the whole
# page working with no network. Anything latex2mathml cannot parse falls back to
# the original source in a code span rather than vanishing.
try:
    from latex2mathml.converter import convert as _latex_to_mathml
except ImportError:  # pragma: no cover - math simply degrades to source text
    _latex_to_mathml = None


@lru_cache(maxsize=4096)
def _mathml(latex: str, display: bool) -> str:
    source = latex.strip()
    if not source:
        return ""
    if _latex_to_mathml is None:
        return f'<code class="math-raw">{html.escape(source)}</code>'
    try:
        out = _latex_to_mathml(source)
    except Exception:  # noqa: BLE001 - malformed TeX in a writeup must not 500
        return f'<code class="math-raw">{html.escape(source)}</code>'
    if display:
        out = out.replace('display="inline"', 'display="block"', 1)
    return out


def _math_inline_renderer(self, tokens, idx, options, env):
    return f'<span class="math math-inline">{_mathml(tokens[idx].content, False)}</span>'


def _math_block_renderer(self, tokens, idx, options, env):
    return f'<div class="math math-display">{_mathml(tokens[idx].content, True)}</div>\n'


def _make_md() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False, "linkify": True, "typographer": False})
    md.enable(["table", "strikethrough", "linkify"])
    md.use(dollarmath_plugin, allow_space=True, allow_digits=False, double_inline=True)
    md.add_render_rule("fence", _fence_renderer)
    md.add_render_rule("math_inline", _math_inline_renderer)
    md.add_render_rule("math_inline_double", _math_block_renderer)
    md.add_render_rule("math_block", _math_block_renderer)
    md.add_render_rule("math_block_label", _math_block_renderer)
    return md


_MD = _make_md()


@lru_cache(maxsize=192)
def _render_cached(markdown_text: str) -> tuple[str, tuple]:
    html, toc = _render(markdown_text)
    return html, tuple(tuple(sorted(h.items())) for h in toc)


def render(markdown_text: str) -> tuple[str, list[dict]]:
    """Return (html, table_of_contents).

    Results are cached: the largest pages (the GTFOBins tables, the long
    cheatsheets) take ~0.7s to highlight, and they are exactly the ones you
    reopen repeatedly during a competition.
    """
    html, toc = _render_cached(markdown_text)
    return html, [dict(h) for h in toc]


def _render(markdown_text: str) -> tuple[str, list[dict]]:
    tokens = _MD.parse(markdown_text)

    toc: list[dict] = []
    seen: dict[str, int] = {}
    for i, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        inline = tokens[i + 1]
        text = re.sub(r"[`*_]", "", inline.content).strip()
        base = slugify(text)
        seen[base] = seen.get(base, 0) + 1
        anchor = base if seen[base] == 1 else f"{base}-{seen[base]}"
        token.attrSet("id", anchor)
        level = int(token.tag[1])
        if 2 <= level <= 3:
            toc.append({"level": level, "text": text, "anchor": anchor})

    body_html = _MD.renderer.render(tokens, _MD.options, {})
    return body_html, toc


@lru_cache(maxsize=1)
def pygments_css() -> str:
    """Two themes in one stylesheet, switched by a `data-theme` attribute."""
    dark = HtmlFormatter(style="one-dark", cssclass="hl").get_style_defs(".hl")
    light = HtmlFormatter(style="friendly", cssclass="hl").get_style_defs(".hl")
    scoped_light = "\n".join(
        f'[data-theme="light"] {line}' if line.strip().startswith(".hl") else line
        for line in light.splitlines()
    )
    return f"/* dark (default) */\n{dark}\n\n/* light */\n{scoped_light}\n"


def to_plain_text(markdown_text: str, limit: int = 0) -> str:
    """Crude markdown stripper used for terminal output and previews."""
    text = re.sub(r"```.*?```", " [code] ", markdown_text, flags=re.DOTALL)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"^[#>*\-|]+\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"[*_]{1,3}", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    return text[:limit] if limit else text
