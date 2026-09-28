"""Markdown rendering must be complete, offline and safe to inject into the page."""
from ctfbrain.render import pygments_css, render, slugify, to_plain_text


def test_headings_get_stable_unique_anchors():
    html, toc = render("## Attack\n\ntext\n\n## Attack\n\nmore\n\n### Deep\n")
    anchors = [h["anchor"] for h in toc]
    assert anchors == ["attack", "attack-2", "deep"]
    assert len(set(anchors)) == len(anchors)
    assert 'id="attack-2"' in html


def test_code_fences_become_highlighted_blocks_with_a_copy_button():
    html, _ = render("```python\nimport os\n```\n")
    assert 'class="codeblock"' in html
    assert 'data-lang="python"' in html
    assert 'class="copy"' in html
    assert "<span" in html, "pygments should have emitted token spans"


def test_unknown_language_still_renders():
    html, _ = render("```notalanguage\nx = 1\n```\n")
    assert "codeblock" in html
    assert "x = 1" in html


def test_tables_render():
    html, _ = render("| a | b |\n|---|---|\n| 1 | 2 |\n")
    assert "<table>" in html and "<td>1</td>" in html


def test_raw_html_in_source_is_not_passed_through():
    html, _ = render("<script>alert(1)</script>\n\nnormal text\n")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_toc_only_collects_h2_and_h3():
    _, toc = render("# One\n\n## Two\n\n### Three\n\n#### Four\n")
    assert [h["level"] for h in toc] == [2, 3]


def test_pygments_css_covers_both_themes():
    css = pygments_css()
    assert ".hl" in css
    assert '[data-theme="light"]' in css


def test_slugify():
    assert slugify("RSA - Common Modulus!") == "rsa-common-modulus"
    assert slugify("") == "section"


def test_plain_text_strips_markup():
    text = to_plain_text("# H\n\n`code` and **bold** and [link](http://x)\n\n```\nblock\n```\n")
    assert "#" not in text and "**" not in text
    assert "link" in text and "[code]" in text


# ------------------------------------------------------------------- math
# LaTeX is converted to MathML server-side. The risk is not that math fails to
# render, it is that the math parser eats shell variables and currency.
def test_inline_math_becomes_mathml():
    html, _ = render(r"Euler gives $\varphi(n) = (p-1)(q-1)$ here.")
    assert 'class="math math-inline"' in html
    assert "<math " in html
    assert "varphi" not in html, "the TeX source should have been converted"


def test_display_math_becomes_a_block():
    html, _ = render(r"$$d \equiv e^{-1} \pmod{\varphi(n)}$$")
    assert 'class="math math-display"' in html
    assert 'display="block"' in html


def test_currency_is_not_treated_as_math():
    html, _ = render("It costs $5 and then $10 more.")
    assert "math-inline" not in html
    assert "$5 and then $10" in html


def test_dollars_inside_code_fences_are_untouched():
    html, _ = render('```bash\necho "$PATH"\nawk \'{print $1}\'\n```')
    assert "<math " not in html and "math-inline" not in html
    import re
    text = re.sub(r"<[^>]+>", "", html)
    assert "$PATH" in text and "print $1" in text


def test_dollars_inside_code_spans_are_untouched():
    html, _ = render("Use `$HOME` and `$ne` in the query.")
    assert "<math " not in html
    assert "$HOME" in html and "$ne" in html


def test_unparseable_latex_keeps_its_source():
    html, _ = render(r"Broken: $\frobnicate{{{$ end.")
    assert "math-raw" in html
    assert "frobnicate" in html, "the source must survive so the page still reads"


def test_math_does_not_break_the_renderer():
    for src in [r"$$", r"$ $", r"$\\$", r"$^$", "$" * 12, r"$$\begin{matrix}$$"]:
        render(src)   # must not raise
