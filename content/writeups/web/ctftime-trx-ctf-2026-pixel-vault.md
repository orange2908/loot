---
title: "Pixel Vault - TRX CTF 2026"
category: "web"
type: "writeup"
tags: ["web", "pixel", "vault", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "PixelVault is an image-hosting web challenge."
source:
  name: "CTFtime writeup #40723"
  url: "https://ctftime.org/writeup/40723"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-pixel-vault-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "Pixel Vault"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** Pixel Vault
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40723>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-pixel-vault-writeup>

---
Summary  
PixelVault is an image-hosting web challenge. The final exploit chain is a server-side Python format-string bug that is triggered through logging, combined with an upload endpoint that lets us place an arbitrary ELF shared object on disk under a predictable web-upload path.

The important chain is:

/upload accepts a file based only on its filename extension.  
The accepted file is saved under /data/uploads/originals/YYYY/MM/DD/<shortcode>.<ext>.  
Registration validates the submitted email with Pydantic, but the patched version stores the original raw email string instead of the normalized/validated value.  
A quoted RFC-style email display name can therefore preserve a payload such as "{self...}" <[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)>.  
User.__str__() incorrectly calls .format(self=self) on a string containing attacker-controlled email content.  
/login logs [logger.info](http://logger.info)("User logged in: %s", user), forcing str(user) and evaluating the attacker-controlled format field.  
The format field traverses Python objects to reach ctypes.cdll[...] and loads the uploaded shared object.  
The shared object's constructor executes immediately on dlopen() and runs /readflag 'could you please give me the flag thank you so much', redirecting the output into a separate uploaded holder file.  
The holder file is read back through /raw/<holder_code>.  
This is RCE without needing to view the logs. The logger is only the trigger that stringifies the malicious User object.

Relevant files
