---
title: "Ez ⛳ v3 - KalmarCTF 2025"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "caddy", "mtls", "ssrf", "kalmarctf", "kalmarctf-2025", "2025", "ctf-writeup"]
summary: "mTLS can only be applied during the TLS handshake, so by setting Server Name Indication (SNI) to public.caddy.chal-kalmarc.tf no clientauth is enforced while making the TLS connection."
source:
  name: "CTFtime writeup #40073"
  url: "https://ctftime.org/writeup/40073"
original_source: "https://github.com/kalmarunionenctf/kalmarctf/blob/main/2025/web/caddy-v3/solution.md"
ctf:
  name: "KalmarCTF 2025"
  year: 2025
  challenge: "Ez ⛳ v3"
---

## Metadata

- **CTF:** KalmarCTF 2025
- **Task:** Ez ⛳ v3
- **Author team:** kalmarunionen
- **CTFtime tags:** ssti, caddy, mtls
- **CTFtime:** <https://ctftime.org/writeup/40073>
- **Original writeup:** <https://github.com/kalmarunionenctf/kalmarctf/blob/main/2025/web/caddy-v3/solution.md>

---
# Ez ⛳ v3 

mTLS can only be applied during the TLS handshake, so by setting Server Name Indication (SNI) to `[public.caddy.chal-kalmarc.tf](http://public.caddy.chal-kalmarc.tf)` no `client_auth` is enforced while making the TLS connection. Afterwards we set the `Host` header to ` [private.caddy.chal-kalmarc.tf](http://private.caddy.chal-kalmarc.tf)` so the wrong server is selected. Note: this only works because `strict_sni_host`-checking is turned off (props to Caddy for rightfully calling this option `insecure_off`!).

When accessing the private server a bunch of tools are available. The `/fetch/` feature give us a kinda SSRF primitive, but we can't request `/flag` due to the `denied2` check.  
But `/fetch/` is using `httpInclude` which [weirdly does another server-side rendering i.e. SSTI](<https://github.com/caddyserver/caddy/blob/d57ab215a2f198a465ea33abe4588bb5696e7abd/modules/caddyhttp/templates/tplcontext.go#L211>). We need to reflect something in the body of the `/fetch/` call to trigger the SSTI - which is exactly what `/headers` does (reflect our initial headers). Note that `mustToPrettyJson` will jsonify the reflected headers, so we can't use quotes (`"` and `'`), but we can use a backtick ``` ` ``` which will be unescaped in the JSON output.

## PoC

```bash  
curl -sk '<https://public.caddy.chal-kalmarc.tf/fetch/headers'> -H 'Host: [private.caddy.chal-kalmarc.tf](http://private.caddy.chal-kalmarc.tf)' -H 'Anything: {{ env `FLAG` }}'  
```
