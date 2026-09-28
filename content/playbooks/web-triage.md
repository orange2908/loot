---
title: "Playbook - Web Challenge Triage"
category: web
subcategory: triage
type: playbook
tags: [web-triage, where-to-start, stuck, what-attack, recon, source-review, sqli, xss, ssti, ssrf, lfi, idor, deserialization, jwt, prototype-pollution, race-condition, ffuf, burpsuite, grep-list, git-leak]
summary: "Recon order for a URL, the grep list per language for given source, and where the bug usually is per stack."
when_to_use:
  - "You have a web challenge URL and do not know where to look"
  - "You were given the web app's source and need a review order"
  - "You have found a candidate injection point and need the attack family"
related: [source-code-given, attack-surface-by-primitive, ffuf, burpsuite, sqlmap, http-status-and-headers]
---

## TL;DR

**With source**: skip scanning. Read the flag's location first, then the route that touches it. Go to section 3.
**Without source**: 10 minutes of recon (section 1), then fingerprint the stack (section 2), then the bug table (section 4).

---

## 1. Recon order for a URL (do these in this order, ~10 minutes)

```sh
URL=https://chal.example.ctf

# 1. What does the raw response say? headers first - they name the stack.
curl -sSik "$URL/" | head -60

# 2. The page source. Comments, JS bundles, hidden inputs, API base URLs.
curl -sS "$URL/" | grep -oE '<!--.*?-->|src="[^"]+"|href="[^"]+"|action="[^"]+"'

# 3. The obvious files. Read them, do not just check the status code.
for p in robots.txt sitemap.xml .git/HEAD .env .env.local .DS_Store \
         package.json composer.json requirements.txt Dockerfile docker-compose.yml \
         .svn/entries .hg/store backup.zip source.zip app.zip www.zip \
         server-status phpinfo.php info.php admin login api swagger.json \
         openapi.json graphql .well-known/security.txt; do
  code=$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "$URL/$p")
  echo "$code  /$p"
done

# 4. Directory brute force. Start small and fast, escalate only if needed.
ffuf -u "$URL/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404 -t 60
ffuf -u "$URL/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt      -mc all -fc 404 -t 60 -e .php,.txt,.bak,.old,.zip,.json

# 5. Parameter discovery on the interesting endpoints.
ffuf -u "$URL/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs $(curl -s "$URL/page" | wc -c)

# 6. Vhost / subdomain if the challenge hints at it.
ffuf -u "$URL/" -H "Host: FUZZ.chal.example.ctf" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0
```

**Then put Burp in the loop and click every single feature of the app by hand.** In CTF, the bug is almost always in a feature the author wrote, not in a library.

Checklist of things people skip and then lose an hour to:
- View-source the JS bundle and search for `/api/`, `fetch(`, `axios`, `token`, `admin`, `debug`.
- Check for sourcemaps: `curl -sI "$URL/static/js/main.js.map"`.
- Check cookies: flags, decode any base64/JWT, check for a signed-but-not-encrypted session.
- Check the 404/500 page for a framework banner and a stack trace.
- Diff the response of a valid vs invalid username (enumeration is often the intended first step).

---

## 2. Fingerprint the stack

| Signal | Stack | Where the bug usually is |
|---|---|---|
| `X-Powered-By: PHP`, `.php` paths, `PHPSESSID` | PHP | type juggling `==`, `file_get_contents`, `unserialize`, LFI, `preg_replace /e`, `extract()` |
| `Set-Cookie: session=eyJ...` + `.` signature | Flask | SSTI in Jinja2, `secret_key` brute force, pickle in session |
| `csrftoken`, `sessionid`, `/admin/` login page styling | Django | SSTI (rare), ORM leaks, `debug=True` page, pickle session |
| `X-Powered-By: Express`, `connect.sid` | Node/Express | prototype pollution, NoSQLi, `child_process`, `vm`, JWT `alg:none` |
| `Next.js` build id, `/_next/` | Next.js | middleware auth bypass, `/_next/image` SSRF, server actions |
| `laravel_session`, `XSRF-TOKEN` | Laravel | `APP_KEY` leak -> decrypt cookie -> unserialize RCE, debug page |
| `JSESSIONID`, `.jsp`, `.do`, `.action` | Java | deserialization (ysoserial), EL/OGNL injection, path traversal, XXE |
| `ASP.NET_SessionId`, `__VIEWSTATE` | ASP.NET | ViewState deserialization, `machineKey` leak, `trace.axd` |
| `X-Powered-By: ASP.NET` + `.aspx` | Webforms | same, plus request-validation bypass |
| `Server: gunicorn/uvicorn`, `/docs`, `/openapi.json` | FastAPI | dependency-injection auth gaps, Pydantic coercion, mass assignment |
| `_rails_session`, `authenticity_token` | Rails | `Marshal.load`, mass assignment, `render` path traversal, `to_json` leaks |
| `wp-content`, `wp-json` | WordPress | plugin CVEs, `xmlrpc.php`, user enumeration |
| `graphql` endpoint responds to POST | GraphQL | introspection, IDOR via `node()`, batching, field-level authz |
| Go: no banner, very fast, `text/plain` errors | Go | template injection (`text/template`), path traversal, `httputil` proxy |
| `Werkzeug` in a traceback | Flask debug | the debugger console PIN -> RCE |

---

## 3. Source-code review order (when the source is given)

1. **Find the flag.** `grep -rn 'flag\|FLAG' . --include='*' | head -40`, and `cat Dockerfile docker-compose.yml` (the flag is often an env var or a file copied in).
2. **Find who reads it.** That route/function is the target.
3. **Map routes.** Enumerate every endpoint and its auth decorator. The one with no decorator is the bug.
4. **Find the sinks.** Grep list below.
5. **Trace user input to a sink.** Untrusted -> sanitiser? -> sink.
6. **Look at what is custom.** Hand-rolled auth, hand-rolled crypto, hand-rolled parsing = the bug.

### Grep list by language

```sh
# --- PHP ---
grep -rnE 'eval|assert|system|exec|shell_exec|passthru|popen|proc_open|`' --include='*.php' .
grep -rnE 'unserialize|__wakeup|__destruct|__toString|extract\(|\$\$' --include='*.php' .
grep -rnE 'include|require|file_get_contents|fopen|readfile|file_put_contents' --include='*.php' .
grep -rnE '\bmysql_query|->query\(|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE' --include='*.php' .
grep -rnE '==[^=]|in_array\([^,]+,[^,]+\)|strcmp|md5\(|preg_replace.*\/e' --include='*.php' .

# --- Python ---
grep -rnE 'eval\(|exec\(|compile\(|__import__|os\.system|subprocess|popen|shell=True' --include='*.py' .
grep -rnE 'pickle\.loads|cPickle|yaml\.load\(|marshal\.loads|dill|jsonpickle' --include='*.py' .
grep -rnE 'render_template_string|Template\(|jinja2|format\(|%\s*\(|f["\x27].*\{' --include='*.py' .
grep -rnE 'execute\(.*%|execute\(.*\+|execute\(.*format|raw\(|extra\(' --include='*.py' .
grep -rnE 'send_file|open\(|os\.path\.join|safe_join|\.\./' --include='*.py' .
grep -rnE 'requests\.get\(|urllib|urlopen|httpx' --include='*.py' .

# --- JavaScript / Node ---
grep -rnE 'eval\(|new Function|vm\.run|child_process|exec\(|execSync|spawn' --include='*.js' --include='*.ts' .
grep -rnE 'JSON\.parse|_\.merge|_\.defaultsDeep|Object\.assign|__proto__|constructor\[' --include='*.js' --include='*.ts' .
grep -rnE 'innerHTML|dangerouslySetInnerHTML|document\.write|\$\(.*\)\.html' --include='*.js' --include='*.jsx' .
grep -rnE 'jwt\.|jsonwebtoken|verify\(|decode\(|algorithms' --include='*.js' .
grep -rnE '\$where|\$ne|\$gt|\$regex|find\(.*req\.' --include='*.js' .
grep -rnE 'serialize-javascript|node-serialize|unserialize' --include='*.js' .

# --- Java ---
grep -rnE 'readObject|ObjectInputStream|XMLDecoder|Yaml\.load|readValue' --include='*.java' .
grep -rnE 'Runtime.getRuntime|ProcessBuilder|ScriptEngine|OgnlUtil|SpelExpression' --include='*.java' .
grep -rnE 'createQuery|createNativeQuery|"\s*\+\s*\w+\s*\+\s*"' --include='*.java' .
grep -rnE 'DocumentBuilderFactory|SAXParser|XMLReader|Unmarshaller' --include='*.java' .

# --- Go ---
grep -rnE 'text/template|template\.HTML|exec\.Command|os/exec' --include='*.go' .
grep -rnE 'fmt\.Sprintf\(".*(SELECT|INSERT|UPDATE)' --include='*.go' .
grep -rnE 'filepath\.Join|http\.Dir|ServeFile' --include='*.go' .

# --- Ruby ---
grep -rnE 'eval|send\(|__send__|constantize|Marshal\.load|YAML\.load|instance_eval' --include='*.rb' .
grep -rnE 'render\s+(file|inline|text)|system|%x\(|`|Open3' --include='*.rb' .

# --- Universal ---
grep -rniE 'password|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH|PRIVATE)|AKIA[0-9A-Z]{16}' .
grep -rnE 'TODO|FIXME|XXX|HACK|debug|DEBUG *= *True|backdoor' .
git log --oneline -30 2>/dev/null && git diff HEAD~5 2>/dev/null | head -100
```

---

## 4. Bug family by observable signal

| You see | Try | Search |
|---|---|---|
| Any parameter reflected in HTML | XSS (reflected/stored/DOM) | `ctfbrain search xss` |
| Parameter reflected with `{{7*7}}` -> `49` | SSTI | `ctfbrain search ssti` |
| Parameter that becomes a filename/path | LFI/path traversal, then log poisoning / `/proc/self/environ` / php filters | `ctfbrain search lfi` |
| A numeric/GUID id in the URL or body | IDOR - increment it, try another user's | `ctfbrain search idor` |
| Login form, or any DB-backed query | SQLi (`'`, `"`, `\`, `)`), then `sqlmap` | `ctfbrain search sqli sqlmap` |
| JSON login accepting objects | NoSQLi `{"$ne": null}`, `{"$regex": "^a"}` | `ctfbrain search nosqli` |
| App fetches a URL you supply | SSRF -> `127.0.0.1`, `169.254.169.254`, `file://`, `gopher://` | `ctfbrain search ssrf` |
| XML anywhere (SOAP, SVG, DOCX, config upload) | XXE | `ctfbrain search xxe` |
| File upload | webshell, SVG XSS, zip slip, polyglot | `ctfbrain search file-upload` |
| A cookie that is base64 and decodes to a struct | forge it; check for a signature and weak key | `ctfbrain search deserialization jwt-tool` |
| `eyJ...` token | JWT: `alg:none`, HS/RS confusion, weak secret, `kid` traversal, `jku`/`jwk` | `ctfbrain search jwt-tool` |
| Balance/credits/coupons/transfers | race condition, negative values, integer overflow, TOCTOU | `ctfbrain search race-condition` |
| Admin-only feature + a "role" field anywhere | mass assignment `{"role":"admin"}` | `ctfbrain search mass-assignment` |
| `redirect=` / `next=` / `url=` param | open redirect -> OAuth token theft chain | `ctfbrain search open-redirect oauth` |
| A "bot visits your URL" feature | XSS -> steal the admin cookie; or CSRF; or SSRF via the headless browser | `ctfbrain search xss-bot` |
| Password reset by email | host-header poisoning, token predictability, no-expiry | `ctfbrain search host-header ato` |
| A cache / CDN header (`Age`, `X-Cache`) | cache poisoning / web cache deception | `ctfbrain search cache-poison` |
| A regex used for validation | ReDoS or a bypass (`^`/`$` missing, unescaped `.`) | `ctfbrain search regex-recipes` |
| A `Content-Length` + `Transfer-Encoding` disagreement | request smuggling | `ctfbrain search http-smuggling` |
| `/debug`, `/console`, `/actuator`, `/metrics` | direct RCE or secret disclosure | `ctfbrain search information-disclosure` |
| `.git` directory served | `git-dumper` then `git log -p` | `ctfbrain search git-leak` |

---

## 5. Common CTF-only web tricks

- The flag is in the **response headers**, or an HTML comment, or a cookie you never decoded.
- The app is **behind a proxy**: try `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `X-Original-URL: /admin`, `X-Forwarded-Host`.
- **Unicode/normalisation**: `%u0041`, `\u0041`, overlong UTF-8, dotted-capital-I lowercasing to `i` under a Turkish locale, homoglyph lookalikes - all bypass naive blocklists.
- **Parser differentials**: PHP `parse_str` vs the proxy, `?a=1&a=2` (first vs last wins), array params `a[]=1`.
- **Type juggling**: PHP `"0e123" == "0e456"` is true; `strcmp(array, string)` returns NULL.
- **Null bytes**: `%00` still works in some file-path handling.
- **Case and encoding on filters**: `SeLeCt`, `/**/`, `%0a`, double URL-encoding, `%252e%252e%252f`.
- The rate limit is per-IP but the flag is only 4 digits: brute force with `X-Forwarded-For` rotation.
- Read `docker-compose.yml`: internal service names are your SSRF targets.

## When to stop and re-triage
If 30 minutes of the above yields nothing, the challenge is not a standard bug class -> `ctfbrain search stuck`.
