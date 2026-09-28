---
title: "Example Box - The Cyber Jawara International 2024"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "path-traversal", "jwt", "flask", "render-template", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #39611"
  url: "https://ctftime.org/writeup/39611"
original_source: "https://araisantai.gitbook.io/araisantai-archives/ctf-archive/web-the-cyber-jawara-international-2024#example-box"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Example Box"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Example Box
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39611>
- **Original writeup:** <https://araisantai.gitbook.io/araisantai-archives/ctf-archive/web-the-cyber-jawara-international-2024#example-box>

---
For the complete documentation index, see [llms.txt](https://araisantai.gitbook.io/araisantai-archives/llms.txt). This page is also available as [Markdown](https://araisantai.gitbook.io/araisantai-archives/ctf-archive/web-the-cyber-jawara-international-2024.md).

## Example Box

Category

Points

Author

Web; **whitebox**

495

**farisv**

###  Code Analysis

Here is the main code that provided

Copy

```
    from flask import Flask, abort, render_template, request, Response
    from re import sub
    from unidecode import unidecode
    from urllib3.util import parse_url
    import requests
    
    app = Flask(__name__)
    
    allowed_hostname = ["example.com"]
    allowed_path = ["", "/"]
    fallback = "http://example.com/"
    cache = {}
    
    def normalize(token):
        if token == None:
            token = ""
        return sub(r'\s+', '', unidecode(str(token)))
    
    def filter_url(url):
        parsed_url = parse_url(url)
        scheme = normalize(parsed_url.scheme) # http
        host = normalize(parsed_url.host)
        path = normalize(parsed_url.path)
        filtered_url = url
        if not scheme.startswith('http'):
            filtered_url = fallback
        if not host in allowed_hostname:
            filtered_url = fallback
        if not path in allowed_path:
            filtered_url = fallback
        return normalize(filtered_url)
    
    @app.route('/', methods=['GET', 'POST'])
    def index():
        url = request.form.get('url', '')
        return render_template('index.html', url=url)
    
    @app.route('/fetch_url')
    def fetch_url():
        url = request.args.get('url')
        filtered_url = filter_url(url)
        print("request from: ", request.remote_addr)
        # print("cache now: ")
        try:
            if filtered_url in cache:
                response = cache[filtered_url]
            else:
                response = requests.get(filtered_url)
                cache[filtered_url] = response
            return Response(response.content,
                            status=response.status_code,
                            content_type=response.headers.get('Content-Type'))
        except requests.exceptions.RequestException as e:
            return f"Error fetching the URL: {e}", 500
    
    @app.route('/flag')
    def flag():
        if request.remote_addr != '127.0.0.1':
            abort(403)
        with open('/flag.txt', 'r') as flag:
            return flag.read()
    
    if __name__ == '__main__':
        app.run(debug=False, host='0.0.0.0', port=20002)
```

Reviewing the code we know that, this must be related to ssrf but there is some url parsing filter that we should bypass. Although the code looks very simple but i found that its really tricky to bypass.

Our objective is to access path flag with 127.0.0.1 remote addres `http://127.0.01/flag`

Reviewing the code the `normalize` function is to check if there is whitespace or any unicode in the url. 

`filter_url` is check for the whitelist. 

the challenge is we need to bypass parse_url and fallback overwrite, to perform this there is a good reads that that i found for bypassing the parse_url() in python. 

<https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf>

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FXNoTDdrLwsi9eOeyseWE%252Fimage.png%3Falt%3Dmedia%26token%3Db4512708-3dab-4f1c-9436-b41f3d00b090&width=768&dpr=3&quality=100&sign=17f9b262ee282d9bd231493a0b1264ea&sv=3)

Yepp we can use `@` to bypass the parse_url, 

### Exploitation

Because there are some whitelist so we need to use it to perform SSRF

I perform some test code to debug the website and see how the parsed works

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FJVcQLAfezyZCwzIkk9nX%252Fimage.png%3Falt%3Dmedia%26token%3D06493641-3bd6-45d7-837c-dabe28045163&width=768&dpr=3&quality=100&sign=6ee95aa80b9fa2b4f2da942de62f5cd2&sv=3)

We can see we have finally bypass the parse_url and fallback. but the `request python` still accepting our request as `example.com`

the problem is if we access the path flag manually like this `http://127.0.0.1/flag@example.com` the parse will works again and our input will be only `example.com`.

So we need to use unicode because normalize function and we are using `?` for the reuqest to not accessing path @example.com. 

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252Foiz6qoIbZ9uebdCxngKY%252Fimage.png%3Falt%3Dmedia%26token%3De0b48fde-29a4-4d71-bb2f-a95355be653a&width=768&dpr=3&quality=100&sign=c6aecc4b167262fcb5f67ea86320ce1d&sv=3)

So here is the full payload:

[`http://127.0.0.1:20002／ⓕⓛⓐⓖ？@example.com`](http://127.0.0.1:20002／ⓕⓛⓐⓖ？@example.com)

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252F3c2i9bzVt2YrFpnd95FL%252Fimage.png%3Falt%3Dmedia%26token%3D981e4e6b-fb59-4e9f-a49b-94df84ecc7f9&width=768&dpr=3&quality=100&sign=28b8f85559ed8515dfa095e1557393dc&sv=3)

Flag: `CJ{enough_with_example.com_here_is_your_nice_Phl4g!}`

## Java Box

Category

Points

Author

Java Box; **blackbox**

499

farisv

In this challenge our team work together to solve the challenge. Thanks to @daffainfo who find the initial foothold of the challenge we can continue the challenge and manage to solve 1 hour before the CTF ends.

### Blackbox

We are given a service and there is no code provided so it should be blackbox challenge. There is only register and login to the dahsboard and nothing special with other feature of the service.

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252F0S5P97r2E1fxrtsBV8Ng%252Fimage.png%3Falt%3Dmedia%26token%3D59f5548c-20a5-4dcf-a76f-fc3b0d0b70f1&width=768&dpr=3&quality=100&sign=c0e211260d712f0a6c200229c573e96e&sv=3)

Our team found that we can see java stack trace in `assets` path. After that we started by doing some enumeration there. 

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252F1iyBeINO5W33k3wyW3Lo%252Fimage.png%3Falt%3Dmedia%26token%3Da9502f5a-0ff3-43c3-ab8a-00023cce2998&width=768&dpr=3&quality=100&sign=345ef7dad4b4d0fafec2c47621a43a01&sv=3)

If we're accessing assets the error given is `java.lang.StringIndexOutOfBoundsException `accessing But if we are accessing something like this the error given is different, it look like failed to get some resouce in the server we consider that is trying to access file in the server.

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FQehwOYRSfJIlcRNecus9%252Fimage.png%3Falt%3Dmedia%26token%3Dd22e4599-ad95-4797-ad4b-93ceb133669a&width=768&dpr=3&quality=100&sign=e92ee41f39e21f8ab9d1fe6ab81cd08c&sv=3)

### Exploitation

After some time we find a good article expalaing about some new release CVEs 

<https://attackerkb.com/assessments/25397f72-670e-4ef4-a19b-2a3a55120d18?referrer=profile>

But even is simmiliar we didnt find the real objective and still struggling, then several time my team friend got something like this 

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FXVlDdjcARvYwWAxPLfd4%252Fimage.png%3Falt%3Dmedia%26token%3Da09e7b2a-8256-43dc-8d2e-ab6a3ff9f46f&width=768&dpr=3&quality=100&sign=f1fee38c3a6c53cb64598e8b1407240e&sv=3)

After that From here, i figue out why not trying to access the path traversal like in java folder as usual im asking chat gpt for that and yep we found 200 status. But we didnt manage to get Main Controller at first.

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FirGSgGjr69ljOupbUaDe%252Fimage.png%3Falt%3Dmedia%26token%3Dbbc30eb5-996c-45b9-9da4-0b0432203cd7&width=768&dpr=3&quality=100&sign=ecc1071d59d41625bc128f36b4954016&sv=3)

We forgot that is being compiled so its not .java but .class here is the code we find

`com.cyberjawara.chall.web.javabox.controller.MainController`

MainController.class

dashboard.html

Analyzing the source code is obvious we need to access admin to get the flag so we need to construct our jwt but we need the jwt secret key. We found it in:

`com.cyberjawara.chall.web.javabox.util.JwtUtil.class`

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FLcXVkItNQajCuyCgBA4p%252Fimage.png%3Falt%3Dmedia%26token%3De72fd149-353d-40d9-bec0-0c0c7d0e0d75&width=768&dpr=3&quality=100&sign=74cf35e5a6840153ff5c10f748cc76ca&sv=3)

the key we found: `c31bcd4ffcff8e971a6ad6ddcbdc613a1246f4223c00fa37404b501ad749257c`

From here we struggle a little bit changing the jwt.io but our tem found that we need to use token.dev for the jwt thanks to @Lyyn

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FiKNsmHRLiU2WSX0c2U8Y%252Fimage.png%3Falt%3Dmedia%26token%3D38b73984-b058-4410-939a-3390eb88e6ad&width=768&dpr=3&quality=100&sign=7c5ab4ac5c1aff655bea9bf040fc3a9e&sv=3)

Then we change the jwt for the win :)

![](https://araisantai.gitbook.io/araisantai-archives/~gitbook/image?url=https%3A%2F%2F1910630273-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F3QJ17KQprZ7zDYm7AfYn%252Fuploads%252FRhjO5PrmrTR0jxgKCNYh%252Fimage.png%3Falt%3Dmedia%26token%3Dd7e5fa5f-5a1e-405a-b1ac-d18e944973ef&width=768&dpr=3&quality=100&sign=3871ca1c3f8c45cadf7bbafb6553a5e0&sv=3)

Flag: `CJ{black_box_web_testing_is_not_that_bad_and_too_guessy_right?}`

[PreviousWelcome](https://araisantai.gitbook.io/araisantai-archives)[NextHTB university 2024](https://araisantai.gitbook.io/araisantai-archives/ctf-archive/htb-university-2024)

Last updated 1 year ago
