---
title: "Ask, and It Shall Be Given to You - Texas Security Awareness Week 2024"
category: "web"
type: "writeup"
tags: ["robots.txt", "error", "web", "post", "flask", "werkzeug", "burp", "texas-security-awareness-week", "texas-security-awareness-week-2024", "2024", "ctf-writeup"]
summary: "The flag is at 3.23.56.243:9008."
source:
  name: "CTFtime writeup #38959"
  url: "https://ctftime.org/writeup/38959"
original_source: "https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/web/ask-and-it-shall-be-given-to-you.html"
ctf:
  name: "Texas Security Awareness Week 2024"
  year: 2024
  challenge: "Ask, and It Shall Be Given to You"
---

## Metadata

- **CTF:** Texas Security Awareness Week 2024
- **Task:** Ask, and It Shall Be Given to You
- **Author team:** reCAPTCHA the Flag
- **CTFtime tags:** robots.txt, error, web, post
- **CTFtime:** <https://ctftime.org/writeup/38959>
- **Original writeup:** <https://nightxade.github.io/ctf-writeups/writeups/2024/Texsaw-CTF-2024/web/ask-and-it-shall-be-given-to-you.html>

---
The flag is at 3.23.56.243:9008. Unfortunately it seems like the site is down right now :( . Maybe you can ask someone for help? Don't blow up their inbox though :) and make sure you clearly tell them what you want. 

\---

Visiting the [site](http://3.23.56.243:9008/), we are presented the following message, and nothing else: 

```  
Website down! please contact IT for more information  
```

Checking /robots.txt, we find some info: 

```  
USER AGENTS: *  
DISALLOW contactIT  
DISALLOW countdown  
```

Visiting /contactIT, we get this message: 

```  
Post:Json Request Only  
```

And /countdown returns some page with Pennywise in the background and the text "27 years." 

Heading into Burp Suite, we can send the request to /contactIT to the Repeater. Let's change the method to POST and resend the request: 

```yaml  
POST /contactIT HTTP/1.1  
Host: 3.23.56.243:9008  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Accept-Encoding: gzip, deflate, br  
Accept-Language: en-US,en;q=0.9  
Connection: close  
```

The response: 

```html  
HTTP/1.1 415 UNSUPPORTED MEDIA TYPE  
Server: Werkzeug/3.0.1 Python/3.12.2  
Date: Sun, 24 Mar 2024 20:05:59 GMT  
Content-Type: text/html; charset=utf-8  
Content-Length: 215  
Connection: close

<html lang=en>  
<title>415 Unsupported Media Type</title>  
<h1>Unsupported Media Type</h1>  


Did not attempt to load JSON data because the request Content-Type was not 'application/json'.

```

Seems like we need to set the Content-Type header to "application/json". I also added some JSON into the data section to see if it'd produce a response: 

```yaml  
POST /contactIT HTTP/1.1  
Host: 3.23.56.243:9008  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Accept-Encoding: gzip, deflate, br  
Accept-Language: en-US,en;q=0.9  
Connection: close  
Content-Length: 15  
Content-Type: application/json

{"years": "27"}  
```

The response: 

```html  
HTTP/1.1 500 INTERNAL SERVER ERROR  
Server: Werkzeug/3.0.1 Python/3.12.2  
Date: Sun, 24 Mar 2024 20:10:40 GMT  
Content-Type: text/html; charset=utf-8  
Content-Length: 15591  
Connection: close

<html lang=en>  
<head>  
<title>TypeError: argument of type 'NoneType' is not iterable  
// Werkzeug Debugger</title>  
<link rel="stylesheet" href="?__debugger__=yes&cmd=resource&f=style.css">  
<link rel="shortcut icon"  
href="?__debugger__=yes&cmd=resource&f=console.png">  
<script src="?__debugger__=yes&cmd=resource&f=debugger.js"></script>  
<script>  
var CONSOLE_MODE = false,  
EVALEX = true,  
EVALEX_TRUSTED = false,  
SECRET = "WYleT8qx5TNo2HMQyp6Q";  
</script>  
</head>  
<body style="background-color: #fff">  
<div class="debugger">  
<h1>TypeError</h1>  
<div class="detail">  


TypeError: argument of type 'NoneType' is not iterable  


  
</div>  
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>  
<div class="traceback">  
<h3></h3>  


  * <div class="frame" id="frame-140077653438480">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">1488</em>,  
in `__call__`</h4>  
<div class="source library">
[code]<span>    </span>) -> cabc.Iterable[bytes]:
```

  

[code]<span>        </span>"""The WSGI server calls the Flask application object as the
```

  

[code]<span>        </span>WSGI application. This calls :meth:`wsgi_app`, which can be
```

  

[code]<span>        </span>wrapped to apply middleware.
```

  

[code]<span>        </span>"""
```

  

[code]<span>        </span>return self.wsgi_app(environ, start_response)  
        <span>        </span>       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

</div>  
</div>

  * <div class="frame" id="frame-140077653438624">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">1466</em>,  
in `wsgi_app`</h4>  
<div class="source library">
[code]<span>            </span>try:
```

  

[code]<span>                </span>ctx.push()
```

  

[code]<span>                </span>response = self.full_dispatch_request()
```

  

[code]<span>            </span>except Exception as e:
```

  

[code]<span>                </span>error = e
```

  

[code]<span>                </span>response = self.handle_exception(e)  
        <span>                </span>           ^^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span>            </span>except:  # noqa: B001
```

  

[code]<span>                </span>error = sys.exc_info()[1]
```

  

[code]<span>                </span>raise
```

  

[code]<span>            </span>return response(environ, start_response)
```

  

[code]<span>        </span>finally:
```

</div>  
</div>

  * <div class="frame" id="frame-140077653438768">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">1463</em>,  
in `wsgi_app`</h4>  
<div class="source library">
[code]<span>        </span>ctx = self.request_context(environ)
```

  

[code]<span>        </span>error: BaseException | None = None
```

  

[code]<span>        </span>try:
```

  

[code]<span>            </span>try:
```

  

[code]<span>                </span>ctx.push()
```

  

[code]<span>                </span>response = self.full_dispatch_request()  
        <span>                </span>           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span>            </span>except Exception as e:
```

  

[code]<span>                </span>error = e
```

  

[code]<span>                </span>response = self.handle_exception(e)
```

  

[code]<span>            </span>except:  # noqa: B001
```

  

[code]<span>                </span>error = sys.exc_info()[1]
```

</div>  
</div>

  * <div class="frame" id="frame-140077653438912">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">872</em>,  
in `full_dispatch_request`</h4>  
<div class="source library">
[code]<span>            </span>request_started.send(self, _async_wrapper=self.ensure_sync)
```

  

[code]<span>            </span>rv = self.preprocess_request()
```

  

[code]<span>            </span>if rv is None:
```

  

[code]<span>                </span>rv = self.dispatch_request()
```

  

[code]<span>        </span>except Exception as e:
```

  

[code]<span>            </span>rv = self.handle_user_exception(e)  
        <span>            </span>     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span>        </span>return self.finalize_request(rv)
```

  

[code]<span></span> 
```

  

[code]<span>    </span>def finalize_request(
```

  

[code]<span>        </span>self,
```

  

[code]<span>        </span>rv: ft.ResponseReturnValue | HTTPException,
```

</div>  
</div>

  * <div class="frame" id="frame-140077653439056">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">870</em>,  
in `full_dispatch_request`</h4>  
<div class="source library">
[code]<span></span> 
```

  

[code]<span>        </span>try:
```

  

[code]<span>            </span>request_started.send(self, _async_wrapper=self.ensure_sync)
```

  

[code]<span>            </span>rv = self.preprocess_request()
```

  

[code]<span>            </span>if rv is None:
```

  

[code]<span>                </span>rv = self.dispatch_request()  
        <span>                </span>     ^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span>        </span>except Exception as e:
```

  

[code]<span>            </span>rv = self.handle_user_exception(e)
```

  

[code]<span>        </span>return self.finalize_request(rv)
```

  

[code]<span></span> 
```

  

[code]<span>    </span>def finalize_request(
```

</div>  
</div>

  * <div class="frame" id="frame-140077653439200">  
<h4>File <cite class="filename">"/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)"</cite>,  
line <em class="line">855</em>,  
in `dispatch_request`</h4>  
<div class="source library">
[code]<span>            </span>and req.method == "OPTIONS"
```

  

[code]<span>        </span>):
```

  

[code]<span>            </span>return self.make_default_options_response()
```

  

[code]<span>        </span># otherwise dispatch to the handler for that endpoint
```

  

[code]<span>        </span>view_args: dict[str, t.Any] = req.view_args  # type: ignore[assignment]
```

  

[code]<span>        </span>return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)  # type: ignore[no-any-return]  
        <span>        </span>       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span></span> 
```

  

[code]<span>    </span>def full_dispatch_request(self) -> Response:
```

  

[code]<span>        </span>"""Dispatches the request and on top of that performs request
```

  

[code]<span>        </span>pre and postprocessing as well as HTTP exception catching and
```

  

[code]<span>        </span>error handling.
```

</div>  
</div>

  * <div class="frame" id="frame-140077653439344">  
<h4>File <cite class="filename">"/app/[webapp.py](http://webapp.py)"</cite>,  
line <em class="line">26</em>,  
in `submitted`</h4>  
<div class="source ">
[code]<span>    </span>if request.method == 'POST':
```

  

[code]<span>        </span>content = request.get_json()
```

  

[code]<span>        </span>sender = content.get('email')
```

  

[code]<span>        </span>messege = content.get('messege')
```

  

[code]<span>        </span>f.setSender(sender)
```

  

[code]<span>        </span>f.checkResponds(messege)  
        <span>        </span>^^^^^^^^^^^^^^^^^^^^^^^^
```

  

[code]<span>    </span>else:
```

  

[code]<span>        </span>return "Post:Json Request Only"
```

  

[code]<span>    </span>return "Email Sent!"
```

  

[code]<span></span> 
```

  

[code]<span></span>@app.route("/countdown")
```

</div>  
</div>

  * <div class="frame" id="frame-140077653439488">  
<h4>File <cite class="filename">"/app/[floaty.py](http://floaty.py)"</cite>,  
line <em class="line">17</em>,  
in `checkResponds`</h4>  
<div class="source ">
[code]<span>    </span>def setSender(self, email):
```

  

[code]<span>        </span>self.sendto = email
```

  

[code]<span></span> 
```

  

[code]<span></span>#Check Responds for flag or fake
```

  

[code]<span>    </span>def checkResponds(self, responds):
```

  

[code]<span>        </span>if "flag" in responds:  
        <span>        </span>   ^^^^^^^^^^^^^^^^^^
```

  

[code]<span>            </span>self.sendFlag()
```

  

[code]<span>        </span>else:
```

  

[code]<span>            </span>self.sendFake()
```

  

[code]<span></span> 
```

  

[code]<span></span>#Send Flag if requested
```

</div>  
</div>  


  
<blockquote>TypeError: argument of type 'NoneType' is not iterable  
</blockquote>  
</div>

<div class="plain">  


  
This is the Copy/Paste friendly version of the traceback.  


  
<textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 1488, in __call__  
return self.wsgi_app(environ, start_response)  
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 1466, in wsgi_app  
response = self.handle_exception(e)  
^^^^^^^^^^^^^^^^^^^^^^^^  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 1463, in wsgi_app  
response = self.full_dispatch_request()  
^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 872, in full_dispatch_request  
rv = self.handle_user_exception(e)  
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 870, in full_dispatch_request  
rv = self.dispatch_request()  
^^^^^^^^^^^^^^^^^^^^^^^  
File "/usr/local/lib/python3.12/site-packages/flask/[app.py](http://app.py)", line 855, in dispatch_request  
return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args) # type: ignore[no-any-return]  
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  
File "/app/[webapp.py](http://webapp.py)", line 26, in submitted  
f.checkResponds(messege)  
File "/app/[floaty.py](http://floaty.py)", line 17, in checkResponds  
if "flag" in responds:  
^^^^^^^^^^^^^^^^^^^  
TypeError: argument of type 'NoneType' is not iterable  
</textarea>  
</div>  
<div class="explanation">  
The debugger caught an exception in your WSGI application. You can now  
look at the traceback which led to the error. <span>  
If you enable JavaScript you can also use additional features such as code  
execution (if the evalex feature is enabled), automatic pasting of the  
exceptions and much more.</span>  
</div>  
<div class="footer">  
Brought to you by **DON'T PANIC** , your  
friendly Werkzeug powered traceback interpreter.  
</div>  
</div>

<div class="pin-prompt">  
<div class="inner">  
<h3>Console Locked</h3>  


  
The console is locked and needs to be unlocked by entering the PIN.  
You can find the PIN printed out on the standard output of your  
shell that runs the server.  
<form>  


PIN:  
<input type=text name=pin size=14>  
<input type=submit name=btn value="Confirm Pin">  
</form>  
</div>  
</div>  
</body>  
</html>

```

That's long... 

But, notably, after scrolling through, I noticed it seemed to be outputting the lines in the source code! Perfect. Let's try and write out what's going on, starting from line 139: 

This is /app/[webapp.py](http://webapp.py): 

```py  
def unknown_func():  
if request.method == "POST":  
content = request.get_json()  
sender = content.get("email")  
messege = content.get("messege")  
f.setSender(sender)  
f.checkResponds(messege)  
else:  
return "Post:Json Request Only"  
return "Email Sent!"

@app.route("/countdown")  
```

And this is /app/[floaty.py](http://floaty.py): 

```py  
class unknown_class:  
def setSender(self, email):  
self.sendto = email

#Check Responds for flag or fake  
def checkResponds(self, responds):  
if "flag" in responds:  
self.sendFlag()  
else:  
self.sendFake()  
#Send Flag if requested  
```

Seems like we need to include a json object with an "email" and a "messege". The "email" should be one we can access, while the "messege" should just include the flag. Thus, the final request is as follows: 

```yaml  
POST /contactIT HTTP/1.1  
Host: 3.23.56.243:9008  
Upgrade-Insecure-Requests: 1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
Accept-Encoding: gzip, deflate, br  
Accept-Language: en-US,en;q=0.9  
Connection: close  
Content-Length: 66  
Content-Type: application/json

{  
"email": "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)",  
"messege": "flag"  
}  
```

The response: 

```html  
HTTP/1.1 200 OK  
Server: Werkzeug/3.0.1 Python/3.12.2  
Date: Sun, 24 Mar 2024 20:16:55 GMT  
Content-Type: text/html; charset=utf-8  
Content-Length: 11  
Connection: close

Email Sent!  
```

Check your email for the flag! 

texsaw{7h15_15_7h3_r34l_fl46_c0n6r47ul4710n5}
