---
title: "Ez ⛳ v2 - KalmarCTF 2024"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "base64", "kalmarctf", "kalmarctf-2024", "2024", "ctf-writeup"]
summary: "The challenge got 89 solves, and I personally got the blood on this challenge!"
source:
  name: "CTFtime writeup #39091"
  url: "https://ctftime.org/writeup/39091"
original_source: "https://seall.dev/posts/ezv2kalmarctf2024"
ctf:
  name: "KalmarCTF 2024"
  year: 2024
  challenge: "Ez ⛳ v2"
---

## Metadata

- **CTF:** KalmarCTF 2024
- **Task:** Ez ⛳ v2
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39091>
- **Original writeup:** <https://seall.dev/posts/ezv2kalmarctf2024>

---
## The Challenge

### Challenge Metadata

The challenge got 89 solves, and I personally got the blood on this challenge! ?

Here is the challenge description:

> Caddy webserver is AWESOME, using a neat and compact syntax you can do a lot of powerful things, e.g. wanna know if your browser supports [HTTP3](<https://http3.caddy.chal-kalmarc.tf/)?> Or [TLS1.3](<https://tls13.caddy.chal-kalmarc.tf/)?> etc  
> Flag is located at `GET /$(head -c 18 /dev/urandom | base64)` go fetch it.

### What are we working with?

We are given a ZIP file with multiple files consisting of webserver sourcecode.  
```  
Caddyfile  
docker-compose.yml  
flag  
README.txt  
```

### Solution

Reading through each of the files we can gather the following information initially:  
\- The `Caddyfile` contains multiple entrys for various webservers, reading the bottom of the file there's some HTML of interest:  
```html  
Hello! Wanna know you if your browser supports [http/1.1](https://http1.caddy.chal-kalmarc.tf/)? [http/2](https://http2.caddy.chal-kalmarc.tf/)? Or fancy for some [http/3](https://http3.caddy.chal-kalmarc.tf/)?! Check your preference [here](https://http.caddy.chal-kalmarc.tf/).  
We also allow you to check [TLS/1.2](https://tls12.caddy.chal-kalmarc.tf/), [TLS/1.3](https://tls13.caddy.chal-kalmarc.tf/), [TLS preference](https://tls.caddy.chal-kalmarc.tf/), supports [mTLS](https://mtls.caddy.chal-kalmarc.tf/)? Checkout your [User-Agent](https://ua.caddy.chal-kalmarc.tf/)!  
```

Giving us some new endpoints to check out:  
\- <https://http1.caddy.chal-kalmarc.tf/>  
\- <https://http2.caddy.chal-kalmarc.tf/>  
\- <https://http.caddy.chal-kalmarc.tf/>  
\- <https://tls12.caddy.chal-kalmarc.tf/>  
\- <https://tls.caddy.chal-kalmarc.tf/>  
\- <https://mtls.caddy.chal-kalmarc.tf/>  
\- <https://ua.caddy.chal-kalmarc.tf/>  
\- <https://flag.caddy.chal-kalmarc.tf/>

Ofcourse, the `flag` subdomain is down, but it was worth a shot!

\- Reading the `docker-compose.yml` we can see the file will be stored in the root directory, though we already know this from the challenge description.

\- The `flag` file and `README.txt` file are not of major importance.

So, out of the endpoints we are given in that HTML, whats likely to have our exploit? I have a strong feeling its the User-Agent one (<https://ua.caddy.chal-kalmarc.tf/>) because we can modify our User-Agent value to insert something to the page, such as SSTI!

Visiting the page, all it does is display our User-Agent on the screen.

![ua.png](https://seall.dev/images/ctfs/kalmarctf2024/ua.png)

Now, looking into what a `Caddyfile` is for, I find this [documentation](<https://caddyserver.com/docs/caddyfile>). Looking on the documentation page I search for any instances of 'template' and find a page about [templates](<https://caddyserver.com/docs/modules/http.handlers.templates#docs>), bingo!

I find a good testing value for the SSTI exploit is `{%raw%}{{now}}{%endraw%}`, which should display the time.

![now.png](https://seall.dev/images/ctfs/kalmarctf2024/now.png)

Yay! There's our exploit, now how do we read the file? Let's check that documentation again:

![docs.png](https://seall.dev/images/ctfs/kalmarctf2024/docs.png)

Well, let's give it a shot! I set my User-Agent to `{%raw%}{{listFiles "/"}}{%endraw%}` and look for an output.

![listfiles.png](https://seall.dev/images/ctfs/kalmarctf2024/listfiles.png)

There's the file: `CVGjuzCIVR99QNpJTLtBn9`, lets read it by using `{%raw%}{{readFile "/CVGjuzCIVR99QNpJTLtBn9"}}{%endraw%}` as the User-Agent.

![readfile.png](https://seall.dev/images/ctfs/kalmarctf2024/readfile.png)

Bam! And a blood too! ?

Flag: `kalmar{Y0_d4wg_I_h3rd_y0u_l1k3_templates_s0_I_put_4n_template_1n_y0ur_template_s0_y0u_c4n_readFile_wh1le_y0u_executeTemplate}`
