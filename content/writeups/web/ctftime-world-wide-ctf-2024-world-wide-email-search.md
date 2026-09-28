---
title: "World Wide Email Search - World Wide CTF 2024"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "blind-sqli", "nosql-injection", "ssti", "command-injection", "flask", "sqlite", "unicode-normalization", "world-wide-ctf", "world-wide-ctf-2024", "2024", "ctf-writeup"]
summary: "I think this was the first time I was part of one of the first teams to solve a hard challenge in a big CTF."
source:
  name: "CTFtime writeup #39699"
  url: "https://ctftime.org/writeup/39699"
original_source: "https://www.thesecuritywind.com/post/world-wide-ctf-2024-world-wide-email-search-web"
ctf:
  name: "World Wide CTF 2024"
  year: 2024
  challenge: "World Wide Email Search"
---

## Metadata

- **CTF:** World Wide CTF 2024
- **Task:** World Wide Email Search
- **Author team:** WindTeam
- **CTFtime:** <https://ctftime.org/writeup/39699>
- **Original writeup:** <https://www.thesecuritywind.com/post/world-wide-ctf-2024-world-wide-email-search-web>

---
I think this was the first time I was part of one of the first teams to solve a hard challenge in a big CTF. We were the third team to solve it (it ended with 7 solves out of ~580 teams). Sagiv and I worked together on this challenge and it was enriching and fun, especially because I tried a lot of different things along the way and learned new things.

The solution to this challenge might seem a bit straightforward or easy but I think what made it a hard challenge were the subtle hints and limited suspicious behaviors, which affected the leads. 

So instead of writing a concise writeup, I'll explain how we got there.

After entering the URL we see that we can enter an email address and could probably retrieve the results for that email address.  
I wanted to understand what technology is in use, but didn't see any indications of that, so I used the 404 error message to understand what the technology might be.   
According to this useful article, the web app is probably written in Python, using Flask.  
Back to the main functionality. Searching for a certain email address results in these messages.  
Two different messages - interesting. Maybe it indicates something?  
An invalid email format results in this error and it doesn't reflect the input. Also, interesting - why wouldn't it reflect the input?  
We tried to understand the web application's behavior, fuzzed a little bit, and tried different injections, which didn't work.  
The web application removed the following characters from the input:  
'  
"  
\  
some whitespace characters

At this point we had a few ideas:

SSTI using the reflection of the email address. Although it reflected inputs like {{7*7}}@gmail.com without evaluating them, we wondered if we needed to enter an input that would be both a valid template and a valid email format from start to end.

We wondered if we should find the correct email address to retrieve the flag. If so, maybe NoSQL injection or blind SQL injection could help with that. 

Some of the email addresses were reflected in the server's response while others were decoded so maybe it had something to do with it. After a quick search, we realized it's just a Cloudflare service for encoding email addresses against bots scraping.

Maybe there's a system command on the backend that is used and we can exploit it to perform command injection?

Right before continuing, one of the first things that came to my mind was a research article by Gareth that I had wanted to read for some time now, and I thought it might be related (I highly recommend reading it). Most of it talks about how various valid unpopular email formats can be valid email addresses, while they might cause security issues. 

We thought about whether we could enter an input that would be considered a valid email format but would later be parsed as something different which could help us with our leads. Unfortunately nothing worked. HOWEVER, one of the things that Gareth mentioned was Unicode overflows.

I tried that and it didn't work. I'm not sure if it's because it works differently in Python or because of another reason. But I tried to copy the weird 'l' characters (I tried the other ones as well) and it turned it to a normal 'l'.

I know this Python's behavior. It's Unicode normalization. Sometimes it can be used to bypass blacklists when trying to bypass sandboxes or maybe with when trying to exploit SSTI too.

We tried a few things and then we've thought - "wait, if we can turn characters to other ones like к to k, can we do that for other characters? For example for a single quote?

We got some ideas from perplexity:

Note that the first character is not a backtick which didn't work for this challenge.

Eventually, we had a lead! The left single quotation mark was reflected as a single quote in the first message and resulted in a syntax error in the second message.

So it's SQLite. From here, the solution might be pretty straightforward.

Just to make sure.

Table structure (we replaced spaces with /**/).

TL;DR: 

The user enters an email address.

The web application only supposedly allows a valid email format, and removes single quotes, double quotes and whitespaces from the input.

Python has Unicode normalization, so it turns the left single quotation mark into a single quote. 

Using that, it's possible to use this and /**/ as a substitute for whitespace to craft an SQL injection payload to retrieve the flag. 

![](<https://static.wixstatic.com/media/e8e84d_a5a897403d454808be536b48ff231871~mv2.jpg>)
