---
title: "Open Seasame - PatriotCTF 2024"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "ssrf", "command-injection", "open", "seasame", "patriotctf", "patriotctf-2024", "2024", "ctf-writeup"]
summary: "The challenge provided two files - server.py and admin.js, and a link to a web application that lets us enter a URL path that the bot will visit, which means this challenge is probably XSS or SSRF-rel"
source:
  name: "CTFtime writeup #39480"
  url: "https://ctftime.org/writeup/39480"
original_source: "https://www.thesecuritywind.com/post/patriotctf-2024-open-seasame-web"
ctf:
  name: "PatriotCTF 2024"
  year: 2024
  challenge: "Open Seasame"
---

## Metadata

- **CTF:** PatriotCTF 2024
- **Task:** Open Seasame
- **Author team:** WindTeam
- **CTFtime tags:** xss
- **CTFtime:** <https://ctftime.org/writeup/39480>
- **Original writeup:** <https://www.thesecuritywind.com/post/patriotctf-2024-open-seasame-web>

---
The challenge provided two files - [server.py](http://server.py) and admin.js, and a link to a web application that lets us enter a URL path that the bot will visit, which means this challenge is probably XSS or SSRF-related.

Let's dive into the source code and see where the flag is mentioned, so we can think about the next steps.

Unfortunately, I did not find any mentions of a flag, but we can see in '[server.py](http://server.py)' that a secret value is read from 'secret.txt'.  
Later in the code, we can see that this secret value needs to be set in the cookies for the '/api/cal' API endpoint. We can also see that it is probably possible to exploit a command injection vulnerability, using the 'modifier' parameter. It would look something like: 

?modifier=;ls 

Maybe we can tell the bot to visit this API endpoint if the bot has the secret in its cookies, and somehow send us the command injection results.  
Looking at the 'admin.js' file, we can see that the bot has the secret in its cookies, but we cannot tell it to visit any URLs that include 'cal' or '%'.   
So we need to find another way to make the bot access the API endpoint vulnerable to the command injection.  
We can add a high score in the system by sending 'username' and 'high_score' parameters and we will receive a UUID.  
And this API endpoint returns the high score UUID data.  
This is the main functionality of the web app. We need to retrieve the secret value to be able to exploit the command injection, or to make the bot access it.  
We can try to inject a script as the 'username' parameter's value in the '/api/stats' endpoint and then, tell the bot to visit the UUID that contains the XSS payload.   
The script tells the bot to access '/api/cal/?modifier=;cat secret.txt' (the endpoint vulnerable to command injection), and to read the 'secret.txt' file. Then it will create a new image with the source of our server, and to append the response of '/api/cal' as an image URL parameter's value.   
An image element is used instead of a simle ajax request request to bypass the same-origin policy requirements which are not applied to images.  
We tell the bot to visit the malicious UUID  
The bot request to our server includes the contents of 'secret.txt' file.  
We can now use the secret to find the flag file and read it.
