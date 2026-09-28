---
title: "Secret Notes - IRON CTF 2024"
category: "web"
subcategory: "csrf"
type: "writeup"
tags: ["web", "csrf", "xss", "cookie-tossing", "flask", "secret", "notes", "iron-ctf", "iron-ctf-2024", "2024", "ctf-writeup"]
summary: "Admin Bot Behavior: In typical XSS challenges, the admin bot visits the page first (after login)."
source:
  name: "CTFtime writeup #39556"
  url: "https://ctftime.org/writeup/39556"
original_source: "https://abdulhaq.me/blog/iron-ctf-2024/#web-secret-notes"
ctf:
  name: "IRON CTF 2024"
  year: 2024
  challenge: "Secret Notes"
---

## Metadata

- **CTF:** IRON CTF 2024
- **Task:** Secret Notes
- **Author team:** 1nf1n1ty
- **CTFtime tags:** csrf, xss, cookie-tossing
- **CTFtime:** <https://ctftime.org/writeup/39556>
- **Original writeup:** <https://abdulhaq.me/blog/iron-ctf-2024/#web-secret-notes>

---
Challenge Structure  
Admin Bot Behavior: In typical XSS challenges, the admin bot visits the page first (after login). However, in this case, url which your given is visited first,and then the admin bot will login. so we need to be persistent with our attack

CSRF (Cross-Site Request Forgery):

No CSRF Protection: The application lacks CSRF protection, meaning you can send requests from any site to the application’s /login endpoint.  
Force Login To Attacker1 Account: You can create a malicious page with a hidden form that submits a login request to the /login endpoint of the application. When a victim visits this page, it triggers a login attempt, allowing you to log them into Attacker1 account.  
Payload Execution: After the admin is logged into Attacker1 account, you can execute JavaScript payload present in Attacker1’s profile page.  
Cookie Tossing and Cookie Precedence:

Cookie Jar: The browser stores cookies in a structure called the “cookie jar.” If too many cookies are set, old cookies are removed to make space for new ones.  
Removing Cookies: You can exploit this by adding more cookies to the jar, pushing out old cookies like the session cookie. This effectively logs the Attacker1 out by removing their session.  
we need this trick because we need to have our cookie in certain location only but not in all the locations.  
Setting Attacker2’s Session Cookie: By setting your own session cookie with a Path parameter pointing to /profile, you can make the browser send Attacker2 cookie to the server whenever the admin visits their profile page. This happens because the cookie path takes precedence.  
Flask & HttpOnly: While HttpOnly cookies cannot be accessed via JavaScript, Flask (or most web frameworks) doesn’t care about this flag when parsing request it will get the first cookie. The server accepts any valid cookie during requests, even if it’s not HttpOnly with the name session.  
Exploiting the Admin’s Profile Page:

Cookie Path Precedence: When the admin visits /profile, the browser will send Attacker2 session cookie instead of admin’s, meaning the admin loads Attacker2 profile, which has our final step of the exploit.  
It will open a window and retrive the flag form the /notes endpoint  
Steps Summarized  
Log in to the Attacker1 account via a CSRF attack to exploit the XSS vulnerability on the profile page.

Use the XSS to perform a Cookie Jar Overflow attack, which overwrites the session cookie with a new session cookie belonging to Attacker2, but with the Path attribute set to /profile.

This new session cookie is for the Attacker2 account, which also contains the XSS payload. When the admin bot logs in and get redirected to /profile page, the browser sends Attacker2’s cookie instead of the admin’s session cookie, due to cookie path precedence. This triggers the XSS payload in Attacker2’s profile.

Once the XSS is triggered, the payload can open the admin’s notes page, which will use the admin’s session cookie, allowing the exfiltration of the notes’ content.

The problem now is that we can’t use more than 31 characters, so we need to use a reference object to store our payload. Since the admin bot uses page.goto, which means it changes the URL in the browser instead of opening a new tab, we can set [window.name](http://window.name) to store our payload and use it later whenever needed.

Full writeup is [here](<https://abdulhaq.me/blog/iron-ctf-2024/#web-secret-notes>)
