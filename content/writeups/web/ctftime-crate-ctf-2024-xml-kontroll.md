---
title: "XML-kontroll - Crate-CTF 2024"
category: "web"
subcategory: "xxe"
type: "writeup"
tags: ["web", "xxeinjection", "xxe", "xml", "xmlexternalentity", "xml-kontroll", "crate-ctf", "crate-ctf-2024", "2024", "ctf-writeup"]
summary: "Challenge description is like below:"
source:
  name: "CTFtime writeup #39661"
  url: "https://ctftime.org/writeup/39661"
original_source: "https://medium.com/@embossdotar/ctf-writeup-crate-ctf-2024-xml-kontroll-c57459443c4c"
ctf:
  name: "Crate-CTF 2024"
  year: 2024
  challenge: "XML-kontroll"
---

## Metadata

- **CTF:** Crate-CTF 2024
- **Task:** XML-kontroll
- **Author team:** ctfrrteam
- **CTFtime tags:** xxeinjection, xxe, xml, xmlexternalentity
- **CTFtime:** <https://ctftime.org/writeup/39661>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-crate-ctf-2024-xml-kontroll-c57459443c4c>

---
Hi,  
Challenge description is like below:

"XML-kontroll  
Kontrollera din XML med vår webbtjänst!  
Skriv in din XML-data, vänta några sekunder, och få (nästan) samma sträng tillbaka. Snabbt, enkelt och… ja, det är ganska meningslöst, men det fungerar (nästan) felfritt!

Servern används också för att lagra en hemlig flagga, men den är i säkert förvar i namnet på ett användarkonto så det finns (nästan) absolut ingen risk att någon läser ut den från filsystemet!

<http://challs.crate.nu:16627> "

Do you speak [Swedish](<https://en.wikipedia.org/wiki/Swedish_language)?> No? Me too (at least, not yet! But funny fact is, I’ve learnt many words taking a part there! For example ‘Golf-SM’ task, if you know what I mean:P), but as I’ve said long time ago in ‘[CTF Writeup — Hackme CTF](<https://medium.com/@embossdotar/ctf-writeup-iron-ctf-2024-math-gone-wrong-ccc0b463e38f)’> article, that will not be a problem for us, that won’t stop us!

"English version is:  
XML control  
Check your XML with our web service!  
Enter your XML data, wait a few seconds, and get (almost) the same string back. Quick, easy and… well, it’s pretty pointless, but it works (almost) flawlessly!  
The server is also used to store a secret flag, but it is in safe custody in the name of a user account so there is (almost) absolutely no risk of someone reading it from the file system!  
<http://challs.crate.nu:16627> "

There is no attachment/s.

So, need to visit given resource.

Quick note — if you want to solve it yourself, give yourself some time now — later it will be too late, because you will already see the solution; that means no such fun:P

Short note — ‘ Skicka’ means ‘Send’ in English.

Site view and the solution (payload):

![solution](<https://miro.medium.com/v2/resize:fit:786/format:webp/1*47XQ9ThAS3AST2tUpy6rZQ.png>)

Initial interaction and solution (payload), source: Crate-CTF 2024

This CTF task appears to involve uploading XML data to a server. The goal is to exploit the XML parsing process to access a file or piece of data on the server containing the flag. Since the description mentions a “secret flag” stored in a username’s file path, the task likely involves [XML External Entity (XXE) injection](<https://cwe.mitre.org/data/definitions/611.html>) or similar file manipulation through XML.

If you want to read more about this you can check article titled ‘[TryHackMe — XXE Injection — Writeup](<https://medium.com/@embossdotar/tryhackme-xxe-injection-writeup-8ae820685212)’>.

If the server does not properly validate or sanitize uploaded XML, it might be possible to use external entities to read local files on the server. Here’s an example of an XML payload to test for XXE:

![payload](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*Jd1nYCoWTxvODSs69r-v0Q.png>)

Payload — solution, source: Crate-CTF 2024

The server processes uploaded XML and returns a modified version of the XML. The mention of a “safe” flag stored in a username-based path hints that the flag might be accessible through the filesystem.  
XML parsers, if improperly configured, can allow attackers to retrieve local files using features like external entities.

The directive defines an external entity (xxe) that points to a local file, such as /etc/passwd.  
When the server processes this XML, it might replace &xx;; with the contents of the file, returning it in the response.

![result and flag](<https://miro.medium.com/v2/resize:fit:786/format:webp/1*sJFEuLwu0WmYj2_aSYQMZQ.png>)

Flag and solution (payload triggered), source: Crate-CTF 2024

**Flag: cratectf{xml_xxe_xploit_xpert}**

I hope you enjoy!
