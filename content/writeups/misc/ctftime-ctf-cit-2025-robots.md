---
title: "Robots - CTF@CIT 2025"
category: "misc"
type: "writeup"
tags: ["misc", "gobuster", "robots", "ctf-cit", "ctf-cit-2025", "2025", "ctf-writeup"]
summary: "Hey, Zul from Singapore here representing Spectra Secondary School."
source:
  name: "CTFtime writeup #40208"
  url: "https://ctftime.org/writeup/40208"
ctf:
  name: "CTF@CIT 2025"
  year: 2025
  challenge: "Robots"
---

## Metadata

- **CTF:** CTF@CIT 2025
- **Task:** Robots
- **Author team:** Infinity Code Asia
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40208>

---
Hey, [Zul](<http://linkedin.com/in/zulfaqarnet>) from Singapore here representing Spectra Secondary School.

I'll be doing a writeup for the challenge "ROBOTS"  
![figure 1.0:<https://drive.google.com/file/d/1fMYKljHl3rNqIvLJJcHbTUlxTMA0v04t/view?usp=sharing>](<https://drive.google.com/file/d/1fMYKljHl3rNqIvLJJcHbTUlxTMA0v04t/view?usp=sharing>)

This challenge consist of basic web pentesting fundelmental (Maybe not exactly web pentesting. But still consider one)  
I litterally didn't focus the word during this challenge, and didn't solved it. But after I read it carefully and try something and I realized my mistake.

\-----  
**What will you be learning from this challenge?**  
* Basic web crawling  
* Basic keyboard shortcuts (^_^ YES! Basic shortcut on getting the flag)

\-----  
**EH ZUL WHAT"S WEB CRAWLING AH? WHAT IS WEB PENTESTING?**  
chill- chill!   
web pentesting is a cyberattack techniques of breaking an web application and web services (*unauthorizedly or authorizedly!*)  
And Web crawling is part of web pentesting techniques. **This technique focus on reading the web app sub-pages** (best way to explain to litle kid bahahaha).  
There are few ways we can obtain this information.

**What are the ways?**  
1\. robot crawler/ user-agent  
2\. sitemap/ web maps  
3\. HTML Page Link Following (similar to number 2)  
4\. subdomain scanning (this one like AD and uhhh your gobuster! :3)

in this case we're looking specifically at number 1. The reasson why we use this is because the title of the challenge is call "ROBOTS".

\-----  
  
**What is User-Agent??**  
imagine you're visiting a site and you type a domain, how can it automatically know where to go?  
Well, your browser send a metadata tag to your computer on what are the pages they can go and cannot go (basically hide away from the main view).  
So how they communicate is through your HTTP header (which is your browser and fetching information back from it to your browser "Not exactly what I'm saying. But yapping indeed"). 

**How do I do this?**  
you can typically type   
> robots.txt  
for example..  
><https://example.com/robots.txt>  
yeah, just add "**robots.txt**" at the end of the url using "/"

\-----  
**STEP 1) ACCESSING WEB CRAWLER**  
for this challenge we use **robots.txt**. Add this guy at the end of the ctf platform website itself. Like this: https://ctf.cyber-cit.club/robots.txt  
You should see this massive dumpster rubish idk whats its gonna be call..  
![figure 1.2:<https://drive.google.com/file/d/13JnQv8PTgN4wpR_udYdU8pvtFjA5Hun3/view?usp=sharing> ](<https://drive.google.com/file/d/13JnQv8PTgN4wpR_udYdU8pvtFjA5Hun3/view?usp=sharing>)

\-----  
**STEP 2) FINDING READ AND ANALYZE. OR JUST USE A SHORTCUT KEY MAYBE U GET THE FLAG HEHEHE**  
Alright, now you have few option. **1) ANALYZE THE WHOLE CRAWLER MANUALLY (TIME CONTRAINING)** or **2) USING A SHORTCUT KEY AND STRAIGHT AWAY GETTING THE FLAG**.

If you wanna go for the short key. There's this special shortcut on your computer call **"ctrl + f"** or on ** mac "⌘F"** 

if you wanna go for the analyzing, this typically depend on certain situation. So, there's this word call "allow" and "disallow". All you need to focus is on "disallow",  
Sometime you lucky and sometime you're not lucky. But by manually doing this, you can explore more pages and learn how each pages work.  
And sometime they aren't a dead giftaway like this challenge. Worth trying analyzing the whole user-agent rather than trying your luck to give in this challenge.

eventually, you shall see this highlighted web page on this user-agent/crawler. COPY IT AND MAKE SURE IT DON'T RANAWAY FROM YOU! CATCH AND TRAP IT!!  
BAHAHAHAHAHA THAT'S YOUR FLAG AND YOUR SLAVE. MAKE SURE ITS NOT RUNNING AWAY FROM YOU. PUT IT INTO UR SLAVE CAGE **>:3**  
![Figure 1.3: <https://drive.google.com/file/d/1MnMu-ttaC-TMjoMxH6kqmBc-OQpDDidr/view?usp=sharing>](<https://drive.google.com/file/d/1MnMu-ttaC-TMjoMxH6kqmBc-OQpDDidr/view?usp=sharing>)

\-----  
**STEP 3) COPY AND PASTE THE FLAG INTO THE PLATFORM**  
so how to copy?  
Okay guys! this is a simple toturial, use your typical mouse or touchpad. Move your cursor on the CIT{...} and then hold shift and arrow key left. Or on mac do the same but shift + command + arrow key to the left. :3  
YAY! CONGRATS U HAVE COPIED AND TRAP YOUR FLAG INTO A SLAVE CAGE.   
Now go to https://ctf.cyber-cit.club/ and paste it on the challenge!  
![Figure 1.4:<https://drive.google.com/file/d/1EIcqRPuZuo2XWXELAdfSD7tTEQgqlYdO/view?usp=sharing>](<https://drive.google.com/file/d/1EIcqRPuZuo2XWXELAdfSD7tTEQgqlYdO/view?usp=sharing>)  
**FLAG: CIT{m6F2nr8RgjYI}**
