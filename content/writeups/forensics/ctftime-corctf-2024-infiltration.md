---
title: "infiltration - corCTF 2024"
category: "forensics"
subcategory: "windows"
type: "writeup"
tags: ["forensics", "evtx", "infiltration", "windows", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39354"
  url: "https://ctftime.org/writeup/39354"
original_source: "https://medium.com/@embossdotar/ctf-writeup-corctf-2024-infiltration-b39d39d46e37"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "infiltration"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** infiltration
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39354>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-corctf-2024-infiltration-b39d39d46e37>

---
Hi All, Challenge description is like below:

" forensics/infiltration  
jammy

After successfully infiltrating the lemonthinker gang, we’ve obtained their current location — the UK. We’ve attained some security logs from a gang member’s PC, but need some help in answering information relating to these.

nc [be.ax](https://be.ax) 32222 "

Challenge contains a file — security-logs.evtx

At start we can interact with given ‘[nc](<https://en.wikipedia.org/wiki/Netcat)’> to see what awaits us.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*JYNiDq1BflZKlsz1Af0NEg.png>)

netcat interaction, source: corCTF 2024 — infiltration

OK, here we can see some additional info. This part of challenge will be from the “Q&A type”. But at start we have to gather info.

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*7f5-XypW46QBAG1JJ6eVdw.png>)

Single wrong answer means disconnected

Without correct answer, you will not see the next question — so at this moment you should be familiar with attached file.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*iumJQnQRh1F7GAeDQxSi9Q.png>)

Too slow — means disconnected

Moreover, as you can see above — time is important as well as correct answers — if you’re too slow, the connection can be disconnected. There is an example of correct answer, but as result — disconnected:D

The best to gather all needed answers and at the end give the correct answers.

It’s time to investigate this!

Download mentioned file and use (to install [python-evtx](<https://pypi.org/project/python-evtx/>) package):

`pip install python-evtx`

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*931_1YnlsBFq-Eu1TRz_EA.png>)

Installing python-evtx

Package which includes tools for handling [EVTX files](<https://fileinfo.com/extension/evtx>).

Next, use:

`[evtx_dump.py](http://evtx_dump.py) security-logs.evtx > security-logs.xml`

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*G9eeIebyqsFDj3avC_9M1Q.png>)

Created security-logs.xml (opened with [Sublime](<https://www.sublimetext.com/>)), source: corCTF 2024 — infiltration

to convert the EVTX file to [XML](<https://en.wikipedia.org/wiki/XML>) format.

As you can notice, it’s quite big.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*LxY-aDC-__AfSWUetrpIPg.png>)

The last row of the file (Sublime used), source: corCTF 2024 — infiltration

It contains about 173329 rows.

You can investigate it in your own ways or with own methods, you can search with [Sublime](<https://en.wikipedia.org/wiki/Sublime_Text>) or even via Console:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*KNzDVqtNrOEC4GcjbI6UgA.png>)

cat & grep -i & tail commands in action, source: corCTF 2024 — infiltration

I hope that after reading this writeup you can have a landscape of this interesting challenge (investigation — data gathering, Q&A console interaction).

Below you can see all of the correct answers (from investigation):

1 — **slice1**  
2 — **lemon-squeezer**  
3 — **83**  
4 — **1721946160**  
5 — **notabackdoor**  
6 — **Administrators**

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*61_NIATxl5RjTr2sZ_ooKw.png>)

Epoch date — one of the solutions, source: <https://www.epochconverter.com/>

It worth to notice that to get an answer for question nr 4 you need to use [UNIX timestamp](<https://en.wikipedia.org/wiki/Unix_time>) (so, convert to).

You can use many tools, ie.: [[epochconverter.com](http://epochconverter.com)](<https://www.epochconverter.com/>)

**Final solution:**  
```  
root@[REDACTED]:~# nc [be.ax](https://be.ax) 32222  
Hello agent. Thanks for your hard work in the field researching. We’ll now ask you 6 questions on the information you’ve gathered.  
I’d like to take this opportunity to remind you that our targets are located in the United Kingdom, so their timezone is BST (UTC +1).  
We’d like to confirm what the username of the main user on the target’s computer is. Can you provide this information? **slice1**  
Correct! Excellent work.  
Now, we’d like the name of the computer, after it was renamed. Ensure that it is entered in exactly how it is in the logs. **lemon-squeezer**  
Correct! Excellent work.  
I wonder if they’ll make any lemonade with that lemon-squeezer…  
Great work! In order to prevent their lemons from moulding, the lemonthinkers changed the maximum password age. What is this value? Please enter it as an integer number in days. **83**  
Correct! Excellent work.  
It seems that our targets are incredibly smart, and turned off the antivirus. At what time did this happen? Give your answer as a UNIX timestamp. **1721946160**  
Correct! Excellent work.  
The main lemonthinker, slice1, hasn’t learnt from the-conspiracy and has (again) downloaded some malware on the system. What is the name of the user created by this malware? **notabackdoor**  
Correct! Excellent work.  
Finally, we’d like to know the name of the group that the user created by the malware is part of, which has the greatest security risk. What is this? **Administrators**  
Correct! Excellent work.  
Thank you for your hard work in the field. We’ll be in touch with your next mission soon.  
In the meantime, enjoy a flag!  
**corctf{alw4y5_l3m0n_7h1nk_b3f0r3_y0u_c0mm1t_cr1m3}**  
```

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*M2ppR3FTxWr6ZlGTgvY62Q.png>)

Flag with the correct answers, source: corCTF 2024 — infiltration

**Flag: corctf{alw4y5_l3m0n_7h1nk_b3f0r3_y0u_c0mm1t_cr1m3}**

I hope you enjoy!
