---
title: "OSINT EXAM - FortID CTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "2025", "linkedin", "fortidctf25", "google-hacking", "discord", "fortid-ctf", "fortid-ctf-2025", "ctf-writeup"]
summary: "Check out my full write-up (including other challenges) here: <https://bjs-bytes.com/blog/fortid-ctf-writeup/>"
source:
  name: "CTFtime writeup #40679"
  url: "https://ctftime.org/writeup/40679"
original_source: "https://bjs-bytes.com/blog/fortid-ctf-writeup/"
ctf:
  name: "FortID CTF 2025"
  year: 2025
  challenge: "OSINT EXAM"
---

## Metadata

- **CTF:** FortID CTF 2025
- **Task:** OSINT EXAM
- **Author team:** CSG
- **CTFtime tags:** osint, 2025, linkedin, fortidctf25, google_hacking, discord
- **CTFtime:** <https://ctftime.org/writeup/40679>
- **Original writeup:** <https://bjs-bytes.com/blog/fortid-ctf-writeup/>

---
Check out my [full write-up](<https://bjs-bytes.com/blog/fortid-ctf-writeup/>) (including other challenges) here: <https://bjs-bytes.com/blog/fortid-ctf-writeup/>

### Misc - OSINT Exam

“Can you pass our OSINT certification exam?

`nc [0.cloud.chals.io](http://0.cloud.chals.io) 27689`”

\---

We were handed a zip folder with 6 images and the app running on that port posted an OSINT question and the answer format. Each question had to be answered before moving onto the next image.

#### Location 1

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_1.webp>)

Q: One of our branch headquarters is located @ {location1.png}. What is the full name of that coworking space and who is the managing director of that branch?

Format: \<name\\_of\\_coworking\\_space> \<managing\\_director\\_name> \<managing\\_director\\_surname>

\---

A reverse image search immediately revealed several posts that this was the LHoFT. That is the Luxemburg House of Technology (great name!). I misunderstood the question and I was looking for the managing director of LHoFT, but couldn’t find anyone with that title.

My teammates found the managing director of Blockhouse Technology at the LHoFT branch pretty quickly on the LHoFT website.

#### Location 2

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_2.webp>)

Q: One of our branch headquarters is located @ {location2.png}. What is the full address of that building?

Format: \<house\\_number> \<street\\_name> \<town> \<postcode> \<country>

\---

Initially, I thought it was the Kipling house due to a reverse image search, but I didn’t have the question at that time (before we solved Q1). Since we know we’re looking at Blockhouse Technology branches and the architecture appears to match several locations in the UK/Oxford, I tried a little google dorking. Searching “Blockhouse technology” UK office located the LinkedIn page with the correct address ([linkedin](<https://www.linkedin.com/company/blockhouse-technology-ltd/?originalSubdomain=uk>)). My teammates cracked this one first using similar methods.

#### Location 3

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_3.webp>)

Q: Our branch with the best BBQ is located @ {location3.png}. What is the full address of that building?

Format: \<street\\_name> \<house number> \<postcode> \<town> \<country>

\---

My teammates also cracked this one, while I was working on Intro - Crypto.

Reverse image search yielded nothing. We already had two offices in the UK and Luxembourg, but the Zagreb office in Croatia hadn’t been mentioned. Just a little Google Dorking was all it took to find the address, which happened to be correct.

#### Location 4

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_4.webp>)

Q: Two of our team members ran a road race together earlier this year @ {location4.png}. What city was the race at and what were their finish times (hh:mm:ss)?

Format: \<city> \<slower\\_result> \<faster\\_result>

\---

My teammates had found a [website](<https://www.greatrun.org/>) to lookup race times. And they had the Blockhouse Technology company page on LinkedIn. They started checking employees, but ran into an issue. Many accounts had blank photos and names redacted as “LinkedIn Member”. But I knew what to do. I popped it open under my account and everyone’s names and images popped up. Even though they were all the way across the world in Croatia, some were 3rd degree connections. I suspect due to being connected with a few people from Romania who I interviewed for my [podcast](<https://www.foundersascent.com/>). Because of this link (or some other random connection), LinkedIn permitted me access to their profiles.

Yeah. You need to be LinkedIn-maxing for OSINT challenges.

After trying a couple names, we tracked down the guy on the left. His LinkedIn profile picture was a bad angle and he had no facial hair and looked younger, so it took longer than it should’ve and we weren’t even sure it was him.

I used a facial recognition website to find a similar image, but the site only shared the top level domain unless I paid. But that was enough, with some Google Dorking.  
I searched: `site:<https://ioinformatics.org/> "ivan paljak"` and only got 1 search result.

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint-exam-q4-solve.webp>)

His profile for the International Olympiad in Informatics, which matched a clearer picture to his name and his LinkedIn profile. We pulled his time from the race website and started looking for his friend.

But all of our previous methods failed.

We were convinced he had no online presence.

But then my teammates noted an interesting username on the FortID CTF discord server.

ipaljak. An Admin. Ivan Paljak was in the discord.

The Blockhouse staff are the ones running the CTF. Its very possible that the other guy in the photo is also an Admin. We started cross referencing the discord Administrator usernames with the staff until one name hit on the race website.

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint-exam-q4-solve2.webp>)

And there he was. We grabbed the times and moved on to the next question.

#### Location 5

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_5.webp>)

Q: The squad from our Zagreb office took part in a local charity futsal tournament in 2024 @ {location_5.png}. What was the tournament called and what place did they win?

Format: \<tournament\\_name> \<place\\_won>

\---

My teammate, [Celina](<https://linkedin.com/in/celina-rodriguez-1773201b4>), cracked this one. In her own words:

“For 5, I found it through the e student hint in the photo. E student is a student organization that organizes the Kopacka Solidarnosti futsal tournament that happens to go to a non profit. The website only had information on the tournament from 2023 but some google dorking led me to a LinkedIn page from the winners of the 2024 tournament confirming there was a tournament that year. Then just guessing and checking the placements ?”

#### Location 6

[picture](<https://bjs-bytes.com/blog/fortid-ctf-writeup/images/misc-osint_exam-location_6.webp>)

Q: One of our senior members has an artistic side to them as you can see from the beautiful flower @ {location6.png}. What is the name of the book with that member's self-portrait on its cover?

Format: \<book title>

\---

This one actually was probably the easiest. We already had the senior staff from browsing the Blockhouse Technology website. Basic Google Dorking by searching: `“insert name” book` immediately found the textbook.

And closed a very fun and challenging OSINT series. OSINT are one of my favorite categories because they are some of the most collaborative CTF challenges and everyone seems to have a unique approach that can contribute to the search.
