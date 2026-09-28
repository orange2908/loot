---
title: "Infinite Queue - NahamCon CTF 2025"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "jwt", "infinite", "queue", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "In this challenge there is a website in which we need to buy a ticket, but we are added to a long queue."
source:
  name: "CTFtime writeup #40281"
  url: "https://ctftime.org/writeup/40281"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/InfiniteQueue"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "Infinite Queue"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** Infinite Queue
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40281>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/web/InfiniteQueue>

---
> Solved by Legend

In this challenge there is a website in which we need to buy a ticket, but we are added to a long queue.

![](<https://i.imgur.com/sf9G3EA.png>)

There was a JWT token to us which contains the info for our ticket.

![](<https://i.imgur.com/BQEzHAg.png>)

So I modified the value for `queue_time` but got an error because the token's signature was failing, but the server responded with too much information including the `queue_time`. 

![](<https://i.imgur.com/pjWycz6.png>)

I used the `JWT_SECRET` to sign the token which I modified and got in to purchase the ticket.

![](<https://i.imgur.com/q4m9Sz2.png>)

Once the purchase is done we can get the flag from the API request of the ticket PDF.

![](<https://i.imgur.com/D5GR7Mr.png>)

**Key Learning and Takeaways**

\- Don’t trust JWTs blindly they can be modified if the secret is known or weak.  
\- Error messages can leak useful information always read them carefully.  
\- JWT signing is a common web security flaw when secrets are exposed or guessable.
