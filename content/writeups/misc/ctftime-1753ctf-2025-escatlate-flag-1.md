---
title: "Escatlate (flag #1) - 1753CTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "escatlate", "1753ctf", "1753ctf-2025", "2025", "ctf-writeup"]
summary: "The challenge provided a URL and the source code of 'index.js'"
source:
  name: "CTFtime writeup #40157"
  url: "https://ctftime.org/writeup/40157"
original_source: "https://www.thesecuritywind.com/post/1753ctf-2025#viewer-ie6q91289"
ctf:
  name: "1753CTF 2025"
  year: 2025
  challenge: "Escatlate (flag #1)"
---

## Metadata

- **CTF:** 1753CTF 2025
- **Task:** Escatlate (flag #1)
- **Author team:** WindTeam
- **CTFtime:** <https://ctftime.org/writeup/40157>
- **Original writeup:** <https://www.thesecuritywind.com/post/1753ctf-2025#viewer-ie6q91289>

---
The challenge provided a URL and the source code of 'index.js'  
After I opened 'index.js', I immediately searched for the keyword 'flag' to get an idea of what I should do.  
It looks like there are two separate flags for the two different challenges.  
If the user role is admin, the server will send the admin flag when accessing the '/api/message' endpoint. If the user role is moderator, it will send the moderator flag.  
I searched for the keyword 'moderator' and there were no other places with this keyword.  
I continued reading the code, specifically the '/api/register' endpoint.   
We can see that this function checks if the user already exists (line 85-86), validates that the 'role' parameter in the request body is not the admin role (88-89), and then creates the user.  
So it might be simple - all we have to do is register with the 'moderator' role.  
And we can access the flag.
