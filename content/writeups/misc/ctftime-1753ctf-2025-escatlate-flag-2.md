---
title: "Escatlate (flag #2) - 1753CTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "unicode-normalization", "escatlate", "1753ctf", "1753ctf-2025", "2025", "ctf-writeup"]
summary: "We know that we need an 'admin' role, but the registration functionality checks if we register with the administrative role:"
source:
  name: "CTFtime writeup #40158"
  url: "https://ctftime.org/writeup/40158"
original_source: "https://www.thesecuritywind.com/post/1753ctf-2025#viewer-h84kf25011"
ctf:
  name: "1753CTF 2025"
  year: 2025
  challenge: "Escatlate (flag #2)"
---

## Metadata

- **CTF:** 1753CTF 2025
- **Task:** Escatlate (flag #2)
- **Author team:** WindTeam
- **CTFtime:** <https://ctftime.org/writeup/40158>
- **Original writeup:** <https://www.thesecuritywind.com/post/1753ctf-2025#viewer-h84kf25011>

---
We know that we need an 'admin' role, but the registration functionality checks if we register with the administrative role:  
if(req.body.role?.toLowerCase() == 'admin')  
As we previously saw, the flag will be exposed only if the output of 'role.toUpperCase()' would be 'ADMIN':  
if(req.user.role.toUpperCase() === 'ADMIN')  
return res.json({ message: `Hi Admin! Your flag is ${process.env.ADMIN_FLAG}` });  
It means that we need to find an input for the 'role' value which will behave like this:  
role.toLowerCase() == 'admin' //false  
role.toUpperCase() === 'ADMIN' //true  
And the solution for this is to use a character that looks like 'i' instead of the 'i' in 'admin' (Unicode normalization), for example 'Latin Small Letter Dotless I':
