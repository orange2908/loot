---
title: "Open My Vault Live - CTF@CIT 2026"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "jwt", "graphql", "hashcat", "open", "vault", "live", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Author: by 10splayaSec"
source:
  name: "CTFtime writeup #40743"
  url: "https://ctftime.org/writeup/40743"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Open My Vault Live"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Open My Vault Live
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40743>

---
# Open My Vault Live — Writeup

\- Category: Misc  
\- Value: 974 pts  
\- Author: by **10splayaSec**

## Challenge

> One of the challenge authors is also a sponsor this year. During a recent  
> YouTube livestream, something may have been left behind. Most people didn't  
> notice.... but it's still there.  
>  
> Can you find the flag?

Flag format: `CIT{test_flag}`

## Recon (the long way)

**Identify the sponsor-author.** The CIT sponsor page lists MRE Security.  
GitHub has a public profile [10splayaSec](<https://github.com/10splayaSec>)  
(Evan Isaac, Twitter `@10splayaSec`) — so the challenge author *is* on the MRE  
Security YouTube channel.

**Find the livestream.** MRE Security's "Learning With A Hacker" series has 8  
past livestreams. The obvious match for "Open My Vault" is **EP 2 — Live API  
Hacking: OpenVault Bank** (`4BxNi9kNN-4`, streamed 2026-03-18).

**Hunt for the flag through every API/DB surface** (all rabbit trails):

\- `GET /api/v1/health` leaks `database_url`, version, and `OVB{h3alth_ch3ck_l3aks_ev3rything}`.  
\- `GET /api/v1/debug` reveals `OVB{d3bug_endp0int_sh0uld_b3_d1sabl3d}`, hints at  
an admin password ("predictable"), and confirms BOLA on `/admin/accounts`.  
\- `POST /api/v1/auth/token` with `[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection) / admin123` logs in as admin.  
\- The leaked DSN is a live Supabase Postgres. `psql` into it, dump every  
schema: `public.{users,accounts,payments,transactions,api_logs,jwt_secrets_to_try}`,  
`vault.{secrets,decrypted_secrets}`, `net._http_response`, `storage.*`,  
`realtime.*`, `auth.*`, `graphql_public.*`, plus every function/view/comment.  
**Zero `CIT{…}` matches anywhere.**  
\- SPA bundle (`[openvaultbank.com/assets/index-*.js](http://openvaultbank.com/assets/index-*.js)`) — no `CIT{…}`.  
\- JWT secret — hashcat mode 16500, rockyou + best64 on an L4 (156 MH/s) —  
exhausted in 7 s, no hit. Signing key is random.

Every automated path is sterile. The description hint "Most people didn't  
notice.... but it's still there" makes more sense now — **the flag is  
on-screen in the recording**, not in the app.

## Solve

Live chat at **59:43**:

> `@ChampBreed: I think your last image review the frag on health check :)`

Scrub EP 2 to the **INTERMISSION** card immediately after Evan finishes the  
OpenVault Bank walk-through. At **1:01:34** he has a Mousepad scratchpad  
visible beside the Burp window:

```text  
1 CIT{M@n@g3d_R1sk_3xpert5}  
2  
3  
4  
5  
```

Line 1 is the flag, sitting in his note-taking buffer from prepping the  
stream. Most viewers skip the intermission — the chat comment at 59:43 is the  
only person who noticed.

"Managed Risk Experts" = MRE Security's tagline; "5" is the episode cadence  
pun / typical leet trailing `s → 5`.

## Flag

```text  
CIT{M@n@g3d_R1sk_3xpert5}  
```

## Notes — the dead ends worth recording

\- **The leaky `/health` DSN is a real Supabase credential**; opening the  
`vault.secrets` and `vault.decrypted_secrets` tables fits the challenge name  
perfectly, but both are empty. Gorgeous red herring.  
\- **`/admin/stats` is gated by an `X-Analytics-Key` that's not the JWT secret,  
not the admin password, not `apisec-admin-key`** (that's just the  
sessionStorage key name in the React bundle). Not needed for the flag.  
\- **Signup / password-reset flow** leaks `debug_code` and lets you take over  
accounts (e.g. `testing123!`) — lab design, not the flag.  
\- This is a **pure OSINT / scrubbing challenge masquerading as an API-hacking  
one**. Zero code needed; all the "vulnerabilities" in OVB are noise.

## Files

\- [scripts/[pg_dump.py](http://pg_dump.py)](scripts/[pg_dump.py](http://pg_dump.py)) — Supabase DB dump across every schema  
\- [scripts/[pg_hunt_vault.py](http://pg_hunt_vault.py)](scripts/[pg_hunt_vault.py](http://pg_hunt_vault.py)) — `vault.*` + global `CIT{` grep  
\- [other/ovb.openapi.json](other/ovb.openapi.json) — OVB OpenAPI spec snapshot  
\- [solution/flag.txt](solution/flag.txt) — recovered flag
