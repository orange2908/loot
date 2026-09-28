---
title: "Silent Oracle - 0xV01D CTF 2026"
category: "web"
subcategory: "sqli"
type: "writeup"
tags: ["web", "sqli", "graphql", "sqlite", "silent", "oracle", "0xv01d-ctf", "0xv01d-ctf-2026", "2026", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40811"
  url: "https://ctftime.org/writeup/40811"
original_source: "https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/silent-oracle-0xv01d-ctf-2026"
ctf:
  name: "0xV01D CTF 2026"
  year: 2026
  challenge: "Silent Oracle"
---

## Metadata

- **CTF:** 0xV01D CTF 2026
- **Task:** Silent Oracle
- **Author team:** Team0Skills
- **CTFtime:** <https://ctftime.org/writeup/40811>
- **Original writeup:** <https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/silent-oracle-0xv01d-ctf-2026>

---
For the complete documentation index, see [llms.txt](https://l1nuxkid.gitbook.io/l1nuxkid-docs/llms.txt). This page is also available as [Markdown](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/silent-oracle-0xv01d-ctf-2026.md).

> **Event:** [0xV01D CTF 2026](https://ctftime.org/event/3269/)

Field

Details

Challenge

Silent Oracle

Category

Web Exploitation

Type

GraphQL → SQLi → UNION-based data extraction

Difficulty

Medium

**Attack Path:**

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F3jFor2hXOFfZbLS5rBTn%252Fimage.png%3Falt%3Dmedia%26token%3D15c98cf7-06f9-4e88-a4a9-503628ab0733&width=768&dpr=3&quality=100&sign=f296c20eb5ed1abeeed931b48a946aa5&sv=3)

###  Initial Recon

Visiting the website revealed a simple message: a small internal directory exposed a GraphQL endpoint. The public field looked harmless at first glance. Running the default provided query returned a list of users with the following fields:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FjFyVp8RL7LAW5Ajpadwr%252Fimage.png%3Falt%3Dmedia%26token%3D59e214b8-4734-49b8-9f13-d6958dd702ed&width=768&dpr=3&quality=100&sign=54304f1b934f7b929942f0bc64ea4622&sv=3)

Multiple users came back with bios, display names, and roles but no flags or obvious secrets. The `search` parameter immediately stood out as worth probing.

### Vulnerability discovery

**Step 1 SQL injection confirmation**

The `search` parameter caught my attention. It seemed to be filtering users based on input.

  * I injected a classic tautology into the `search` parameter:


![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FWCGSUHchMmZJ2qfcvPRE%252Fimage.png%3Falt%3Dmedia%26token%3D37b4a06e-da3c-4286-aeb2-8b9d3cf1d161&width=768&dpr=3&quality=100&sign=8909c4a06e0bc3c048eaf4429154f0f0&sv=3)

**Result:** All users were returned, ignoring the original search filter. This confirmed a **SQL injection vulnerability** in the `search` parameter. _**SQL injection confirmed.**_

**Step 2 Column enumeration**

  * To find how many columns the underlying query returns, I used `ORDER BY`:


![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FrSd8P3ZIBtBHdqHG8kN9%252Fimage.png%3Falt%3Dmedia%26token%3De3fc8dd2-b992-4c66-9248-bb07720d314d&width=768&dpr=3&quality=100&sign=616c24c43831556da28c69af4ca4f78c&sv=3)

  * `ORDER BY 5` → success

  * `ORDER BY 6` → error


Column mapping (by position in UNION):

Position

GraphQL Field

1

id

2

username

3

displayName

4

role

5

bio

**Step 3 Database fingerprinting**

I used a UNION-based payload to identify the database engine:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FGCe3JmRkH68R7MFwDr7R%252Fimage.png%3Falt%3Dmedia%26token%3D05bd6c07-73bc-4598-95bd-6d53d4e025af&width=768&dpr=3&quality=100&sign=1bac37d1fc93d73eb6dfb3c5210c2b1a&sv=3)

The `username` field returned `3.46.1`. This confirmed the backend is **SQLite**.

**Step 4 List all tables**

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252F6vYkF9NmmD1Ok6TooBBL%252Fimage.png%3Falt%3Dmedia%26token%3D81fc0245-cdef-4c57-9234-a58ca03d0800&width=768&dpr=3&quality=100&sign=4adf5f7bf873361868742a2e983da552&sv=3)

**Tables found:** `users`, `audit_log` , `sqlite_sequence`

**Step 5 Extract the schema**

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FDARlDldTFU5DcUkL8txa%252Fimage.png%3Falt%3Dmedia%26token%3D8e634dda-bc2b-4ccb-b4e6-150726a9b962&width=768&dpr=3&quality=100&sign=7e97a38aada3ef6d308a8c6e8e784179&sv=3)

Two key observations from the schema:

  * The database column is `display_name`, not `displayName` (GraphQL aliases it)

  * A `secret` column exists not exposed in the GraphQL schema at all


**Step 6 Extract the flag**

Now I directly selected the `secret` column from the `users` table:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FnokE7j2ZpojYE6SHwl8Y%252Fimage.png%3Falt%3Dmedia%26token%3D82da164f-c554-47c6-9c63-0e9dc93129bf&width=768&dpr=3&quality=100&sign=55ab485b267c9e69a54cad1ad0b6a8fb&sv=3)

The `bio` field (mapped to the 5th column position) now contains the `secret` column values. One entry held the flag. 🎉

### Lessons learned

  * **GraphQL is not SQL injection proof.** If the resolvers pass user input directly to a SQL query, the attack surface is identical to REST.

  * `**ORDER BY**`**and**`**UNION**`**work the same way** regardless of whether the entry point is GraphQL or a traditional form — the vulnerability lives in the backend, not the API layer.

  * **SQLite's**`**sqlite_master**` is your best friend for schema enumeration without needing `information_schema`.

  * **Hidden columns are a real risk.** The `secret` column was never surfaced in the GraphQL schema, yet it was fully accessible via UNION injection. Never assume unexposed fields are safe.


[PreviousSpotiVibe 1 - K!nd4SUS CTF 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/spotivibe-1-k-nd4sus-ctf-2026)[NextBeta app - Hackअस्त्र 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/beta-app-hack-2026)

Last updated 4 months ago
