---
title: "Object Storage Misconfiguration - S3, GCS and Azure Blob"
category: cloud
subcategory: storage
type: technique
tags: [cloud, s3, gcs, azure-blob, object-storage, bucket, misconfiguration, public-access, acl, bucket-policy, anonymous, listing, enumeration, versioning, data-exposure, presigned-url]
difficulty: easy
summary: "Public or over-permissive buckets let anyone list and read (sometimes write) objects; enumerate the bucket, list it, and pull the objects."
when_to_use:
  - "The challenge references a bucket name, an S3/GCS/Blob URL, or 'cloud storage'"
  - "A web app loads assets from *.s3.amazonaws.com, storage.googleapis.com, or *.blob.core.windows.net"
  - "You have credentials and want to find readable buckets"
  - "You need to find old/deleted data via versioning"
tools: [awscli, gsutil, az, curl, s3scanner]
related: [aws-enumeration-privesc, cloud-metadata-ssrf, serverless-attacks, aws-cli-cheatsheet]
---

## TL;DR

Object stores default to private, but misconfiguration (a public ACL, an over-broad bucket policy,
"all authenticated users") re-opens them. The workflow is: find the bucket name, test anonymous and
authenticated listing, then read (and check for write and for old versions).

## Recognise it

- URLs like `https://<name>.s3.amazonaws.com/`, `https://s3.<region>.amazonaws.com/<name>/`,
  `https://storage.googleapis.com/<name>/`, `https://<acct>.blob.core.windows.net/<container>/`.
- A web page whose assets, uploads, or backups come from one of those hosts.
- The challenge gives a bucket name outright, or a hint to guess one (`company-backups`, `-dev`,
  `-assets`, `-logs`).
- A `403` on the bucket root but `200` on a specific known key -> listing off, reads on.

## Theory

### The two access models (S3)

1. **ACLs** - legacy per-object/per-bucket grants. The dangerous grantees are
   `http://acs.amazonaws.com/groups/global/AllUsers` (anyone) and `.../AuthenticatedUsers` (any AWS
   account, a common misunderstanding - it is *not* just your account).
2. **Bucket policies** - JSON documents; `"Principal": "*"` with `s3:GetObject` makes objects
   world-readable, and with `s3:ListBucket` makes the bucket world-listable. `s3:PutObject` to `*`
   is world-writable (defacement / malware hosting).

`Block Public Access` (account and bucket level) overrides both; when it is off, the ACL/policy
takes effect. In a CTF the challenge has typically turned it off.

### Listing vs reading

These are distinct permissions:
- **List** (`s3:ListBucket`) returns the keys.
- **Read** (`s3:GetObject`) returns an object's content.

A bucket can be readable-but-not-listable (you must know the key) or listable-but-not-readable
(you see names, not content). Check both.

### GCS and Azure equivalents

- **GCS**: IAM bindings (`allUsers`/`allAuthenticatedUsers` with `roles/storage.objectViewer` or
  `objectAdmin`) plus legacy ACLs. `storage.buckets.list` vs `storage.objects.get`.
- **Azure Blob**: a container's public access level is `private`, `blob` (read individual blobs
  anonymously) or `container` (anonymous list + read). SAS tokens are time-limited signed URLs;
  a leaked SAS with `sp=rwl` is read/write/list.

### Versioning and deletion

If versioning is enabled, "deleted" objects persist as prior versions. `s3api list-object-versions`
reveals them; a flag removed from the current version may still be in an old one. Delete markers
hide but do not erase.

## Procedure

### Find the bucket name

```bash
# from a web app: watch the network tab / grep the HTML and JS
curl -s https://target.example | grep -oE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com'
curl -s https://target.example | grep -oE 'storage\.googleapis\.com/[a-z0-9._-]+'
# guess from the org name (common suffixes)
for s in backup backups assets static uploads dev staging prod logs data private; do
  echo "$ORG-$s"; done
```

### S3

```bash
BUCKET=example-bucket

# anonymous listing (no credentials)
aws s3 ls "s3://$BUCKET" --no-sign-request
curl -s "https://$BUCKET.s3.amazonaws.com/"          # returns XML key listing if public-list
curl -s "https://s3.amazonaws.com/$BUCKET/"          # path style

# anonymous read of a known key
aws s3 cp "s3://$BUCKET/flag.txt" - --no-sign-request
curl -s "https://$BUCKET.s3.amazonaws.com/flag.txt"

# authenticated listing (with credentials in the env)
aws s3 ls "s3://$BUCKET"
aws s3api list-objects-v2 --bucket "$BUCKET" --query 'Contents[].Key' --output text

# old / deleted versions
aws s3api list-object-versions --bucket "$BUCKET" --query 'Versions[].[Key,VersionId]' --output text
aws s3api get-object --bucket "$BUCKET" --key flag.txt --version-id VERSION out.txt

# read the ACL / policy to understand exposure
aws s3api get-bucket-acl --bucket "$BUCKET"
aws s3api get-bucket-policy --bucket "$BUCKET"

# test writability (non-destructive: a uniquely-named probe object)
echo probe > /tmp/probe.txt
aws s3 cp /tmp/probe.txt "s3://$BUCKET/probe-$RANDOM.txt" --no-sign-request
```

### GCS

```bash
BUCKET=example-bucket
# anonymous
curl -s "https://storage.googleapis.com/$BUCKET/"                    # XML listing if public
curl -s "https://storage.googleapis.com/storage/v1/b/$BUCKET/o"      # JSON API listing
gsutil ls "gs://$BUCKET" 2>/dev/null
gsutil cp "gs://$BUCKET/flag.txt" - 2>/dev/null
# IAM bindings (with credentials)
gsutil iam get "gs://$BUCKET"
```

### Azure Blob

```bash
ACCT=exampleacct; CONTAINER=data
# anonymous list (only if access level is 'container')
curl -s "https://$ACCT.blob.core.windows.net/$CONTAINER?restype=container&comp=list"
# anonymous blob read (access level 'blob' or 'container')
curl -s "https://$ACCT.blob.core.windows.net/$CONTAINER/flag.txt"
# with the Azure CLI and credentials
az storage blob list --account-name "$ACCT" --container-name "$CONTAINER" --output table
# a leaked SAS URL is used as-is
curl -s "https://$ACCT.blob.core.windows.net/$CONTAINER/flag.txt?sp=r&sig=..."
```

## Code - a read-only exposure checker

```python
#!/usr/bin/env python3
"""Check object-storage exposure across S3 / GCS / Azure Blob, read-only.

Tests anonymous LIST and READ over plain HTTP(S). Reports what is exposed; it does
not attempt writes and does not require any SDK.

Python 3.11+, standard library only. Usage:
    python3 storage_check.py s3 my-bucket
    python3 storage_check.py gcs my-bucket
    python3 storage_check.py azure myacct mycontainer
    python3 storage_check.py --self-test
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

TIMEOUT = 8


def fetch(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def parse_s3_keys(xml_body: str) -> list[str]:
    """Extract <Key> entries from an S3/GCS XML listing (namespace-agnostic)."""
    keys: list[str] = []
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return keys
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == "Key" and el.text:
            keys.append(el.text)
    return keys


def check_s3(bucket: str) -> None:
    print(f"=== S3: {bucket} ===")
    for style in (f"https://{bucket}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{bucket}/"):
        code, body = fetch(style)
        print(f"  LIST {style} -> HTTP {code}")
        if code == 200:
            keys = parse_s3_keys(body)
            print(f"    PUBLIC LIST: {len(keys)} key(s): {keys[:15]}")
        elif code == 403:
            print("    listing denied (bucket may still allow reads of known keys)")
        elif code == 404:
            print("    bucket not found / no such bucket")


def check_gcs(bucket: str) -> None:
    print(f"=== GCS: {bucket} ===")
    code, body = fetch(f"https://storage.googleapis.com/{bucket}/")
    print(f"  LIST https://storage.googleapis.com/{bucket}/ -> HTTP {code}")
    if code == 200:
        print(f"    PUBLIC LIST: {len(parse_s3_keys(body))} key(s)")
    code, body = fetch(f"https://storage.googleapis.com/storage/v1/b/{bucket}/o")
    print(f"  JSON API -> HTTP {code}")


def check_azure(account: str, container: str) -> None:
    print(f"=== Azure Blob: {account}/{container} ===")
    url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
    code, body = fetch(url)
    print(f"  LIST -> HTTP {code}")
    if code == 200:
        names = [el.text for el in ET.fromstring(body).iter()
                 if el.tag.rsplit('}', 1)[-1] == "Name" and el.text] if body.strip().startswith("<") else []
        print(f"    PUBLIC LIST ('container' access): {len(names)} blob(s): {names[:15]}")
    elif code in (403, 404):
        print("    anonymous list not permitted (may still allow 'blob' level reads)")


def check_read(url: str) -> None:
    code, body = fetch(url)
    print(f"  READ {url} -> HTTP {code}" + (f", {len(body)} bytes" if code == 200 else ""))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    provider = argv[0]
    if provider == "s3" and len(argv) >= 2:
        check_s3(argv[1])
    elif provider == "gcs" and len(argv) >= 2:
        check_gcs(argv[1])
    elif provider == "azure" and len(argv) >= 3:
        check_azure(argv[1], argv[2])
    else:
        print(__doc__)
        return 1
    if "--read" in argv:
        check_read(argv[argv.index("--read") + 1])
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        xml = ('<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
               "<Contents><Key>a.txt</Key></Contents><Contents><Key>b/c.txt</Key></Contents>"
               "</ListBucketResult>")
        keys = parse_s3_keys(xml)
        assert keys == ["a.txt", "b/c.txt"], keys
        assert parse_s3_keys("not xml") == []
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main(sys.argv[1:]))
```

## Variants & pitfalls

- **`AuthenticatedUsers` is not "my account"** - it is *any* AWS account. A bucket granting it is
  public to anyone who authenticates with any AWS credentials, including `--no-sign-request` failing
  but a free-tier account succeeding.
- **Region redirects**: an S3 request to the wrong region returns a 301 with the correct endpoint;
  follow it (`--region`).
- **Path style vs virtual-hosted style**: both `bucket.s3.amazonaws.com` and
  `s3.amazonaws.com/bucket` exist; try both, and the regional forms
  (`s3.eu-west-1.amazonaws.com/bucket`).
- **Listing off, reads on**: a `403` on `/` does not mean the bucket is safe - known keys may still
  be readable. Harvest key names from the app's HTML/JS.
- **Versioning**: the flag may be in a prior version even after "deletion". Always
  `list-object-versions`.
- **Writable buckets**: `s3:PutObject` to `*` lets you overwrite site assets (stored XSS, supply
  chain). Test with a uniquely named probe object, and clean up.
- **Presigned / SAS URLs** carry their own auth in the query string; treat a leaked one as a
  credential with the embedded permissions and expiry.
- **GCS uniform vs fine-grained**: uniform bucket-level access disables object ACLs; exposure is
  then purely via IAM bindings.
- **Bucket name guessing** is a real technique but generates noise; enumerate from the app first.

## Hardening checklist

- Enable S3 Block Public Access at the account level; use it as the default.
- Never grant `AllUsers`/`AuthenticatedUsers` ACLs or `"Principal": "*"` policies unless the data is
  intentionally public.
- Use GCS uniform bucket-level access and Azure "private" container access as defaults.
- Scope presigned/SAS URLs to the minimum permission and shortest lifetime.
- Enable versioning plus MFA-delete for buckets holding sensitive data, and monitor with Access
  Analyzer.

## Tools

- `aws` CLI (`s3`, `s3api`), `gsutil`, `az storage`.
- `s3scanner`, `cloud_enum`, `GCPBucketBrute` - bucket discovery and permission testing.
- `ScoutSuite`, `Prowler` - posture reporting.

## References

- AWS documentation: "Blocking public access to your Amazon S3 storage", "Bucket policy examples".
- Google Cloud documentation: "Making data public", "Uniform bucket-level access".
- Microsoft documentation: "Configure anonymous public read access for containers and blobs".
