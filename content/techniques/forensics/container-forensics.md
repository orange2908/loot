---
title: "Docker, Container and Cloud-Log Forensics"
category: forensics
subcategory: container
type: technique
tags: [docker, container, overlay2, whiteout, docker-save, docker-export, containerd, crictl, kubernetes, k8s, kubelet, etcd, cloudtrail, vpc-flow-logs, gcp-audit-logs, azure-activity-log, jq, dive, image-layers, dfir]
difficulty: medium
summary: "Reconstruct what ran inside a container from /var/lib/docker or a docker save tarball, read layer whiteouts, and triage CloudTrail/GCP/Azure logs with jq."
when_to_use:
  - "The image contains /var/lib/docker, or you were handed a .tar from docker save/export"
  - "The challenge asks what a container did, or what a Dockerfile layer deleted"
  - "You have Kubernetes pod logs, an etcd snapshot, or a kubelet filesystem"
  - "You were handed CloudTrail / VPC flow / S3 access / GCP audit JSON and must find the intruder"
tools: [docker, dive, skopeo, crictl, ctr, nerdctl, etcdctl, jq, tar]
related: [disk-linux-forensics, disk-image-triage, git-forensics, disk-file-carving]
---

## TL;DR

Everything a container **wrote** lives in its overlay2 **upper** (`diff`) directory -- that one
directory is the whole "what did the attacker do" answer. Everything a Dockerfile **deleted**
lives as a `.wh.` whiteout in a later layer, the original still intact in the earlier one.
Offline, a `docker save` tarball gives you both without a daemon.

## Recognise it

- The image has `/var/lib/docker/`, `/var/lib/containerd/` or `/var/lib/rancher/`; a `.tar`
  whose root holds `manifest.json` + `<sha256>/layer.tar` is `docker save`, one whose root is
  `bin/ etc/ usr/` is `docker export`, and `/var/log/pods/` means a Kubernetes node. JSON
  objects carrying `eventVersion`, `eventSource`, `eventName` are AWS CloudTrail.

## Artifact anatomy: Docker on disk

```text
overlay2/<id>/diff/                     the layer's files (the "upper" for a container)
image/overlay2/imagedb/content/sha256/<id>        image CONFIG: Env, Cmd, history
image/overlay2/layerdb/mounts/<cid>/mount-id      container -> its writable layer
containers/<cid>/config.v2.json   name, created, image, Env, Cmd, mounts, exit code, State
containers/<cid>/hostconfig.json  Privileged, CapAdd, Binds, NetworkMode = the escape surface
containers/<cid>/<cid>-json.log   stdout/stderr, one JSON object per line, RFC3339Nano
volumes/<name>/_data/             named volumes: data that SURVIVED container deletion
```

**overlay2 is a stack**: `lowerdir` layers are read-only image layers, `upperdir` is the
container's writable layer, `merged` is the union, and a modified file is copied up into `upper`
in full. A deleted file becomes a **whiteout**: a 0/0 char device on a live overlayfs, a
zero-length `.wh.<name>` inside a layer **tar** (`.wh..wh..opq` for a directory). `RUN rm -f
/secret` only adds `.wh.secret` to the next layer; the original stays readable in the one before.

## Triage: live, then offline

```sh
# every container incl. stopped, full metadata, and the path of the writable layer
docker ps -a --no-trunc; docker inspect -f '{{.GraphDriver.Data.UpperDir}}' <c>
# WHAT CHANGED vs the image (A/C/D) - the fastest "what did they do" - plus logs and Env
docker diff <c>; docker logs -t <c>
# how the image was built (--build-arg secrets live here), then export the container
# FILESYSTEM (writable layer, no history) vs save the IMAGE (all layers, all whiteouts)
docker history --no-trunc <image>
docker export <c> > c.tar; docker save <image> > img.tar; docker cp <c>:/etc/shadow ./shadow
# OFFLINE: unpack a docker save tarball; manifest.json holds the layer ORDER and config blob
mkdir img && tar -xf img.tar -C img && jq . img/manifest.json
# every whiteout in every layer = every file DELETED by a later build step
for l in img/*/layer.tar; do echo "== $l"; tar -tf "$l" | grep -E '(^|/)\.wh\.'; done
# the original still lives in an EARLIER layer; then grep names and content across all layers
tar -xf img/<earlier>/layer.tar -O path/to/secret
for l in img/*/layer.tar; do tar -xOf "$l" 2>/dev/null | grep -aoE 'AKIA[0-9A-Z]{16}'; done
# layer TUI and conversion; volumes outlive containers; CRI hosts (ctr/crictl/runc) differ
dive --source docker-archive img.tar; skopeo copy docker-archive:img.tar dir:./unpacked
# from a dead host: the stdout log (config.v2.json and hostconfig.json sit beside it)
jq -r '.time + " " + .stream + " " + .log' var/lib/docker/containers/<id>/<id>-json.log
# map the container to its writable layer, then grep everything it ever wrote
cat var/lib/docker/image/overlay2/layerdb/mounts/<id>/mount-id
grep -rniaE 'flag\{|password|BEGIN OPENSSH' var/lib/docker/overlay2/<mount-id>/diff/
```

## Kubernetes

Node artifacts: `/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log` (CRI-format logs, symlinked
from `/var/log/containers/`); `/var/lib/kubelet/pods/<uid>/volumes/` (projected secrets and
configmaps); `/etc/kubernetes/manifests/` (**static pods** = node-level persistence);
`/etc/kubernetes/{admin,kubelet}.conf` plus `pki/`; `/var/lib/etcd/member/{snap,wal}`.

```sh
# CRI lines are "<rfc3339nano> <stdout|stderr> <F|P> <msg>"; kubelet's journal has pulls and
# mounts, and /var/run/secrets/kubernetes.io/serviceaccount/token is a full API credential
tail -50 /var/log/pods/default_web-0_*/app/0.log
# static pods run forever - check what they execute and whether they escape the namespace
grep -rn 'image:\|command:\|hostPID\|hostNetwork' etc/kubernetes/manifests/
# etcd: snapshot status needs no cluster; `snapshot restore --data-dir ./x` then
# `etcdctl get /registry/secrets --prefix` reads every Secret (PROTOBUF PLAINTEXT on disk)
ETCDCTL_API=3 etcdctl snapshot status snapshot.db --write-out=table
strings -a snapshot.db | grep -aiE 'flag\{|password|token'
```

## Cloud logs

**CloudTrail** is NDJSON or `{"Records":[...]}`, gzipped under `AWSLogs/<acct>/CloudTrail/...`;
fields: `eventTime`, `eventName`, `eventSource`, `userIdentity.arn`/`.type`/`.accessKeyId`,
`sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`, `errorCode`.
**VPC flow logs** (v2) are space-separated `version account-id interface-id srcaddr dstaddr
srcport dstport protocol packets bytes start end action log-status`. **S3 access logs** are
`bucket-owner bucket time remote-ip requester request-id operation key request-uri http-status
error-code bytes-sent object-size total-time turn-around-time referer user-agent`. **GCP** uses
`protoPayload.methodName`, `.authenticationInfo.principalEmail`, `.requestMetadata.callerIp`,
`.authorizationInfo[].granted`, `.status.code`; **Azure** uses `time`, `operationName.value`,
`resultType`, `callerIpAddress`, `identity.claims`, plus `userPrincipalName` and
`status.errorCode` in sign-in logs.

```sh
# flatten gzipped trail files, then the core who/what/when/where view
zcat AWSLogs/**/*.json.gz | jq -c '.Records[]' > events.jsonl
jq -r '[.eventTime,.userIdentity.arn,.sourceIPAddress,.eventName] | @tsv' events.jsonl | sort
# failures (AccessDenied bursts = enumeration), then persistence: new users, keys, roles
jq -r 'select(.errorCode) | [.eventTime,.errorCode,.eventName,.userIdentity.arn] | @tsv' events.jsonl
jq -r 'select(.eventName | test("CreateUser|CreateAccessKey|AttachUserPolicy|CreateRole"))
       | [.eventTime,.eventName,.userIdentity.arn,.requestParameters.userName] | @tsv' events.jsonl
# defence evasion (logging off), then exfiltration (bulk reads, snapshot sharing)
jq -r 'select(.eventName | test("StopLogging|DeleteTrail|PutEventSelectors|DeleteFlowLogs"))
       | [.eventTime,.eventName,.userIdentity.arn] | @tsv' events.jsonl
jq -r 'select(.eventName | test("GetObject|ListBucket|CopyObject|ModifySnapshotAttribute"))
       | [.eventTime,.eventName,.requestParameters.bucketName] | @tsv' events.jsonl
# VPC: top ACCEPTed talkers by bytes (add $8==6 && $7!=443 for odd-port TCP egress)
awk '$13=="ACCEPT" {b[$4" "$5":"$7]+=$10} END{for(k in b) print b[k], k}' flows.log | sort -rn | head
# GCP: caller/method/IP (Azure is the same shape over .operationName.value / .resultType,
# with sign-in error 50126 = bad password and 50074 = MFA needed)
jq -r '[.timestamp,.protoPayload.authenticationInfo.principalEmail] | @tsv' gcp.jsonl
```

## Code

```python
#!/usr/bin/env python3
"""Walk an extracted `docker save` tarball: layers, whiteouts and regex hits.

manifest.json gives the layer order and the image config; every `.wh.` entry is a
file DELETED by that layer whose original is still readable in an earlier one.
Run: tar -xf img.tar -C ./img && python3 docker_layers.py ./img --grep 'AKIA[A-Z0-9]{16}'
"""
import argparse, json, os, re, sys, tarfile

MAX_GREP = 8 << 20
WH, OPQ = ".wh.", ".wh..wh..opq"

def whiteouts(names):
    """Split member names into (opaque dirs, paths deleted by this layer)."""
    opaque, deleted = [], []
    for name in names:
        base = os.path.basename(name)
        if base == OPQ:
            opaque.append(os.path.dirname(name) or ".")
        elif base.startswith(WH):
            deleted.append(os.path.join(os.path.dirname(name), base[len(WH):]))
    return opaque, deleted

def scan_layer(path, pattern):
    """Return (names, opaque, deleted, hits) for one layer tar."""
    names, hits = [], []
    with tarfile.open(path, "r:*") as tf:
        for member in tf:
            names.append(member.name)
            if pattern is None or not member.isfile() or member.size > MAX_GREP:
                continue
            handle = tf.extractfile(member)
            if handle is not None:
                hits += [(member.name, m.group(0).decode("utf-8", "replace"))
                         for m in pattern.finditer(handle.read())]
    opaque, deleted = whiteouts(names)
    return names, opaque, deleted, hits

def analyse(root, pattern):
    """Read manifest.json and scan each layer tar it lists."""
    layers, config, manifest = [], {}, os.path.join(root, "manifest.json")
    if os.path.exists(manifest):
        with open(manifest) as fh:
            entry = (json.load(fh) or [{}])[0]
        layers = entry.get("Layers", [])
        rel = entry.get("Config")
        if rel and os.path.exists(os.path.join(root, rel)):
            with open(os.path.join(root, rel)) as fh:
                config = json.load(fh)
    report = {"layers": [], "config": config}
    for index, rel in enumerate(layers):
        path = os.path.join(root, rel)
        names, opaque, deleted, hits = scan_layer(path, pattern)
        report["layers"].append({"path": rel, "opaque": opaque, "deleted": deleted,
                                 "hits": hits})
        print(f"\n=== layer {index}: {rel}  ({len(names)} entries)")
        for item in deleted:
            print(f"  [DELETED HERE] {item}  <- still present in an earlier layer")
        for item in opaque:
            print(f"  [OPAQUE DIR]   {item}  <- hides everything below it")
        for name, text in hits:
            print(f"  [HIT] {name}: {text}")
    for item in (config.get("config") or {}).get("Env") or []:
        print(f"  Env: {item}")      # image Env and `docker history` both leak build secrets
    return report

def selftest():
    """Build a two-layer fake `docker save` tree and prove the whiteout is found."""
    import io, shutil, tempfile
    root = tempfile.mkdtemp(prefix="dockertest-")
    try:
        def layer(sub, files):
            os.makedirs(os.path.join(root, sub), exist_ok=True)
            with tarfile.open(os.path.join(root, sub, "layer.tar"), "w") as tf:
                for name, payload in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            return f"{sub}/layer.tar"

        l0 = layer("aaaa", {"app/secret.txt": b"flag{deleted_in_a_later_layer}"})
        l1 = layer("bbbb", {"app/.wh.secret.txt": b"", "opt/.wh..wh..opq": b""})
        for name, blob in (("cfg.json", {"config": {"Env": ["FLAG=flag{env_leak}"]}}),
                           ("manifest.json", [{"Config": "cfg.json", "Layers": [l0, l1]}])):
            json.dump(blob, open(os.path.join(root, name), "w"))
        first, second = analyse(root, re.compile(rb"flag\{[^}]+\}"))["layers"]
        assert first["hits"] == [("app/secret.txt", "flag{deleted_in_a_later_layer}")], first
        assert second["deleted"] == ["app/secret.txt"] and second["opaque"] == ["opt"], second
        print("\nselftest OK - whiteout and earlier-layer secret both recovered")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default="./img")
    ap.add_argument("--grep", default=r"flag\{[^}]+\}")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not os.path.isdir(args.root):
        print(f"not a directory: {args.root}", file=sys.stderr)
        return 1
    analyse(args.root, re.compile(args.grep.encode()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""CloudTrail triage: flatten, filter and summarise AWS CloudTrail JSON.

Takes a directory (recursing into .json/.json.gz/.jsonl), one file, or stdin, and
handles both the {"Records":[...]} wrapper and NDJSON. Prints per-principal, per-IP
and per-API counts, then flags events matching known techniques.
Run: python3 cloudtrail_triage.py ./AWSLogs --ip 198.51.100.7
"""
import argparse, collections, gzip, io, json, os, re, sys

SUSPICIOUS = {
    "persistence": re.compile(r"^(CreateUser|CreateAccessKey|CreateLoginProfile|CreateRole"
                              r"|AttachUserPolicy|PutUserPolicy|UpdateAssumeRolePolicy)$"),
    "defense-evasion": re.compile(r"^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors"
                                  r"|DeleteFlowLogs|DisableSecurityHub|PutBucketLogging)$"),
    "exfiltration": re.compile(r"^(GetObject|ListBucket|CopyObject|CreateSnapshot|Decrypt"
                               r"|ModifySnapshotAttribute|GetSecretValue|GetParameters?)$"),
    "discovery": re.compile(r"^(List|Describe|Get)(Users|Roles|Policies|Buckets|Instances"
                            r"|Secrets|AccountAuthorizationDetails|CallerIdentity)$")}

def events_from_text(text: str):
    text = text.strip()
    if not text:
        return
    try:
        blobs = [json.loads(text)]
    except json.JSONDecodeError:                 # NDJSON: one JSON object per line
        blobs = []
        for line in text.splitlines():
            try:
                blobs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for blob in blobs:
        if isinstance(blob, dict):
            yield from (blob["Records"] if "Records" in blob else [blob])
        elif isinstance(blob, list):
            yield from blob

def load_events(source):
    """Read stdin, one file, or every JSON/gzipped-JSON file under a directory."""
    if source is None:
        yield from events_from_text(sys.stdin.read())
        return
    paths = [source] if os.path.isfile(source) else [
        os.path.join(d, n) for d, _s, fs in os.walk(source) for n in sorted(fs)
        if n.endswith((".json", ".json.gz", ".jsonl", ".gz"))]
    for path in paths:
        try:
            with (io.TextIOWrapper(gzip.open(path, "rb"), errors="replace")
                  if path.endswith(".gz") else open(path, errors="replace")) as fh:
                yield from events_from_text(fh.read())
        except (OSError, gzip.BadGzipFile) as exc:
            print(f"[!] {path}: {exc}", file=sys.stderr)

def principal(event: dict) -> str:
    ident = event.get("userIdentity") or {}
    return (ident.get("arn") or ident.get("userName") or ident.get("invokedBy")
            or ident.get("type") or "unknown")

def classify(event: dict):
    return [k for k, rx in SUSPICIOUS.items() if rx.match(event.get("eventName", ""))]

def summarise(events):
    counters = {k: collections.Counter() for k in ("principals", "ips", "events", "errors")}
    flagged = collections.defaultdict(list)
    for event in events:
        counters["principals"][principal(event)] += 1
        counters["ips"][event.get("sourceIPAddress", "-")] += 1
        counters["events"][event.get("eventName", "-")] += 1
        if event.get("errorCode"):
            counters["errors"][event["errorCode"]] += 1
        for label in classify(event):
            flagged[label].append(event)
    counters["flagged"] = flagged
    return counters

def selftest():
    arn = "arn:aws:iam::111122223333:user/dev"
    ident = {"type": "IAMUser", "arn": arn, "accessKeyId": "AKIAEXAMPLE"}
    ev = lambda name, **kw: dict({"eventTime": "2024-03-01T10:00:00Z", "eventName": name,
                                  "sourceIPAddress": "198.51.100.7",
                                  "userIdentity": ident}, **kw)
    records = {"Records": [ev("GetCallerIdentity"), ev("CreateAccessKey"),
                           ev("StopLogging", errorCode="AccessDenied")]}
    events = list(events_from_text(json.dumps(records)))
    assert len(events) == 3 and len(list(events_from_text(
        "\n".join(json.dumps(e) for e in records["Records"])))) == 3
    assert principal(events[0]) == arn
    assert classify(events[1]) == ["persistence"] and "defense-evasion" in classify(events[2])
    summary = summarise(events)
    assert summary["ips"]["198.51.100.7"] == 3 and summary["errors"]["AccessDenied"] == 1
    assert len(summary["flagged"]["persistence"]) == len(summary["flagged"]["discovery"]) == 1
    print("selftest OK - 3 events parsed; persistence, evasion and discovery flagged")
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", nargs="?", help="file or directory (default: stdin)")
    ap.add_argument("--ip", help="exact sourceIPAddress filter")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    events = [e for e in load_events(args.source) if isinstance(e, dict)
              and (not args.ip or e.get("sourceIPAddress") == args.ip)]
    if not events:
        print("no events matched", file=sys.stderr)
        return 1
    events.sort(key=lambda e: e.get("eventTime", ""))
    print(f"{len(events)} events  {events[0].get('eventTime')} .. {events[-1].get('eventTime')}")
    summary = summarise(events)
    for title in ("principals", "ips", "events", "errors"):
        if summary[title]:
            print(f"\n=== {title}")
            for key, count in summary[title].most_common(args.top):
                print(f"  {count:>7d}  {key}")
    for label in ("persistence", "defense-evasion", "exfiltration", "discovery"):
        for event in (summary["flagged"].get(label) or [])[:args.top]:
            err = f"  !{event['errorCode']}" if event.get("errorCode") else ""
            print(f"[{label:<15s}] {event.get('eventTime')}  {event.get('eventName'):<26s} "
                  f"{event.get('sourceIPAddress', '-'):<16s} {principal(event)}{err}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`docker export` loses the layers.** For a deleted secret you need `docker save` or raw
  `/var/lib/docker/overlay2`; for what the running container did you need its `UpperDir`.
  Newer `docker save` output is the **OCI layout** (`index.json` + `blobs/sha256/<digest>`, no
  `<id>/layer.tar`) -- let `skopeo` or `dive` normalise it.
- Whiteouts exist only inside layer tars; on a live overlayfs they are 0/0 char devices, so
  `find -type c` finds them. `docker diff` showing `C /etc` is normal noise, and image
  timestamps are often normalised to epoch 0, so never build a timeline from layer mtimes.
- A `/var/run/docker.sock` bind or `"Privileged": true` means the container was root on the
  host, so the investigation does not stop at the container boundary; `--build-arg` secrets
  land in `docker history`; Kubernetes Secrets are **base64, not encrypted**.
- CloudTrail is eventually consistent (~15 min) and data-plane events (`GetObject`) are off by
  default, so their absence proves nothing; `sourceIPAddress` holds an AWS *service* name for
  service-principal calls. VPC flow logs record flows, not payloads, may be sampled, and their
  field order changes with a custom format -- read the header before trusting column numbers.

## Tools and references

`docker` (`ps`, `inspect`, `diff`, `logs`, `history`, `export`, `save`, `cp`), `dive`, `skopeo`,
`crane`, `ctr`, `crictl`, `nerdctl`, `runc`, `podman`, `etcdctl`, `kubectl`, `jq`, `trivy`.
`docker inspect --help` and `man docker-save` document the flags; the OCI Image Format spec
defines `manifest.json`, `index.json` and the `.wh.` / `.wh..wh..opq` whiteouts, and the kernel's
`filesystems/overlayfs.rst` defines overlayfs semantics. AWS, GCP and Azure publish the field
lists for CloudTrail, VPC flow, S3 access and their audit/activity logs.
