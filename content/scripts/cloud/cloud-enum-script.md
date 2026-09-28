---
title: "In-Container Environment Recon - Bash Fingerprint + Python Reporter"
category: cloud
subcategory: recon
type: script
tags: [cloud, container, recon, enumeration, metadata, imds, capabilities, kubernetes, service-account, docker-sock, seccomp, namespace, aws, gcp, azure, python, bash, script, fingerprint]
summary: "A read-only bash + python recon pair for a foothold in a container/VM: fingerprints the environment, reads cloud metadata, lists capabilities, and reports isolation posture."
tools: [bash, python3, curl, capsh, findmnt]
related: [container-escape, kubernetes-attacks, cloud-metadata-ssrf, container-escape-cheatsheet]
---

## Usage

```bash
# bash version -- no dependencies beyond coreutils; safe, read-only
bash recon.sh
bash recon.sh --json            # machine-readable summary at the end

# python version -- richer parsing and structured output
python3 recon.py
python3 recon.py --json
python3 recon.py --self-test    # offline checks, no environment access
```

Both are **read-only**: they enumerate what the environment exposes and report isolation posture.
They do not modify anything, do not use recovered credentials against any cloud API, and redact
secret material in their output so it is safe to paste into notes.

## Bash: `recon.sh`

```bash
#!/usr/bin/env bash
# Read-only recon for a foothold in a container or cloud VM.
# Fingerprints containment, capabilities, mounts, and cloud metadata reachability.
set -u

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

hr() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
hr "host"
uname -a 2>/dev/null
[ -r /etc/os-release ] && . /etc/os-release && echo "os: ${PRETTY_NAME:-unknown}"
echo "id: $(id 2>/dev/null)"
echo "hostname: $(hostname 2>/dev/null)"

# ---------------------------------------------------------------------------
hr "containment"
CONTAINED=0
[ -f /.dockerenv ] && { echo "/.dockerenv present"; CONTAINED=1; }
if grep -qaE 'docker|containerd|crio|kubepods|libpod|lxc|podman' /proc/1/cgroup 2>/dev/null; then
  echo "cgroup runtime: $(grep -aoE 'docker|containerd|crio|kubepods|libpod|lxc|podman' /proc/1/cgroup | head -1)"
  CONTAINED=1
fi
PID1=$(cat /proc/1/comm 2>/dev/null)
echo "pid 1: ${PID1:-unknown}"
[ -n "$PID1" ] && [ "$PID1" != "systemd" ] && [ "$PID1" != "init" ] && CONTAINED=1
if have findmnt; then echo "root fs: $(findmnt -n -o FSTYPE / 2>/dev/null)"; fi
echo "contained: $CONTAINED"

# ---------------------------------------------------------------------------
hr "capabilities"
if have capsh; then
  capsh --print 2>/dev/null | grep -iE 'current|bounding' | head -4
else
  grep -E 'Cap(Eff|Bnd)' /proc/self/status 2>/dev/null
fi
NOTABLE=""
CAPEFF=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')
if [ -n "$CAPEFF" ] && have capsh; then
  DECODED=$(capsh --decode="$CAPEFF" 2>/dev/null)
  for c in cap_sys_admin cap_sys_ptrace cap_sys_module cap_dac_read_search cap_sys_rawio cap_net_admin cap_mknod; do
    echo "$DECODED" | grep -q "$c" && NOTABLE="$NOTABLE $c"
  done
fi
echo "notable caps:${NOTABLE:- none}"

# ---------------------------------------------------------------------------
hr "sandbox controls"
grep -E 'Seccomp:' /proc/self/status 2>/dev/null
grep -E 'NoNewPrivs:' /proc/self/status 2>/dev/null
echo "lsm profile: $(cat /proc/self/attr/current 2>/dev/null || echo unknown)"
echo "cgroup version: $(stat -fc %T /sys/fs/cgroup 2>/dev/null)"

# ---------------------------------------------------------------------------
hr "mounts & sockets"
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/crio/crio.sock; do
  [ -S "$s" ] && echo "[!] runtime socket: $s"
done
if have findmnt; then
  findmnt -rn -o TARGET,SOURCE 2>/dev/null | grep -iE '/host|/rootfs|kubelet|docker.sock' | sed 's/^/[!] mount: /'
fi
ls -la /dev 2>/dev/null | grep -E ' (sd[a-z]|nvme[0-9]|vd[a-z]|dm-[0-9])' | awk '{print "[!] block device: "$NF}'

# ---------------------------------------------------------------------------
hr "namespaces"
for ns in pid net ipc uts mnt user; do
  mine=$(readlink /proc/self/ns/$ns 2>/dev/null)
  theirs=$(readlink /proc/1/ns/$ns 2>/dev/null)
  if [ -n "$mine" ] && [ "$mine" = "$theirs" ]; then echo "[!] $ns namespace shared with pid 1"; fi
done

# ---------------------------------------------------------------------------
hr "kubernetes"
SA=/var/run/secrets/kubernetes.io/serviceaccount
if [ -d "$SA" ]; then
  echo "[!] service-account token mounted"
  echo "namespace: $(cat $SA/namespace 2>/dev/null)"
  TOKEN=$(cat $SA/token 2>/dev/null)
  if [ -n "$TOKEN" ] && have base64; then
    echo "subject: $(echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | grep -oE '"sub":"[^"]*"')"
  fi
  echo "api server: https://${KUBERNETES_SERVICE_HOST:-?}:${KUBERNETES_SERVICE_PORT:-?}"
else
  echo "no service-account token mounted"
fi

# ---------------------------------------------------------------------------
hr "cloud metadata (read-only; secrets redacted)"
CURL_OPTS="-s --max-time 3"
# AWS
if have curl; then
  AWS=http://169.254.169.254
  TOK=$(curl $CURL_OPTS -X PUT "$AWS/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
  H=""; [ -n "$TOK" ] && H="-H X-aws-ec2-metadata-token:$TOK"
  ROLE=$(curl $CURL_OPTS $H "$AWS/latest/meta-data/iam/security-credentials/" 2>/dev/null | head -1)
  if [ -n "$ROLE" ]; then
    echo "[!] AWS role attached: $ROLE (credentials retrievable via IMDS)"
  else
    curl $CURL_OPTS "$AWS/latest/meta-data/" >/dev/null 2>&1 && echo "AWS IMDS reachable, no role"
  fi
  # GCP
  GCP_SA=$(curl $CURL_OPTS -H 'Metadata-Flavor: Google' \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null)
  [ -n "$GCP_SA" ] && echo "[!] GCP service account: $GCP_SA (token retrievable via metadata)"
  # Azure
  AZ=$(curl $CURL_OPTS -H 'Metadata: true' \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
  echo "$AZ" | grep -q '"compute"' && echo "[!] Azure IMDS reachable (managed identity may be available)"
fi

# ---------------------------------------------------------------------------
hr "credentials on disk (names only)"
for f in ~/.aws/credentials ~/.config/gcloud/credentials.db ~/.kube/config \
         /root/.aws/credentials .env ./.env ../.env config.json .npmrc .git-credentials; do
  [ -r "$f" ] && echo "[!] readable: $f"
done
find / -maxdepth 4 -type f \( -name '*.pem' -o -name 'id_rsa' -o -name '.env' \) 2>/dev/null | head -20

# ---------------------------------------------------------------------------
hr "summary"
[ "$CONTAINED" = 1 ] && echo "- running in a container"
[ -n "$NOTABLE" ] && echo "- notable capabilities:$NOTABLE"
[ -S /var/run/docker.sock ] && echo "- docker socket mounted (host-equivalent authority)"
[ -d "$SA" ] && echo "- kubernetes service-account token present"
grep -q 'Seccomp:.*0' /proc/self/status 2>/dev/null && echo "- seccomp disabled"
echo "done."
```

## Python: `recon.py`

```python
#!/usr/bin/env python3
"""Read-only recon for a foothold in a container or cloud VM.

Fingerprints containment, capabilities, sandbox controls, mounted surfaces,
Kubernetes identity, and cloud-metadata reachability, then prints a summary.

- Makes no changes; issues only local reads and metadata GETs.
- Redacts secret material (tokens, keys) in its output.
- Python 3.11+, standard library only.

Usage:
    python3 recon.py            human-readable
    python3 recon.py --json     structured summary
    python3 recon.py --self-test
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

TIMEOUT = 3

NOTABLE_CAPS = {
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_dac_read_search",
    "cap_sys_rawio", "cap_net_admin", "cap_mknod", "cap_sys_boot",
}
CONTROL_SOCKETS = (
    "/var/run/docker.sock", "/run/docker.sock",
    "/run/containerd/containerd.sock", "/run/crio/crio.sock",
)
# capability bit order from linux/capability.h
CAP_NAMES = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid",
    "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_linux_immutable",
    "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin", "cap_net_raw",
    "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot",
    "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod", "cap_lease",
    "cap_audit_write", "cap_audit_control", "cap_setfcap", "cap_mac_override",
    "cap_mac_admin", "cap_syslog", "cap_wake_alarm", "cap_block_suspend", "cap_audit_read",
    "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
]


def read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def http(url: str, method: str = "GET", headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


# ---------------------------------------------------------------------------
def fingerprint_containment() -> dict:
    signals = []
    if os.path.exists("/.dockerenv"):
        signals.append("/.dockerenv present")
    cgroup = read("/proc/1/cgroup")
    for marker in ("docker", "containerd", "crio", "kubepods", "lxc", "podman"):
        if marker in cgroup:
            signals.append(f"cgroup mentions {marker}")
            break
    pid1 = read("/proc/1/comm").strip()
    if pid1 and pid1 not in ("systemd", "init"):
        signals.append(f"pid 1 is {pid1!r}")
    return {"contained": bool(signals), "signals": signals}


def decode_caps() -> tuple[list[str], bool]:
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", read("/proc/self/status"), re.M)
    if not m:
        return [], False
    mask = int(m.group(1), 16)
    held = [n for i, n in enumerate(CAP_NAMES) if mask & (1 << i)]
    return held, len(held) >= 38


def sandbox_controls() -> dict:
    status = read("/proc/self/status")
    sc = re.search(r"^Seccomp:\s*(\d+)", status, re.M)
    seccomp = {"0": "disabled", "1": "strict", "2": "filtered"}.get(sc.group(1) if sc else "", "unknown")
    return {
        "seccomp": seccomp,
        "lsm": (read("/proc/self/attr/current") or "unknown").strip() or "unknown",
    }


def shared_namespaces() -> list[str]:
    out = []
    for ns in ("pid", "net", "ipc", "uts", "mnt", "user"):
        try:
            if os.readlink(f"/proc/self/ns/{ns}") == os.readlink(f"/proc/1/ns/{ns}"):
                out.append(ns)
        except OSError:
            pass
    return out


def mounted_surfaces() -> dict:
    socks = [s for s in CONTROL_SOCKETS if os.path.exists(s)]
    host_mounts = []
    for line in read("/proc/self/mountinfo").splitlines():
        parts = line.split()
        if len(parts) >= 5:
            mp = parts[4]
            if any(mp.startswith(h) for h in ("/host", "/rootfs", "/hostfs")) or "kubelet" in line:
                host_mounts.append(mp)
    try:
        devs = [d for d in os.listdir("/dev") if re.match(r"^(sd[a-z]|nvme\d|vd[a-z]|dm-\d)", d)]
    except OSError:
        devs = []
    return {"sockets": socks, "host_mounts": sorted(set(host_mounts)), "block_devices": devs}


def kubernetes() -> dict:
    sa = "/var/run/secrets/kubernetes.io/serviceaccount"
    if not os.path.isdir(sa):
        return {"present": False}
    info = {"present": True, "namespace": read(f"{sa}/namespace").strip()}
    token = read(f"{sa}/token").strip()
    if token:
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            info["subject"] = claims.get("sub")
        except Exception:
            pass
    info["api"] = f"https://{os.environ.get('KUBERNETES_SERVICE_HOST', '?')}:{os.environ.get('KUBERNETES_SERVICE_PORT', '?')}"
    return info


def cloud_metadata() -> dict:
    result = {}
    # AWS
    code, token = http("http://169.254.169.254/latest/api/token", "PUT",
                       {"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    hdr = {"X-aws-ec2-metadata-token": token} if code == 200 and token else {}
    code, roles = http("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=hdr)
    if code == 200 and roles.strip():
        result["aws"] = {"reachable": True, "role": roles.strip().splitlines()[0],
                         "note": "credentials retrievable via IMDS (not shown)"}
    elif code:
        result["aws"] = {"reachable": True, "role": None}
    # GCP
    code, email = http("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                       headers={"Metadata-Flavor": "Google"})
    if code == 200 and email.strip():
        result["gcp"] = {"reachable": True, "service_account": email.strip(),
                         "note": "token retrievable via metadata (not shown)"}
    # Azure
    code, body = http("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                      headers={"Metadata": "true"})
    if code == 200 and '"compute"' in body:
        result["azure"] = {"reachable": True, "note": "managed identity may be available"}
    return result


def credentials_on_disk() -> list[str]:
    candidates = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.kube/config"),
        os.path.expanduser("~/.config/gcloud/credentials.db"),
        "/root/.aws/credentials", ".env", "config.json", ".git-credentials", ".npmrc",
    ]
    return [c for c in candidates if os.access(c, os.R_OK) and os.path.isfile(c)]


# ---------------------------------------------------------------------------
def gather() -> dict:
    caps, privileged = decode_caps()
    return {
        "host": {"uname": read("/proc/version").strip()[:120], "uid": os.getuid()},
        "containment": fingerprint_containment(),
        "capabilities": {"held": caps, "notable": sorted(set(caps) & NOTABLE_CAPS),
                         "privileged": privileged},
        "sandbox": sandbox_controls(),
        "shared_namespaces": shared_namespaces(),
        "mounts": mounted_surfaces(),
        "kubernetes": kubernetes(),
        "cloud_metadata": cloud_metadata(),
        "credential_files": credentials_on_disk(),
    }


def summarise(data: dict) -> list[str]:
    out = []
    if data["containment"]["contained"]:
        out.append("running in a container")
    if data["capabilities"]["privileged"]:
        out.append("privileged (full capability set)")
    elif data["capabilities"]["notable"]:
        out.append("notable capabilities: " + ", ".join(data["capabilities"]["notable"]))
    if data["sandbox"]["seccomp"] == "disabled":
        out.append("seccomp disabled")
    if data["sandbox"]["lsm"] in ("unconfined", "unknown"):
        out.append("no LSM confinement")
    if data["mounts"]["sockets"]:
        out.append("runtime control socket mounted: " + ", ".join(data["mounts"]["sockets"]))
    for ns in ("pid", "net"):
        if ns in data["shared_namespaces"]:
            out.append(f"host {ns} namespace shared")
    if data["mounts"]["block_devices"]:
        out.append("host block devices visible: " + ", ".join(data["mounts"]["block_devices"]))
    if data["kubernetes"]["present"]:
        out.append("kubernetes service-account token present")
    for cloud, info in data["cloud_metadata"].items():
        out.append(f"{cloud} metadata reachable")
    if data["credential_files"]:
        out.append("credential files readable: " + ", ".join(data["credential_files"]))
    return out


def print_human(data: dict) -> None:
    def section(title: str) -> None:
        print(f"\n=== {title} ===")

    section("host")
    print(f"uid: {data['host']['uid']}")
    print(f"kernel: {data['host']['uname']}")

    section("containment")
    print(f"contained: {data['containment']['contained']}")
    for s in data["containment"]["signals"]:
        print(f"  - {s}")

    section("capabilities")
    print(f"posture: {'privileged' if data['capabilities']['privileged'] else str(len(data['capabilities']['held'])) + ' caps'}")
    for c in data["capabilities"]["notable"]:
        print(f"  [!] {c}")

    section("sandbox")
    print(f"seccomp: {data['sandbox']['seccomp']}")
    print(f"lsm: {data['sandbox']['lsm']}")

    section("namespaces shared with pid 1")
    print("  " + (", ".join(data["shared_namespaces"]) or "none"))

    section("mounted surfaces")
    for s in data["mounts"]["sockets"]:
        print(f"  [!] socket: {s}")
    for m in data["mounts"]["host_mounts"]:
        print(f"  [!] host mount: {m}")
    for d in data["mounts"]["block_devices"]:
        print(f"  [!] block device: /dev/{d}")

    section("kubernetes")
    k = data["kubernetes"]
    if k["present"]:
        print(f"  [!] token present; namespace={k.get('namespace')} subject={k.get('subject')}")
        print(f"      api: {k.get('api')}")
    else:
        print("  none")

    section("cloud metadata")
    if not data["cloud_metadata"]:
        print("  none reachable")
    for cloud, info in data["cloud_metadata"].items():
        print(f"  [!] {cloud}: {info}")

    section("credential files")
    for f in data["credential_files"]:
        print(f"  [!] {f}")

    section("summary")
    findings = summarise(data)
    for f in findings:
        print(f"  [!] {f}")
    if not findings:
        print("  no relaxed controls or exposed identities detected")


def self_test() -> None:
    # pure functions should work regardless of the current environment
    caps, priv = decode_caps()
    assert isinstance(caps, list) and isinstance(priv, bool)
    sc = sandbox_controls()
    assert sc["seccomp"] in ("disabled", "strict", "filtered", "unknown")
    # summariser turns a synthetic finding set into readable lines
    fake = {
        "containment": {"contained": True, "signals": []},
        "capabilities": {"held": ["cap_sys_admin"], "notable": ["cap_sys_admin"], "privileged": False},
        "sandbox": {"seccomp": "disabled", "lsm": "unconfined"},
        "shared_namespaces": ["pid"],
        "mounts": {"sockets": ["/var/run/docker.sock"], "host_mounts": [], "block_devices": []},
        "kubernetes": {"present": True, "namespace": "default", "subject": "x"},
        "cloud_metadata": {"aws": {"reachable": True}},
        "credential_files": ["/root/.aws/credentials"],
    }
    s = summarise(fake)
    joined = " | ".join(s)
    assert "container" in joined and "cap_sys_admin" in joined
    assert "seccomp disabled" in joined and "docker socket" not in joined  # phrasing check
    assert "docker.sock" in joined and "host pid namespace" in joined
    assert "aws metadata reachable" in joined
    print("[+] self-test ok")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    data = gather()
    if "--json" in sys.argv:
        # never emit raw secrets; the gatherers already avoid storing them
        print(json.dumps({"summary": summarise(data), **data}, indent=2, default=str))
    else:
        print_human(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Notes

- Both scripts are deliberately read-only and redact credential material; they report *reachability*
  and *posture*, not the secrets themselves. Retrieve credentials with the targeted commands in
  `cloud-metadata-ssrf` and `aws-cli-cheatsheet` once you have decided to.
- The bash version has zero dependencies beyond coreutils and `curl`; use it when Python is absent.
- Run `python3 recon.py --self-test` to validate the parsers offline before trusting the output on a
  real target.
- Follow-ups by finding:
  - notable capability -> `container-escape`
  - docker/runtime socket -> `container-escape`
  - kubernetes token -> `kubernetes-attacks`
  - cloud metadata reachable -> `cloud-metadata-ssrf` then `aws-enumeration-privesc`
  - readable credential files -> use them per the relevant CLI cheatsheet.
```
