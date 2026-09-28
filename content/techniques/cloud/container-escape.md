---
title: "Container Isolation Failures - Recognising Escape-Prone Configurations"
category: cloud
subcategory: container
type: technique
tags: [cloud, container, docker, escape, privileged, docker-sock, capabilities, cap-sys-admin, cap-sys-ptrace, cap-dac-read-search, cgroups, release-agent, proc, namespace, runc, isolation, hardening, seccomp, apparmor]
difficulty: medium
summary: "A container is namespaces plus cgroups plus capabilities plus seccomp/LSM. Escapes exist where one of those was loosened; enumerate which, then reason about impact."
when_to_use:
  - "You have code execution in a container and need to know whether host access is reachable"
  - "You are assessing a container's isolation posture"
  - "capsh --print or /proc/self/status shows a non-default capability set"
  - "A socket, device node or host path is mounted into the container"
tools: [capsh, findmnt, mount, docker, kubectl, amicontained]
related: [kubernetes-attacks, container-escape-cheatsheet, cloud-enum-script, docker-image-analysis]
---

## TL;DR

Container isolation is not a single boundary; it is five overlapping ones (namespaces, cgroups,
capabilities, seccomp, LSM/AppArmor-SELinux) plus whatever the operator mounted in. Escape research
is almost entirely about *enumeration*: establish which of the five was relaxed, and the escape
path follows mechanically from that. In a CTF, the challenge author deliberately relaxes exactly
one, and your job is to find which.

## Recognise it

### Am I in a container, and which runtime?

```bash
# marker file left by the docker runtime
ls -la /.dockerenv 2>/dev/null

# cgroup paths name the runtime and often the container/pod id
cat /proc/1/cgroup
cat /proc/self/cgroup

# PID 1 is not systemd/init in a container
cat /proc/1/comm

# kubernetes injects these
env | grep -i kubernetes
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null

# container-aware fingerprinting tool
amicontained
```

### What was relaxed?

```bash
# effective capability set -- the single most informative command
capsh --print

# raw bitmask form, useful when capsh is absent
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
# decode a bitmask
capsh --decode=00000000a80425fb

# seccomp mode: 0 = disabled (notable), 2 = filtered
grep Seccomp /proc/self/status

# AppArmor / SELinux profile; "unconfined" is notable
cat /proc/self/attr/current 2>/dev/null

# what is mounted in, and from where
findmnt
mount | grep -E 'docker|kubelet|host|overlay'
cat /proc/self/mountinfo

# host devices exposed into the container
ls -la /dev

# namespaces: compare with PID 1 on the host if visible
ls -la /proc/self/ns/
readlink /proc/self/ns/pid /proc/1/ns/pid

# sockets that proxy to a control plane
ls -la /var/run/docker.sock /run/containerd/containerd.sock \
       /run/crio/crio.sock /var/run/docker/metrics.sock 2>/dev/null
```

## Theory - the five boundaries and what weakens each

### 1. Namespaces

Namespaces virtualise the view of PIDs, mounts, network, users, IPC and UTS. The relevant
weakenings:

| Setting | Effect |
|---|---|
| `--pid=host` | the container sees every host process; `/proc/<pid>/root` of a host process is a path into the host filesystem |
| `--net=host` | no network isolation; host-loopback-only services (metadata proxies, kubelet, etcd) become reachable |
| `--ipc=host` | shared memory segments with host processes |
| no user namespace | root in the container is UID 0 on the host; only capabilities separate them |

The absence of a user namespace is the default for Docker and for most Kubernetes deployments. It
is why capabilities matter so much: in-container root *is* host root, minus the capability set.

### 2. Capabilities

Linux splits root's power into ~40 capabilities. Docker's default set drops the dangerous ones.
The ones whose presence changes the security model:

| Capability | Why it matters |
|---|---|
| `CAP_SYS_ADMIN` | permits `mount(2)`; the single broadest capability, effectively "root minus a few" |
| `CAP_SYS_PTRACE` | attach to other processes; combined with `--pid=host` this reaches host processes |
| `CAP_SYS_MODULE` | load kernel modules, i.e. arbitrary kernel code |
| `CAP_DAC_READ_SEARCH` | bypass file read permission checks; enables `open_by_handle_at` filesystem traversal (the "Shocker" class) |
| `CAP_SYS_BOOT`, `CAP_SYS_RAWIO` | direct hardware/reboot control |
| `CAP_NET_ADMIN`, `CAP_NET_RAW` | reconfigure networking, forge packets |
| `CAP_SYS_CHROOT`, `CAP_MKNOD` | create device nodes, change roots |

`--privileged` grants **all** capabilities, disables seccomp and AppArmor, and exposes all host
devices under `/dev`. It is not "a bit more access"; it is a deliberate removal of the boundary,
and Docker's own documentation says so.

### 3. cgroups

The `cgroup` v1 `release_agent` mechanism lets a cgroup specify a host-side program to run when the
last process leaves the cgroup. Writing to `release_agent` requires the ability to mount a cgroup
hierarchy (`CAP_SYS_ADMIN`) and a writable cgroup mount. cgroup v2 removed the `release_agent`
file entirely and replaced notification with a different mechanism, which is why modern hosts are
not affected by this class.

### 4. seccomp

Docker's default seccomp profile blocks ~44 syscalls including `mount`, `pivot_root`,
`kexec_load`, `init_module` and `ptrace` (historically). `--security-opt seccomp=unconfined`, or
`--privileged`, removes it. `Seccomp: 0` in `/proc/self/status` is the tell.

### 5. LSM (AppArmor / SELinux)

The `docker-default` AppArmor profile denies writes to `/proc/sys`, `/sys`, and mount operations.
`unconfined` in `/proc/self/attr/current` means it is off.

### Mounted-in escape surfaces

These are not kernel weaknesses; they are the operator handing over a control channel:

| Mount | What it grants |
|---|---|
| `/var/run/docker.sock` | full Docker API: create containers with arbitrary mounts and privileges. Equivalent to host root. |
| `/run/containerd/containerd.sock`, `/run/crio/crio.sock` | the same at the CRI layer |
| `/` or `/etc` or `/root` from the host | direct filesystem access |
| `/var/log` (with a symlink-following log reader) | arbitrary host file read |
| `/dev/sda*`, `/dev/mapper/*` | raw block device access -- the filesystem can be read directly regardless of the mount namespace |
| `/proc` from the host (`/host/proc`) | `/proc/1/root` traversal, `/proc/sys` writes |
| kubelet's `/var/lib/kubelet` | every pod's service-account token on that node |

### Why `/proc/1/root` matters

With `--pid=host`, `/proc/<pid>/root` resolves to the root of that process's *mount namespace*.
PID 1 on the host is typically in the host's mount namespace, so that path is a view of the host
filesystem - no exploit required, just a permission the container was granted.

## Assessment procedure

1. **Confirm containment and runtime** - `/proc/1/cgroup`, `/.dockerenv`, `/proc/1/comm`.
2. **Dump the capability set** - `capsh --print`. Compare against the runtime default. Any addition
   is the finding.
3. **Check seccomp and LSM** - `grep Seccomp /proc/self/status`, `/proc/self/attr/current`.
4. **Enumerate mounts** - `findmnt`, `/proc/self/mountinfo`. Look for host paths and sockets.
5. **Enumerate devices** - `ls -la /dev`. A container with `/dev/sda` is not isolated from the disk.
6. **Check namespace sharing** - compare `/proc/self/ns/*` with `/proc/1/ns/*`.
7. **Check the kernel version** - `uname -a`. Container-relevant CVEs (runc, kernel) are
   version-gated; look up the specific version rather than assuming.
8. **Record the impact**: for each relaxed control, state what a process inside the container can
   reach that it should not.

## Code - a read-only posture reporter

```python
#!/usr/bin/env python3
"""Report container isolation posture. Read-only; makes no changes.

Run inside a container to enumerate which isolation controls are relaxed.
Python 3.11+, standard library only.
"""
from __future__ import annotations

import os
import platform
import re
import sys

# Capabilities whose presence materially changes the container's security model.
NOTABLE_CAPS = {
    "cap_sys_admin": "permits mount(2); broadest capability",
    "cap_sys_module": "load kernel modules",
    "cap_sys_ptrace": "attach to other processes",
    "cap_dac_read_search": "bypass file read permission checks",
    "cap_sys_rawio": "raw I/O port and memory access",
    "cap_sys_boot": "reboot / kexec",
    "cap_net_admin": "reconfigure networking",
    "cap_net_raw": "raw sockets / packet forgery",
    "cap_mknod": "create device nodes",
    "cap_sys_chroot": "change root directory",
}

# Runtime control sockets: presence means the container can drive the runtime.
CONTROL_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
)

HOST_PATH_HINTS = ("/host", "/hostfs", "/rootfs", "/mnt/host")


def read(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def in_container() -> tuple[bool, list[str]]:
    signals: list[str] = []
    if os.path.exists("/.dockerenv"):
        signals.append("/.dockerenv present")
    cgroup = read("/proc/1/cgroup")
    for marker in ("docker", "kubepods", "containerd", "crio", "lxc", "podman"):
        if marker in cgroup:
            signals.append(f"/proc/1/cgroup mentions {marker}")
    comm = read("/proc/1/comm").strip()
    if comm and comm not in ("systemd", "init"):
        signals.append(f"PID 1 is {comm!r}, not an init system")
    if os.path.isdir("/var/run/secrets/kubernetes.io/serviceaccount"):
        signals.append("kubernetes service-account directory mounted")
    return bool(signals), signals


def capability_report() -> tuple[list[str], str]:
    """Decode CapEff from /proc/self/status into notable capability names."""
    status = read("/proc/self/status")
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status, re.M)
    if not m:
        return [], "unknown"
    mask = int(m.group(1), 16)
    # /usr/include/linux/capability.h ordering
    names = [
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
    held = [n for i, n in enumerate(names) if mask & (1 << i)]
    # a full or near-full set is the signature of --privileged
    posture = "privileged (full capability set)" if len(held) >= 38 else f"{len(held)} capabilities"
    return held, posture


def seccomp_mode() -> str:
    m = re.search(r"^Seccomp:\s*(\d+)", read("/proc/self/status"), re.M)
    if not m:
        return "unknown"
    return {"0": "disabled", "1": "strict", "2": "filtered"}.get(m.group(1), m.group(1))


def lsm_profile() -> str:
    return (read("/proc/self/attr/current") or "unknown").strip() or "unknown"


def shared_namespaces() -> list[str]:
    shared = []
    for ns in ("pid", "net", "ipc", "uts", "mnt", "user"):
        mine = os.readlink(f"/proc/self/ns/{ns}") if os.path.exists(f"/proc/self/ns/{ns}") else ""
        theirs = ""
        try:
            theirs = os.readlink(f"/proc/1/ns/{ns}")
        except OSError:
            pass
        if mine and theirs and mine == theirs:
            shared.append(ns)
    return shared


def mounted_control_sockets() -> list[str]:
    return [p for p in CONTROL_SOCKETS if os.path.exists(p)]


def suspicious_mounts() -> list[str]:
    out = []
    for line in read("/proc/self/mountinfo").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        root, mountpoint = parts[3], parts[4]
        if any(mountpoint.startswith(h) for h in HOST_PATH_HINTS):
            out.append(f"{mountpoint} (host path hint)")
        elif "kubelet" in line or "docker.sock" in line:
            out.append(f"{mountpoint} (runtime data)")
        elif root == "/" and mountpoint not in ("/", "/proc", "/sys", "/dev"):
            out.append(f"{mountpoint} (whole-filesystem bind from {root})")
    return sorted(set(out))


def exposed_block_devices() -> list[str]:
    try:
        entries = os.listdir("/dev")
    except OSError:
        return []
    return sorted(e for e in entries if re.match(r"^(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|dm-\d)", e))


def main() -> int:
    contained, signals = in_container()
    print("=== containment ===")
    print(f"in a container: {contained}")
    for s in signals:
        print(f"  - {s}")
    print(f"kernel: {platform.platform()}")

    print("\n=== capabilities ===")
    held, posture = capability_report()
    print(f"posture: {posture}")
    for cap in held:
        note = NOTABLE_CAPS.get(cap)
        if note:
            print(f"  ! {cap}: {note}")
    if not any(c in NOTABLE_CAPS for c in held):
        print("  (no notable capabilities beyond the runtime default)")

    print("\n=== sandbox controls ===")
    print(f"seccomp: {seccomp_mode()}")
    print(f"lsm profile: {lsm_profile()}")

    shared = shared_namespaces()
    print("\n=== namespaces ===")
    print(f"shared with PID 1: {', '.join(shared) if shared else 'none detected'}")

    print("\n=== mounted-in surfaces ===")
    socks = mounted_control_sockets()
    for s in socks:
        print(f"  ! runtime control socket: {s}")
    for m in suspicious_mounts():
        print(f"  ! mount: {m}")
    devs = exposed_block_devices()
    if devs:
        print(f"  ! block devices visible: {', '.join(devs)}")
    if not (socks or devs):
        print("  (no runtime sockets or block devices visible)")

    print("\n=== summary ===")
    findings = []
    if "privileged" in posture:
        findings.append("container runs privileged -- isolation boundary is not enforced")
    if seccomp_mode() == "disabled":
        findings.append("seccomp disabled")
    if lsm_profile() in ("unconfined", "unknown"):
        findings.append("no LSM confinement")
    if socks:
        findings.append("runtime control socket mounted (host-equivalent authority)")
    if "pid" in shared:
        findings.append("host PID namespace shared")
    if "net" in shared:
        findings.append("host network namespace shared")
    if devs:
        findings.append("host block devices exposed")
    for f in findings:
        print(f"  [!] {f}")
    if not findings:
        print("  no relaxed isolation controls detected")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        # exercise the pure parsers without requiring a container
        held, posture = capability_report()
        assert isinstance(held, list) and isinstance(posture, str)
        assert seccomp_mode() in ("disabled", "strict", "filtered", "unknown")
        assert isinstance(shared_namespaces(), list)
        assert isinstance(suspicious_mounts(), list)
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **`--privileged` is not required for a weak container.** A single added capability, one host bind
  mount, or `--pid=host` is enough to change the model. Always enumerate all five boundaries.
- **cgroup v1 vs v2**: the `release_agent` class only applies to v1. Check
  `stat -fc %T /sys/fs/cgroup` - `cgroup2fs` means v2.
- **Rootless containers** (Podman rootless, Docker rootless) put you in a user namespace where
  in-container root maps to an unprivileged host UID. Capabilities there are namespaced and far
  less useful.
- **gVisor / Kata / Firecracker**: `dmesg` mentioning gVisor, or an unusual `uname`, means a
  sandboxed runtime where the ordinary reasoning does not apply.
- **Read-only root filesystem** (`--read-only`) does not restrict capabilities; it only limits
  writes to the container's own layer.
- **Runtime CVEs** (runc, containerd) are version-specific. Record `runc --version` /
  `containerd --version` and check them against the vendor advisories rather than guessing.
- **Kubernetes adds its own layer**: PodSecurity admission, SecurityContext, and the service-account
  token. See `kubernetes-attacks`.

## Hardening checklist

- Drop all capabilities and add back only what is needed: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`.
- Never mount a runtime control socket into a workload container; use a broker with a narrow API.
- Run with a user namespace (`userns-remap`, or Kubernetes user namespaces) so container root is
  not host root.
- Keep the default seccomp and AppArmor/SELinux profiles; treat `unconfined` as a finding.
- `--read-only` root filesystem plus explicit `tmpfs` mounts.
- Use `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `privileged: false` in Kubernetes
  SecurityContext, enforced by the PodSecurity "restricted" profile.
- Keep the kernel and container runtime patched; container escapes are frequently runtime CVEs.

## Tools

- `capsh` (libcap) - print and decode capability sets.
- `amicontained` - container introspection: runtime, capabilities, seccomp, namespace sharing.
- `findmnt`, `/proc/self/mountinfo` - authoritative mount view.
- `docker inspect <container>` / `kubectl get pod -o yaml` - the declared configuration, from outside.
- `kube-bench`, `docker-bench-security` - CIS benchmark checks.
- `Trivy`, `Grype` - image and configuration scanning.

## References

- Docker documentation: "Runtime privilege and Linux capabilities" (the `--privileged` warning).
- `capabilities(7)`, `namespaces(7)`, `cgroups(7)`, `user_namespaces(7)` man pages.
- Kubernetes documentation: "Pod Security Standards" and "Configure a Security Context for a Pod".
- NIST SP 800-190, "Application Container Security Guide".
