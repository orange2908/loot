---
title: "Container Detection & Isolation Cheatsheet"
category: cloud
subcategory: container
type: cheatsheet
tags: [cloud, container, docker, detection, capabilities, capsh, proc, cgroups, seccomp, apparmor, namespace, docker-sock, mount, privileged, findmnt, amicontained]
summary: "Detection one-liners (am I in a container? which runtime? what caps?) mapped to the isolation control each one reveals."
tools: [capsh, findmnt, mount, amicontained, docker]
related: [container-escape, kubernetes-cheatsheet, kubernetes-attacks, cloud-enum-script]
---

## Am I in a container?

```bash
# the docker runtime marker file
ls -la /.dockerenv
# cgroup path names the runtime + often the container id
cat /proc/1/cgroup
cat /proc/self/cgroup
# PID 1 is the app, not an init system
cat /proc/1/comm
ps -p 1 -o comm=
# a small process table is a hint
ps aux | wc -l
# overlayfs root is typical of containers
findmnt / -o FSTYPE -n            # overlay
# purpose-built detector: runtime, caps, seccomp, namespaces at a glance
amicontained
```

## Which runtime / orchestrator?

```bash
grep -aoE 'docker|containerd|crio|kubepods|libpod|lxc|podman|garden' /proc/1/cgroup /proc/self/cgroup 2>/dev/null | sort -u
# kubernetes?
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null && echo "kubernetes pod"
env | grep -i kubernetes_service_host
# runtime versions (if binaries are reachable)
runc --version 2>/dev/null; containerd --version 2>/dev/null
# sandboxed runtime? (gVisor/Kata reveal themselves in dmesg/uname)
dmesg 2>/dev/null | grep -i gvisor; uname -a
```

## What capabilities do I have?

```bash
# human-readable effective set -- the single most useful command
capsh --print
# raw bitmasks
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
# decode a bitmask into names
capsh --decode=00000000a80425fb
# quick check for the high-impact ones
grep CapEff /proc/self/status | awk '{print $2}' | xargs -I{} capsh --decode={} \
  | grep -oE 'cap_(sys_admin|sys_ptrace|sys_module|dac_read_search|sys_rawio|net_admin|mknod)'
```

Capability -> what its presence means:

```
cap_sys_admin        mount(2) available; broadest capability
cap_sys_module       load kernel modules (arbitrary kernel code)
cap_sys_ptrace       attach to processes (reaches host procs with --pid=host)
cap_dac_read_search  bypass file-read permission checks
cap_sys_rawio        raw I/O and memory access
cap_net_admin        reconfigure networking
cap_mknod            create device nodes
(full/near-full set) the container is running --privileged
```

## Sandbox controls (seccomp, LSM)

```bash
# seccomp: 0 = disabled (notable), 1 = strict, 2 = filtered
grep Seccomp /proc/self/status
# how many syscalls are filtered
grep Seccomp_filters /proc/self/status
# AppArmor / SELinux profile ("unconfined" is notable)
cat /proc/self/attr/current 2>/dev/null
# is the no_new_privs bit set?
grep NoNewPrivs /proc/self/status
```

## Mounts and exposed surfaces

```bash
# authoritative mount view
findmnt
mount
cat /proc/self/mountinfo
# runtime control sockets mounted in (host-equivalent authority)
ls -la /var/run/docker.sock /run/docker.sock \
       /run/containerd/containerd.sock /run/crio/crio.sock 2>/dev/null
# host filesystem bind mounts
findmnt | grep -iE '/host|/rootfs|/hostfs'
mount | grep -iE 'kubelet|/host|docker'
# host block devices visible -> the disk is reachable regardless of the mount ns
ls -la /dev | grep -E 'sd[a-z]|nvme|vd[a-z]|dm-'
# writable, security-relevant paths
for p in /proc/sys/kernel /sys/kernel /sys/fs/cgroup; do test -w "$p" && echo "writable: $p"; done
```

## Namespaces

```bash
# my namespace ids
ls -la /proc/self/ns/
# compare with PID 1's -- equal means the namespace is SHARED with the host
for ns in pid net ipc uts mnt user; do
  echo -n "$ns: "; [ "$(readlink /proc/self/ns/$ns)" = "$(readlink /proc/1/ns/$ns 2>/dev/null)" ] \
    && echo shared || echo isolated
done
# host PID namespace? -> host processes are visible
ps aux | grep -v '\[' | head
# host network namespace? -> host services on loopback are reachable
ss -tlnp 2>/dev/null; cat /proc/net/tcp | wc -l
```

## cgroup version (affects the release_agent class)

```bash
# cgroup2fs = v2 (release_agent gone); tmpfs/cgroup with subdirs = v1
stat -fc %T /sys/fs/cgroup
mount | grep cgroup
# is a cgroup hierarchy writable? (needed for the v1 release_agent path)
test -w /sys/fs/cgroup && echo "cgroup root writable"
```

## Kernel and image context

```bash
uname -a                          # kernel version gates container-relevant CVEs
cat /etc/os-release               # base image
cat /proc/version
# check the kernel version against known runtime/kernel CVEs rather than assuming
```

## Condition -> what it indicates (reasoning table)

```
/.dockerenv present, overlay root                -> containerised workload
docker.sock mounted                              -> can drive the runtime (host-equivalent)
full capability set + Seccomp: 0 + unconfined    -> --privileged; isolation not enforced
cap_sys_admin present                            -> mount() available
--pid=host (pid ns shared)                        -> host processes / /proc/1/root visible
--net=host (net ns shared)                        -> host-loopback services reachable
host / or /etc bind-mounted                      -> direct host filesystem access
/dev/sda visible                                 -> raw disk reachable
cgroup v1 + writable cgroup mount + cap_sys_admin -> release_agent class applies
no user namespace                                -> in-container root == host UID 0 (minus caps)
```

## Quick posture summary one-liner

```bash
echo "runtime: $(grep -aoE 'docker|containerd|crio|kubepods|podman' /proc/1/cgroup | head -1)"; \
echo "seccomp: $(grep Seccomp: /proc/self/status | awk '{print $2}')"; \
echo "lsm: $(cat /proc/self/attr/current 2>/dev/null)"; \
echo "docker.sock: $(test -S /var/run/docker.sock && echo yes || echo no)"; \
echo "caps:"; capsh --print | grep -i 'current:'
```

## Tools

```bash
amicontained            # runtime, caps, seccomp, namespace sharing in one command
capsh --print           # capability set (from libcap)
kube-hunter --pod       # kubernetes-specific in-pod checks
docker-bench-security   # CIS docker benchmark (from the host)
```
