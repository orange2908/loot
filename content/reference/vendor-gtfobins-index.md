---
title: "GTFOBins - Complete Binary and Function Index"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "index", "binary-index", "suid", "sudo", "capabilities"]
summary: "All 457 GTFOBins binaries and which abuse functions each supports."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this is

All 457 GTFOBins binaries and the abuse functions each one supports, as a single searchable table. Find the binary you have, see what it can do, then open the matching payload page for the exact command.

## How to use it

```bash
# what is setuid on this box?
find / -perm -4000 -type f 2>/dev/null
# what may I run with sudo?
sudo -l
# what has capabilities?
getcap -r / 2>/dev/null
# then look the binary up below
```

## Payload pages

- **shell** — spawns an interactive shell — `ctfbrain show reference:vendor-gtfobins-shell`
- **file-read** — reads an arbitrary file — `ctfbrain show reference:vendor-gtfobins-file-read`
- **file-write** — writes to an arbitrary file — `ctfbrain show reference:vendor-gtfobins-file-write`
- **command** — runs a single command — `ctfbrain show reference:vendor-gtfobins-command`
- **reverse-shell** — connects back to a listener you control — `ctfbrain show reference:vendor-gtfobins-reverse-shell`
- **library-load** — loads an arbitrary shared library — `ctfbrain show reference:vendor-gtfobins-library-load`

## Function meanings

- `bind-shell` — listens for an inbound connection
- `command` — runs a single command
- `download` — see the upstream entry
- `file-read` — reads an arbitrary file
- `file-write` — writes to an arbitrary file
- `inherit` — see the upstream entry
- `library-load` — loads an arbitrary shared library
- `privilege-escalation` — see the upstream entry
- `reverse-shell` — connects back to a listener you control
- `shell` — spawns an interactive shell
- `upload` — see the upstream entry

## Every binary

| Binary | Functions |
|---|---|
| [`7z`](https://gtfobins.github.io/gtfobins/7z/) | `file-read` |
| [`R`](https://gtfobins.github.io/gtfobins/R/) | `shell` |
| [`aa-exec`](https://gtfobins.github.io/gtfobins/aa-exec/) | `shell` |
| [`ab`](https://gtfobins.github.io/gtfobins/ab/) | `download`, `upload` |
| [`acr`](https://gtfobins.github.io/gtfobins/acr/) | `command` |
| [`agetty`](https://gtfobins.github.io/gtfobins/agetty/) | `shell` |
| [`alpine`](https://gtfobins.github.io/gtfobins/alpine/) | `file-read` |
| [`ansible-playbook`](https://gtfobins.github.io/gtfobins/ansible-playbook/) | `shell` |
| [`ansible-test`](https://gtfobins.github.io/gtfobins/ansible-test/) | `shell` |
| [`aoss`](https://gtfobins.github.io/gtfobins/aoss/) | `shell` |
| [`apache2`](https://gtfobins.github.io/gtfobins/apache2/) | `file-read` |
| [`apache2ctl`](https://gtfobins.github.io/gtfobins/apache2ctl/) | `file-read` |
| [`apport-cli`](https://gtfobins.github.io/gtfobins/apport-cli/) | `inherit` |
| [`apt-get`](https://gtfobins.github.io/gtfobins/apt-get/) | `inherit`, `shell` |
| [`aptitude`](https://gtfobins.github.io/gtfobins/aptitude/) | `inherit` |
| [`ar`](https://gtfobins.github.io/gtfobins/ar/) | `file-read` |
| [`arch-nspawn`](https://gtfobins.github.io/gtfobins/arch-nspawn/) | `shell` |
| [`aria2c`](https://gtfobins.github.io/gtfobins/aria2c/) | `command`, `download`, `file-read` |
| [`arj`](https://gtfobins.github.io/gtfobins/arj/) | `file-read`, `file-write` |
| [`arp`](https://gtfobins.github.io/gtfobins/arp/) | `file-read` |
| [`as`](https://gtfobins.github.io/gtfobins/as/) | `file-read` |
| [`ascii-xfr`](https://gtfobins.github.io/gtfobins/ascii-xfr/) | `file-read` |
| [`ascii85`](https://gtfobins.github.io/gtfobins/ascii85/) | `file-read` |
| [`ash`](https://gtfobins.github.io/gtfobins/ash/) | `file-write`, `shell` |
| [`aspell`](https://gtfobins.github.io/gtfobins/aspell/) | `file-read` |
| [`asterisk`](https://gtfobins.github.io/gtfobins/asterisk/) | `shell` |
| [`at`](https://gtfobins.github.io/gtfobins/at/) | `command`, `shell` |
| [`atobm`](https://gtfobins.github.io/gtfobins/atobm/) | `file-read` |
| [`autoconf`](https://gtfobins.github.io/gtfobins/autoconf/) | `shell` |
| [`autoheader`](https://gtfobins.github.io/gtfobins/autoheader/) | `shell` |
| [`autoreconf`](https://gtfobins.github.io/gtfobins/autoreconf/) | `shell` |
| [`aws`](https://gtfobins.github.io/gtfobins/aws/) | `file-read`, `inherit` |
| [`base32`](https://gtfobins.github.io/gtfobins/base32/) | `file-read` |
| [`base58`](https://gtfobins.github.io/gtfobins/base58/) | `file-read` |
| [`base64`](https://gtfobins.github.io/gtfobins/base64/) | `file-read` |
| [`basenc`](https://gtfobins.github.io/gtfobins/basenc/) | `file-read` |
| [`basez`](https://gtfobins.github.io/gtfobins/basez/) | `file-read` |
| [`bash`](https://gtfobins.github.io/gtfobins/bash/) | `download`, `file-read`, `file-write`, `library-load`, `reverse-shell`, `shell`, `upload` |
| [`bashbug`](https://gtfobins.github.io/gtfobins/bashbug/) | `inherit` |
| [`batcat`](https://gtfobins.github.io/gtfobins/batcat/) | `inherit` |
| [`bbot`](https://gtfobins.github.io/gtfobins/bbot/) | `file-read` |
| [`bc`](https://gtfobins.github.io/gtfobins/bc/) | `file-read` |
| [`bconsole`](https://gtfobins.github.io/gtfobins/bconsole/) | `file-read`, `shell` |
| [`bee`](https://gtfobins.github.io/gtfobins/bee/) | `inherit` |
| [`borg`](https://gtfobins.github.io/gtfobins/borg/) | `shell` |
| [`bpftrace`](https://gtfobins.github.io/gtfobins/bpftrace/) | `shell` |
| [`bridge`](https://gtfobins.github.io/gtfobins/bridge/) | `file-read` |
| [`bundle`](https://gtfobins.github.io/gtfobins/bundle/) | `inherit`, `shell` |
| [`busctl`](https://gtfobins.github.io/gtfobins/busctl/) | `inherit`, `shell` |
| [`busybox`](https://gtfobins.github.io/gtfobins/busybox/) | `inherit`, `reverse-shell`, `upload` |
| [`byebug`](https://gtfobins.github.io/gtfobins/byebug/) | `inherit` |
| [`bzip2`](https://gtfobins.github.io/gtfobins/bzip2/) | `file-read` |
| [`cabal`](https://gtfobins.github.io/gtfobins/cabal/) | `shell` |
| [`cancel`](https://gtfobins.github.io/gtfobins/cancel/) | `upload` |
| [`capsh`](https://gtfobins.github.io/gtfobins/capsh/) | `shell` |
| [`cargo`](https://gtfobins.github.io/gtfobins/cargo/) | `inherit` |
| [`cat`](https://gtfobins.github.io/gtfobins/cat/) | `file-read` |
| [`cdist`](https://gtfobins.github.io/gtfobins/cdist/) | `shell` |
| [`certbot`](https://gtfobins.github.io/gtfobins/certbot/) | `shell` |
| [`chattr`](https://gtfobins.github.io/gtfobins/chattr/) | `privilege-escalation` |
| [`check_by_ssh`](https://gtfobins.github.io/gtfobins/check_by_ssh/) | `shell` |
| [`check_cups`](https://gtfobins.github.io/gtfobins/check_cups/) | `file-read` |
| [`check_log`](https://gtfobins.github.io/gtfobins/check_log/) | `file-read`, `file-write` |
| [`check_memory`](https://gtfobins.github.io/gtfobins/check_memory/) | `file-read` |
| [`check_raid`](https://gtfobins.github.io/gtfobins/check_raid/) | `file-read` |
| [`check_ssl_cert`](https://gtfobins.github.io/gtfobins/check_ssl_cert/) | `shell` |
| [`check_statusfile`](https://gtfobins.github.io/gtfobins/check_statusfile/) | `file-read` |
| [`chmod`](https://gtfobins.github.io/gtfobins/chmod/) | `privilege-escalation` |
| [`choom`](https://gtfobins.github.io/gtfobins/choom/) | `shell` |
| [`chown`](https://gtfobins.github.io/gtfobins/chown/) | `privilege-escalation` |
| [`chroot`](https://gtfobins.github.io/gtfobins/chroot/) | `shell` |
| [`chrt`](https://gtfobins.github.io/gtfobins/chrt/) | `shell` |
| [`clamscan`](https://gtfobins.github.io/gtfobins/clamscan/) | `file-read` |
| [`clisp`](https://gtfobins.github.io/gtfobins/clisp/) | `shell` |
| [`cmake`](https://gtfobins.github.io/gtfobins/cmake/) | `file-read`, `shell` |
| [`cmp`](https://gtfobins.github.io/gtfobins/cmp/) | `file-read` |
| [`cobc`](https://gtfobins.github.io/gtfobins/cobc/) | `shell` |
| [`code`](https://gtfobins.github.io/gtfobins/code/) | `download`, `reverse-shell`, `upload` |
| [`codex`](https://gtfobins.github.io/gtfobins/codex/) | `shell` |
| [`column`](https://gtfobins.github.io/gtfobins/column/) | `file-read` |
| [`comm`](https://gtfobins.github.io/gtfobins/comm/) | `file-read` |
| [`composer`](https://gtfobins.github.io/gtfobins/composer/) | `shell` |
| [`cowsay`](https://gtfobins.github.io/gtfobins/cowsay/) | `inherit` |
| [`cowthink`](https://gtfobins.github.io/gtfobins/cowthink/) | `inherit` |
| [`cp`](https://gtfobins.github.io/gtfobins/cp/) | `file-read`, `file-write`, `privilege-escalation` |
| [`cpan`](https://gtfobins.github.io/gtfobins/cpan/) | `inherit` |
| [`cpio`](https://gtfobins.github.io/gtfobins/cpio/) | `file-read`, `file-write`, `shell` |
| [`cpulimit`](https://gtfobins.github.io/gtfobins/cpulimit/) | `shell` |
| [`crash`](https://gtfobins.github.io/gtfobins/crash/) | `command`, `inherit` |
| [`crontab`](https://gtfobins.github.io/gtfobins/crontab/) | `command`, `inherit` |
| [`csh`](https://gtfobins.github.io/gtfobins/csh/) | `file-write`, `shell` |
| [`csplit`](https://gtfobins.github.io/gtfobins/csplit/) | `file-read`, `file-write` |
| [`csvtool`](https://gtfobins.github.io/gtfobins/csvtool/) | `file-read`, `file-write`, `shell` |
| [`ctr`](https://gtfobins.github.io/gtfobins/ctr/) | `shell` |
| [`cupsfilter`](https://gtfobins.github.io/gtfobins/cupsfilter/) | `file-read` |
| [`curl`](https://gtfobins.github.io/gtfobins/curl/) | `download`, `file-read`, `file-write`, `library-load`, `upload` |
| [`cut`](https://gtfobins.github.io/gtfobins/cut/) | `file-read` |
| [`dash`](https://gtfobins.github.io/gtfobins/dash/) | `file-write`, `shell` |
| [`date`](https://gtfobins.github.io/gtfobins/date/) | `file-read` |
| [`dc`](https://gtfobins.github.io/gtfobins/dc/) | `shell` |
| [`dd`](https://gtfobins.github.io/gtfobins/dd/) | `file-read`, `file-write` |
| [`debugfs`](https://gtfobins.github.io/gtfobins/debugfs/) | `shell` |
| [`dhclient`](https://gtfobins.github.io/gtfobins/dhclient/) | `shell` |
| [`dialog`](https://gtfobins.github.io/gtfobins/dialog/) | `file-read` |
| [`diff`](https://gtfobins.github.io/gtfobins/diff/) | `file-read` |
| [`dig`](https://gtfobins.github.io/gtfobins/dig/) | `file-read` |
| [`distcc`](https://gtfobins.github.io/gtfobins/distcc/) | `shell` |
| [`dmesg`](https://gtfobins.github.io/gtfobins/dmesg/) | `file-read`, `inherit` |
| [`dmidecode`](https://gtfobins.github.io/gtfobins/dmidecode/) | `file-write` |
| [`dmsetup`](https://gtfobins.github.io/gtfobins/dmsetup/) | `shell` |
| [`dnf`](https://gtfobins.github.io/gtfobins/dnf/) | `command` |
| [`dnsmasq`](https://gtfobins.github.io/gtfobins/dnsmasq/) | `command` |
| [`doas`](https://gtfobins.github.io/gtfobins/doas/) | `shell` |
| [`docker`](https://gtfobins.github.io/gtfobins/docker/) | `file-read`, `file-write`, `shell` |
| [`dos2unix`](https://gtfobins.github.io/gtfobins/dos2unix/) | `file-read`, `file-write` |
| [`dosbox`](https://gtfobins.github.io/gtfobins/dosbox/) | `file-read`, `file-write` |
| [`dotnet`](https://gtfobins.github.io/gtfobins/dotnet/) | `file-read`, `shell` |
| [`dpkg`](https://gtfobins.github.io/gtfobins/dpkg/) | `inherit`, `shell` |
| [`dstat`](https://gtfobins.github.io/gtfobins/dstat/) | `inherit` |
| [`dvips`](https://gtfobins.github.io/gtfobins/dvips/) | `shell` |
| [`easy_install`](https://gtfobins.github.io/gtfobins/easy_install/) | `inherit` |
| [`easyrsa`](https://gtfobins.github.io/gtfobins/easyrsa/) | `shell` |
| [`eb`](https://gtfobins.github.io/gtfobins/eb/) | `inherit` |
| [`ed`](https://gtfobins.github.io/gtfobins/ed/) | `file-read`, `file-write`, `shell` |
| [`efax`](https://gtfobins.github.io/gtfobins/efax/) | `file-read` |
| [`egrep`](https://gtfobins.github.io/gtfobins/egrep/) | `file-read` |
| [`elvish`](https://gtfobins.github.io/gtfobins/elvish/) | `file-read`, `file-write`, `shell` |
| [`emacs`](https://gtfobins.github.io/gtfobins/emacs/) | `file-read`, `file-write`, `shell` |
| [`enscript`](https://gtfobins.github.io/gtfobins/enscript/) | `shell` |
| [`env`](https://gtfobins.github.io/gtfobins/env/) | `shell` |
| [`eqn`](https://gtfobins.github.io/gtfobins/eqn/) | `file-read` |
| [`espeak`](https://gtfobins.github.io/gtfobins/espeak/) | `file-read` |
| [`ex`](https://gtfobins.github.io/gtfobins/ex/) | `inherit`, `shell` |
| [`exiftool`](https://gtfobins.github.io/gtfobins/exiftool/) | `file-read`, `file-write`, `inherit` |
| [`expand`](https://gtfobins.github.io/gtfobins/expand/) | `file-read` |
| [`expect`](https://gtfobins.github.io/gtfobins/expect/) | `file-read`, `shell` |
| [`facter`](https://gtfobins.github.io/gtfobins/facter/) | `inherit` |
| [`fail2ban-client`](https://gtfobins.github.io/gtfobins/fail2ban-client/) | `command` |
| [`fastfetch`](https://gtfobins.github.io/gtfobins/fastfetch/) | `command`, `file-read`, `shell` |
| [`ffmpeg`](https://gtfobins.github.io/gtfobins/ffmpeg/) | `library-load` |
| [`fgrep`](https://gtfobins.github.io/gtfobins/fgrep/) | `file-read` |
| [`file`](https://gtfobins.github.io/gtfobins/file/) | `file-read` |
| [`find`](https://gtfobins.github.io/gtfobins/find/) | `file-read`, `file-write`, `shell` |
| [`finger`](https://gtfobins.github.io/gtfobins/finger/) | `download`, `upload` |
| [`firejail`](https://gtfobins.github.io/gtfobins/firejail/) | `shell` |
| [`fish`](https://gtfobins.github.io/gtfobins/fish/) | `shell` |
| [`flock`](https://gtfobins.github.io/gtfobins/flock/) | `shell` |
| [`fmt`](https://gtfobins.github.io/gtfobins/fmt/) | `file-read` |
| [`fold`](https://gtfobins.github.io/gtfobins/fold/) | `file-read` |
| [`forge`](https://gtfobins.github.io/gtfobins/forge/) | `shell` |
| [`fping`](https://gtfobins.github.io/gtfobins/fping/) | `file-read` |
| [`ftp`](https://gtfobins.github.io/gtfobins/ftp/) | `download`, `shell`, `upload` |
| [`fzf`](https://gtfobins.github.io/gtfobins/fzf/) | `command`, `shell` |
| [`gawk`](https://gtfobins.github.io/gtfobins/gawk/) | `bind-shell`, `file-read`, `file-write`, `reverse-shell`, `shell` |
| [`gcc`](https://gtfobins.github.io/gtfobins/gcc/) | `file-read`, `file-write`, `shell` |
| [`gcloud`](https://gtfobins.github.io/gtfobins/gcloud/) | `inherit` |
| [`gcore`](https://gtfobins.github.io/gtfobins/gcore/) | `file-read` |
| [`gdb`](https://gtfobins.github.io/gtfobins/gdb/) | `file-write`, `inherit`, `shell` |
| [`gem`](https://gtfobins.github.io/gtfobins/gem/) | `inherit`, `shell` |
| [`genie`](https://gtfobins.github.io/gtfobins/genie/) | `shell` |
| [`genisoimage`](https://gtfobins.github.io/gtfobins/genisoimage/) | `file-read` |
| [`getent`](https://gtfobins.github.io/gtfobins/getent/) | `privilege-escalation` |
| [`ghc`](https://gtfobins.github.io/gtfobins/ghc/) | `shell` |
| [`ghci`](https://gtfobins.github.io/gtfobins/ghci/) | `shell` |
| [`gimp`](https://gtfobins.github.io/gtfobins/gimp/) | `inherit` |
| [`ginsh`](https://gtfobins.github.io/gtfobins/ginsh/) | `shell` |
| [`git`](https://gtfobins.github.io/gtfobins/git/) | `file-read`, `file-write`, `inherit`, `shell` |
| [`gnuplot`](https://gtfobins.github.io/gtfobins/gnuplot/) | `shell` |
| [`go`](https://gtfobins.github.io/gtfobins/go/) | `bind-shell`, `file-read`, `file-write`, `reverse-shell`, `shell` |
| [`grc`](https://gtfobins.github.io/gtfobins/grc/) | `shell` |
| [`grep`](https://gtfobins.github.io/gtfobins/grep/) | `file-read` |
| [`gtester`](https://gtfobins.github.io/gtfobins/gtester/) | `file-write`, `shell` |
| [`guile`](https://gtfobins.github.io/gtfobins/guile/) | `shell` |
| [`gzip`](https://gtfobins.github.io/gtfobins/gzip/) | `file-read` |
| [`hashcat`](https://gtfobins.github.io/gtfobins/hashcat/) | `file-write` |
| [`head`](https://gtfobins.github.io/gtfobins/head/) | `file-read` |
| [`hexdump`](https://gtfobins.github.io/gtfobins/hexdump/) | `file-read` |
| [`hg`](https://gtfobins.github.io/gtfobins/hg/) | `shell` |
| [`highlight`](https://gtfobins.github.io/gtfobins/highlight/) | `file-read` |
| [`hping3`](https://gtfobins.github.io/gtfobins/hping3/) | `shell`, `upload` |
| [`iconv`](https://gtfobins.github.io/gtfobins/iconv/) | `file-read`, `file-write` |
| [`iftop`](https://gtfobins.github.io/gtfobins/iftop/) | `shell` |
| [`install`](https://gtfobins.github.io/gtfobins/install/) | `privilege-escalation` |
| [`ionice`](https://gtfobins.github.io/gtfobins/ionice/) | `shell` |
| [`ip`](https://gtfobins.github.io/gtfobins/ip/) | `file-read`, `shell` |
| [`iptables-save`](https://gtfobins.github.io/gtfobins/iptables-save/) | `file-write` |
| [`irb`](https://gtfobins.github.io/gtfobins/irb/) | `inherit` |
| [`ispell`](https://gtfobins.github.io/gtfobins/ispell/) | `shell` |
| [`java`](https://gtfobins.github.io/gtfobins/java/) | `shell` |
| [`jjs`](https://gtfobins.github.io/gtfobins/jjs/) | `download`, `file-read`, `file-write`, `reverse-shell`, `shell` |
| [`joe`](https://gtfobins.github.io/gtfobins/joe/) | `shell` |
| [`join`](https://gtfobins.github.io/gtfobins/join/) | `file-read` |
| [`journalctl`](https://gtfobins.github.io/gtfobins/journalctl/) | `inherit` |
| [`jq`](https://gtfobins.github.io/gtfobins/jq/) | `file-read` |
| [`jrunscript`](https://gtfobins.github.io/gtfobins/jrunscript/) | `download`, `file-read`, `file-write`, `reverse-shell`, `shell` |
| [`jshell`](https://gtfobins.github.io/gtfobins/jshell/) | `file-read`, `file-write`, `shell` |
| [`jtag`](https://gtfobins.github.io/gtfobins/jtag/) | `shell` |
| [`julia`](https://gtfobins.github.io/gtfobins/julia/) | `download`, `file-read`, `file-write`, `reverse-shell`, `shell` |
| [`knife`](https://gtfobins.github.io/gtfobins/knife/) | `inherit` |
| [`ksshell`](https://gtfobins.github.io/gtfobins/ksshell/) | `file-read` |
| [`ksu`](https://gtfobins.github.io/gtfobins/ksu/) | `shell` |
| [`kubectl`](https://gtfobins.github.io/gtfobins/kubectl/) | `shell`, `upload` |
| [`last`](https://gtfobins.github.io/gtfobins/last/) | `file-read` |
| [`latex`](https://gtfobins.github.io/gtfobins/latex/) | `file-read`, `file-write`, `shell` |
| [`latexmk`](https://gtfobins.github.io/gtfobins/latexmk/) | `file-read`, `inherit`, `shell` |
| [`ldconfig`](https://gtfobins.github.io/gtfobins/ldconfig/) | `library-load` |
| [`less`](https://gtfobins.github.io/gtfobins/less/) | `command`, `file-read`, `file-write`, `inherit`, `shell` |
| [`lftp`](https://gtfobins.github.io/gtfobins/lftp/) | `shell` |
| [`links`](https://gtfobins.github.io/gtfobins/links/) | `file-read` |
| [`ln`](https://gtfobins.github.io/gtfobins/ln/) | `privilege-escalation` |
| [`loginctl`](https://gtfobins.github.io/gtfobins/loginctl/) | `shell` |
| [`logrotate`](https://gtfobins.github.io/gtfobins/logrotate/) | `file-read`, `file-write`, `shell` |
| [`logsave`](https://gtfobins.github.io/gtfobins/logsave/) | `shell` |
| [`look`](https://gtfobins.github.io/gtfobins/look/) | `file-read` |
| [`lp`](https://gtfobins.github.io/gtfobins/lp/) | `upload` |
| [`ltrace`](https://gtfobins.github.io/gtfobins/ltrace/) | `file-read`, `file-write`, `shell` |
| [`lua`](https://gtfobins.github.io/gtfobins/lua/) | `bind-shell`, `download`, `file-read`, `file-write`, `reverse-shell`, `shell`, `upload` |
| [`lualatex`](https://gtfobins.github.io/gtfobins/lualatex/) | `inherit` |
| [`luatex`](https://gtfobins.github.io/gtfobins/luatex/) | `inherit` |
| [`lwp-download`](https://gtfobins.github.io/gtfobins/lwp-download/) | `download`, `file-read`, `file-write` |
| [`lwp-request`](https://gtfobins.github.io/gtfobins/lwp-request/) | `file-read` |
| [`lxd`](https://gtfobins.github.io/gtfobins/lxd/) | `shell` |
| [`m4`](https://gtfobins.github.io/gtfobins/m4/) | `command`, `file-read`, `shell` |
| [`mail`](https://gtfobins.github.io/gtfobins/mail/) | `shell` |
| [`make`](https://gtfobins.github.io/gtfobins/make/) | `file-read`, `file-write`, `shell` |
| [`man`](https://gtfobins.github.io/gtfobins/man/) | `file-read`, `inherit`, `shell` |
| [`mawk`](https://gtfobins.github.io/gtfobins/mawk/) | `file-read`, `file-write`, `shell` |
| [`minicom`](https://gtfobins.github.io/gtfobins/minicom/) | `shell` |
| [`more`](https://gtfobins.github.io/gtfobins/more/) | `file-read`, `shell` |
| [`mosh-server`](https://gtfobins.github.io/gtfobins/mosh-server/) | `shell` |
| [`mosquitto`](https://gtfobins.github.io/gtfobins/mosquitto/) | `file-read` |
| [`mount`](https://gtfobins.github.io/gtfobins/mount/) | `privilege-escalation` |
| [`msfconsole`](https://gtfobins.github.io/gtfobins/msfconsole/) | `inherit` |
| [`msgattrib`](https://gtfobins.github.io/gtfobins/msgattrib/) | `file-read` |
| [`msgcat`](https://gtfobins.github.io/gtfobins/msgcat/) | `file-read` |
| [`msgconv`](https://gtfobins.github.io/gtfobins/msgconv/) | `file-read` |
| [`msgfilter`](https://gtfobins.github.io/gtfobins/msgfilter/) | `file-read`, `shell` |
| [`msgmerge`](https://gtfobins.github.io/gtfobins/msgmerge/) | `file-read` |
| [`msguniq`](https://gtfobins.github.io/gtfobins/msguniq/) | `file-read` |
| [`mtr`](https://gtfobins.github.io/gtfobins/mtr/) | `file-read` |
| [`multitime`](https://gtfobins.github.io/gtfobins/multitime/) | `shell` |
| [`mutt`](https://gtfobins.github.io/gtfobins/mutt/) | `file-read` |
| [`mv`](https://gtfobins.github.io/gtfobins/mv/) | `file-write`, `privilege-escalation` |
| [`mypy`](https://gtfobins.github.io/gtfobins/mypy/) | `file-read`, `file-write` |
| [`mysql`](https://gtfobins.github.io/gtfobins/mysql/) | `library-load`, `shell` |
| [`nano`](https://gtfobins.github.io/gtfobins/nano/) | `file-read`, `file-write`, `shell` |
| [`nasm`](https://gtfobins.github.io/gtfobins/nasm/) | `file-read` |
| [`nc`](https://gtfobins.github.io/gtfobins/nc/) | `bind-shell`, `download`, `reverse-shell`, `upload` |
| [`ncdu`](https://gtfobins.github.io/gtfobins/ncdu/) | `shell` |
| [`ncftp`](https://gtfobins.github.io/gtfobins/ncftp/) | `shell` |
| [`needrestart`](https://gtfobins.github.io/gtfobins/needrestart/) | `inherit` |
| [`neofetch`](https://gtfobins.github.io/gtfobins/neofetch/) | `file-read`, `shell` |
| [`nft`](https://gtfobins.github.io/gtfobins/nft/) | `file-read` |
| [`nginx`](https://gtfobins.github.io/gtfobins/nginx/) | `download`, `library-load`, `upload` |
| [`nice`](https://gtfobins.github.io/gtfobins/nice/) | `shell` |
| [`nl`](https://gtfobins.github.io/gtfobins/nl/) | `file-read` |
| [`nm`](https://gtfobins.github.io/gtfobins/nm/) | `file-read` |
| [`nmap`](https://gtfobins.github.io/gtfobins/nmap/) | `file-read`, `file-write`, `inherit`, `shell` |
| [`node`](https://gtfobins.github.io/gtfobins/node/) | `bind-shell`, `download`, `file-read`, `file-write`, `reverse-shell`, `shell`, `upload` |
| [`nohup`](https://gtfobins.github.io/gtfobins/nohup/) | `command`, `shell` |
| [`npm`](https://gtfobins.github.io/gtfobins/npm/) | `shell` |
| [`nroff`](https://gtfobins.github.io/gtfobins/nroff/) | `file-read`, `shell` |
| [`nsenter`](https://gtfobins.github.io/gtfobins/nsenter/) | `shell` |
| [`ntpdate`](https://gtfobins.github.io/gtfobins/ntpdate/) | `file-read` |
| [`octave`](https://gtfobins.github.io/gtfobins/octave/) | `file-read`, `file-write`, `shell` |
| [`od`](https://gtfobins.github.io/gtfobins/od/) | `file-read` |
| [`opencode`](https://gtfobins.github.io/gtfobins/opencode/) | `command`, `inherit` |
| [`openssl`](https://gtfobins.github.io/gtfobins/openssl/) | `download`, `file-read`, `file-write`, `library-load`, `reverse-shell`, `upload` |
| [`openvpn`](https://gtfobins.github.io/gtfobins/openvpn/) | `file-read`, `shell` |
| [`openvt`](https://gtfobins.github.io/gtfobins/openvt/) | `command` |
| [`opkg`](https://gtfobins.github.io/gtfobins/opkg/) | `shell` |
| [`pandoc`](https://gtfobins.github.io/gtfobins/pandoc/) | `file-read`, `file-write`, `inherit` |
| [`passwd`](https://gtfobins.github.io/gtfobins/passwd/) | `privilege-escalation` |
| [`paste`](https://gtfobins.github.io/gtfobins/paste/) | `file-read` |
| [`pax`](https://gtfobins.github.io/gtfobins/pax/) | `file-read` |
| [`pdb`](https://gtfobins.github.io/gtfobins/pdb/) | `inherit` |
| [`pdflatex`](https://gtfobins.github.io/gtfobins/pdflatex/) | `file-read`, `file-write`, `shell` |
| [`pdftex`](https://gtfobins.github.io/gtfobins/pdftex/) | `shell` |
| [`perf`](https://gtfobins.github.io/gtfobins/perf/) | `shell` |
| [`perl`](https://gtfobins.github.io/gtfobins/perl/) | `download`, `file-read`, `reverse-shell`, `shell`, `upload` |
| [`perlbug`](https://gtfobins.github.io/gtfobins/perlbug/) | `shell` |
| [`pexec`](https://gtfobins.github.io/gtfobins/pexec/) | `shell` |
| [`pg`](https://gtfobins.github.io/gtfobins/pg/) | `file-read`, `shell` |
| [`php`](https://gtfobins.github.io/gtfobins/php/) | `command`, `download`, `file-read`, `file-write`, `reverse-shell`, `shell`, `upload` |
| [`pic`](https://gtfobins.github.io/gtfobins/pic/) | `file-read`, `shell` |
| [`pidstat`](https://gtfobins.github.io/gtfobins/pidstat/) | `shell` |
| [`pip`](https://gtfobins.github.io/gtfobins/pip/) | `inherit`, `shell` |
| [`pipx`](https://gtfobins.github.io/gtfobins/pipx/) | `inherit` |
| [`pkexec`](https://gtfobins.github.io/gtfobins/pkexec/) | `shell` |
| [`pkg`](https://gtfobins.github.io/gtfobins/pkg/) | `command` |
| [`plymouth`](https://gtfobins.github.io/gtfobins/plymouth/) | `shell` |
| [`podman`](https://gtfobins.github.io/gtfobins/podman/) | `shell` |
| [`poetry`](https://gtfobins.github.io/gtfobins/poetry/) | `inherit` |
| [`posh`](https://gtfobins.github.io/gtfobins/posh/) | `shell` |
| [`pr`](https://gtfobins.github.io/gtfobins/pr/) | `file-read` |
| [`procmail`](https://gtfobins.github.io/gtfobins/procmail/) | `command` |
| [`pry`](https://gtfobins.github.io/gtfobins/pry/) | `inherit` |
| [`psftp`](https://gtfobins.github.io/gtfobins/psftp/) | `shell` |
| [`psql`](https://gtfobins.github.io/gtfobins/psql/) | `inherit`, `shell` |
| [`ptx`](https://gtfobins.github.io/gtfobins/ptx/) | `file-read` |
| [`puppet`](https://gtfobins.github.io/gtfobins/puppet/) | `file-read`, `file-write`, `shell` |
| [`pwsh`](https://gtfobins.github.io/gtfobins/pwsh/) | `file-write`, `shell` |
| [`pygmentize`](https://gtfobins.github.io/gtfobins/pygmentize/) | `file-read` |
| [`pyright`](https://gtfobins.github.io/gtfobins/pyright/) | `file-read` |
| [`python`](https://gtfobins.github.io/gtfobins/python/) | `download`, `file-read`, `file-write`, `library-load`, `reverse-shell`, `shell`, `upload` |
| [`qpdf`](https://gtfobins.github.io/gtfobins/qpdf/) | `file-read` |
| [`rake`](https://gtfobins.github.io/gtfobins/rake/) | `file-read`, `inherit` |
| [`ranger`](https://gtfobins.github.io/gtfobins/ranger/) | `shell` |
| [`rc`](https://gtfobins.github.io/gtfobins/rc/) | `shell` |
| [`readelf`](https://gtfobins.github.io/gtfobins/readelf/) | `file-read` |
| [`redcarpet`](https://gtfobins.github.io/gtfobins/redcarpet/) | `file-read` |
| [`redis`](https://gtfobins.github.io/gtfobins/redis/) | `file-write` |
| [`restic`](https://gtfobins.github.io/gtfobins/restic/) | `command`, `shell`, `upload` |
| [`rev`](https://gtfobins.github.io/gtfobins/rev/) | `file-read` |
| [`rlogin`](https://gtfobins.github.io/gtfobins/rlogin/) | `upload` |
| [`rlwrap`](https://gtfobins.github.io/gtfobins/rlwrap/) | `file-write`, `shell` |
| [`rpm`](https://gtfobins.github.io/gtfobins/rpm/) | `command`, `inherit`, `shell` |
| [`rpmdb`](https://gtfobins.github.io/gtfobins/rpmdb/) | `inherit`, `shell` |
| [`rpmquery`](https://gtfobins.github.io/gtfobins/rpmquery/) | `inherit`, `shell` |
| [`rpmverify`](https://gtfobins.github.io/gtfobins/rpmverify/) | `inherit`, `shell` |
| [`rsync`](https://gtfobins.github.io/gtfobins/rsync/) | `shell` |
| [`rsyslogd`](https://gtfobins.github.io/gtfobins/rsyslogd/) | `command` |
| [`rtorrent`](https://gtfobins.github.io/gtfobins/rtorrent/) | `shell` |
| [`ruby`](https://gtfobins.github.io/gtfobins/ruby/) | `download`, `file-read`, `file-write`, `library-load`, `reverse-shell`, `shell`, `upload` |
| [`run-mailcap`](https://gtfobins.github.io/gtfobins/run-mailcap/) | `inherit` |
| [`run-parts`](https://gtfobins.github.io/gtfobins/run-parts/) | `shell` |
| [`runscript`](https://gtfobins.github.io/gtfobins/runscript/) | `shell` |
| [`rustc`](https://gtfobins.github.io/gtfobins/rustc/) | `file-read`, `file-write`, `inherit` |
| [`rustdoc`](https://gtfobins.github.io/gtfobins/rustdoc/) | `file-read`, `file-write` |
| [`rustfmt`](https://gtfobins.github.io/gtfobins/rustfmt/) | `file-read` |
| [`rustup`](https://gtfobins.github.io/gtfobins/rustup/) | `command`, `shell` |
| [`sash`](https://gtfobins.github.io/gtfobins/sash/) | `shell` |
| [`scanmem`](https://gtfobins.github.io/gtfobins/scanmem/) | `shell` |
| [`scp`](https://gtfobins.github.io/gtfobins/scp/) | `download`, `shell`, `upload` |
| [`screen`](https://gtfobins.github.io/gtfobins/screen/) | `file-write`, `shell` |
| [`script`](https://gtfobins.github.io/gtfobins/script/) | `file-write`, `shell` |
| [`scrot`](https://gtfobins.github.io/gtfobins/scrot/) | `shell` |
| [`sed`](https://gtfobins.github.io/gtfobins/sed/) | `file-read`, `file-write`, `shell` |
| [`service`](https://gtfobins.github.io/gtfobins/service/) | `shell` |
| [`setarch`](https://gtfobins.github.io/gtfobins/setarch/) | `shell` |
| [`setcap`](https://gtfobins.github.io/gtfobins/setcap/) | `privilege-escalation` |
| [`setfacl`](https://gtfobins.github.io/gtfobins/setfacl/) | `privilege-escalation` |
| [`setlock`](https://gtfobins.github.io/gtfobins/setlock/) | `shell` |
| [`sftp`](https://gtfobins.github.io/gtfobins/sftp/) | `download`, `shell`, `upload` |
| [`sg`](https://gtfobins.github.io/gtfobins/sg/) | `shell` |
| [`shred`](https://gtfobins.github.io/gtfobins/shred/) | `file-write` |
| [`shuf`](https://gtfobins.github.io/gtfobins/shuf/) | `file-read`, `file-write` |
| [`slsh`](https://gtfobins.github.io/gtfobins/slsh/) | `shell` |
| [`smbclient`](https://gtfobins.github.io/gtfobins/smbclient/) | `download`, `shell`, `upload` |
| [`snap`](https://gtfobins.github.io/gtfobins/snap/) | `command` |
| [`socat`](https://gtfobins.github.io/gtfobins/socat/) | `bind-shell`, `download`, `file-read`, `file-write`, `reverse-shell`, `shell`, `upload` |
| [`socket`](https://gtfobins.github.io/gtfobins/socket/) | `bind-shell`, `reverse-shell` |
| [`soelim`](https://gtfobins.github.io/gtfobins/soelim/) | `file-read` |
| [`softlimit`](https://gtfobins.github.io/gtfobins/softlimit/) | `shell` |
| [`sort`](https://gtfobins.github.io/gtfobins/sort/) | `file-read`, `file-write` |
| [`split`](https://gtfobins.github.io/gtfobins/split/) | `file-read`, `file-write`, `shell` |
| [`sqlite3`](https://gtfobins.github.io/gtfobins/sqlite3/) | `file-read`, `file-write`, `shell` |
| [`sqlmap`](https://gtfobins.github.io/gtfobins/sqlmap/) | `inherit` |
| [`ss`](https://gtfobins.github.io/gtfobins/ss/) | `file-read` |
| [`ssh`](https://gtfobins.github.io/gtfobins/ssh/) | `download`, `file-read`, `shell`, `upload` |
| [`ssh-agent`](https://gtfobins.github.io/gtfobins/ssh-agent/) | `shell` |
| [`ssh-copy-id`](https://gtfobins.github.io/gtfobins/ssh-copy-id/) | `file-read`, `file-write` |
| [`ssh-keygen`](https://gtfobins.github.io/gtfobins/ssh-keygen/) | `library-load` |
| [`ssh-keyscan`](https://gtfobins.github.io/gtfobins/ssh-keyscan/) | `file-read` |
| [`sshfs`](https://gtfobins.github.io/gtfobins/sshfs/) | `command`, `download`, `shell`, `upload` |
| [`sshpass`](https://gtfobins.github.io/gtfobins/sshpass/) | `shell` |
| [`sshuttle`](https://gtfobins.github.io/gtfobins/sshuttle/) | `shell` |
| [`start-stop-daemon`](https://gtfobins.github.io/gtfobins/start-stop-daemon/) | `shell` |
| [`stdbuf`](https://gtfobins.github.io/gtfobins/stdbuf/) | `shell` |
| [`strace`](https://gtfobins.github.io/gtfobins/strace/) | `file-write`, `shell` |
| [`strings`](https://gtfobins.github.io/gtfobins/strings/) | `file-read` |
| [`su`](https://gtfobins.github.io/gtfobins/su/) | `shell` |
| [`sudo`](https://gtfobins.github.io/gtfobins/sudo/) | `shell` |
| [`sysctl`](https://gtfobins.github.io/gtfobins/sysctl/) | `command`, `file-read` |
| [`systemctl`](https://gtfobins.github.io/gtfobins/systemctl/) | `inherit`, `shell` |
| [`systemd-resolve`](https://gtfobins.github.io/gtfobins/systemd-resolve/) | `inherit` |
| [`systemd-run`](https://gtfobins.github.io/gtfobins/systemd-run/) | `command`, `shell` |
| [`tac`](https://gtfobins.github.io/gtfobins/tac/) | `file-read` |
| [`tail`](https://gtfobins.github.io/gtfobins/tail/) | `file-read` |
| [`tailscale`](https://gtfobins.github.io/gtfobins/tailscale/) | `upload` |
| [`tar`](https://gtfobins.github.io/gtfobins/tar/) | `download`, `file-read`, `file-write`, `shell`, `upload` |
| [`task`](https://gtfobins.github.io/gtfobins/task/) | `shell` |
| [`taskset`](https://gtfobins.github.io/gtfobins/taskset/) | `shell` |
| [`tasksh`](https://gtfobins.github.io/gtfobins/tasksh/) | `shell` |
| [`tbl`](https://gtfobins.github.io/gtfobins/tbl/) | `file-read` |
| [`tclsh`](https://gtfobins.github.io/gtfobins/tclsh/) | `library-load`, `reverse-shell`, `shell` |
| [`tcpdump`](https://gtfobins.github.io/gtfobins/tcpdump/) | `command`, `file-write` |
| [`tcsh`](https://gtfobins.github.io/gtfobins/tcsh/) | `file-write`, `shell` |
| [`tdbtool`](https://gtfobins.github.io/gtfobins/tdbtool/) | `shell` |
| [`tee`](https://gtfobins.github.io/gtfobins/tee/) | `file-write` |
| [`telnet`](https://gtfobins.github.io/gtfobins/telnet/) | `reverse-shell`, `shell` |
| [`terraform`](https://gtfobins.github.io/gtfobins/terraform/) | `file-read` |
| [`tex`](https://gtfobins.github.io/gtfobins/tex/) | `shell` |
| [`tftp`](https://gtfobins.github.io/gtfobins/tftp/) | `download`, `upload` |
| [`tic`](https://gtfobins.github.io/gtfobins/tic/) | `file-read` |
| [`time`](https://gtfobins.github.io/gtfobins/time/) | `shell` |
| [`timedatectl`](https://gtfobins.github.io/gtfobins/timedatectl/) | `inherit` |
| [`timeout`](https://gtfobins.github.io/gtfobins/timeout/) | `shell` |
| [`tmate`](https://gtfobins.github.io/gtfobins/tmate/) | `shell` |
| [`tmux`](https://gtfobins.github.io/gtfobins/tmux/) | `file-read`, `shell` |
| [`top`](https://gtfobins.github.io/gtfobins/top/) | `shell` |
| [`torify`](https://gtfobins.github.io/gtfobins/torify/) | `shell` |
| [`torsocks`](https://gtfobins.github.io/gtfobins/torsocks/) | `shell` |
| [`troff`](https://gtfobins.github.io/gtfobins/troff/) | `file-read` |
| [`tsc`](https://gtfobins.github.io/gtfobins/tsc/) | `file-read`, `file-write` |
| [`tshark`](https://gtfobins.github.io/gtfobins/tshark/) | `inherit` |
| [`ul`](https://gtfobins.github.io/gtfobins/ul/) | `file-read` |
| [`unexpand`](https://gtfobins.github.io/gtfobins/unexpand/) | `file-read` |
| [`uniq`](https://gtfobins.github.io/gtfobins/uniq/) | `file-read` |
| [`unshare`](https://gtfobins.github.io/gtfobins/unshare/) | `shell` |
| [`unsquashfs`](https://gtfobins.github.io/gtfobins/unsquashfs/) | `privilege-escalation` |
| [`unzip`](https://gtfobins.github.io/gtfobins/unzip/) | `privilege-escalation` |
| [`update-alternatives`](https://gtfobins.github.io/gtfobins/update-alternatives/) | `file-write` |
| [`urlget`](https://gtfobins.github.io/gtfobins/urlget/) | `file-read` |
| [`uuencode`](https://gtfobins.github.io/gtfobins/uuencode/) | `file-read` |
| [`uv`](https://gtfobins.github.io/gtfobins/uv/) | `shell` |
| [`vagrant`](https://gtfobins.github.io/gtfobins/vagrant/) | `inherit` |
| [`valgrind`](https://gtfobins.github.io/gtfobins/valgrind/) | `shell` |
| [`varnishncsa`](https://gtfobins.github.io/gtfobins/varnishncsa/) | `file-write` |
| [`vi`](https://gtfobins.github.io/gtfobins/vi/) | `file-read`, `file-write`, `shell` |
| [`vigr`](https://gtfobins.github.io/gtfobins/vigr/) | `inherit` |
| [`vim`](https://gtfobins.github.io/gtfobins/vim/) | `file-read`, `inherit` |
| [`vipw`](https://gtfobins.github.io/gtfobins/vipw/) | `inherit` |
| [`virsh`](https://gtfobins.github.io/gtfobins/virsh/) | `command`, `file-write` |
| [`volatility`](https://gtfobins.github.io/gtfobins/volatility/) | `inherit` |
| [`w3m`](https://gtfobins.github.io/gtfobins/w3m/) | `file-read` |
| [`wall`](https://gtfobins.github.io/gtfobins/wall/) | `file-read` |
| [`watch`](https://gtfobins.github.io/gtfobins/watch/) | `shell` |
| [`wc`](https://gtfobins.github.io/gtfobins/wc/) | `file-read` |
| [`wg-quick`](https://gtfobins.github.io/gtfobins/wg-quick/) | `shell` |
| [`wget`](https://gtfobins.github.io/gtfobins/wget/) | `download`, `file-read`, `file-write`, `shell`, `upload` |
| [`whiptail`](https://gtfobins.github.io/gtfobins/whiptail/) | `file-read` |
| [`whois`](https://gtfobins.github.io/gtfobins/whois/) | `download`, `upload` |
| [`wireshark`](https://gtfobins.github.io/gtfobins/wireshark/) | `file-write`, `inherit` |
| [`wish`](https://gtfobins.github.io/gtfobins/wish/) | `inherit` |
| [`xargs`](https://gtfobins.github.io/gtfobins/xargs/) | `file-read`, `shell` |
| [`xdg-user-dir`](https://gtfobins.github.io/gtfobins/xdg-user-dir/) | `shell` |
| [`xdotool`](https://gtfobins.github.io/gtfobins/xdotool/) | `shell` |
| [`xmodmap`](https://gtfobins.github.io/gtfobins/xmodmap/) | `file-read` |
| [`xmore`](https://gtfobins.github.io/gtfobins/xmore/) | `file-read` |
| [`xpad`](https://gtfobins.github.io/gtfobins/xpad/) | `file-read` |
| [`xxd`](https://gtfobins.github.io/gtfobins/xxd/) | `file-read`, `file-write` |
| [`xz`](https://gtfobins.github.io/gtfobins/xz/) | `file-read` |
| [`yarn`](https://gtfobins.github.io/gtfobins/yarn/) | `shell` |
| [`yash`](https://gtfobins.github.io/gtfobins/yash/) | `shell` |
| [`yelp`](https://gtfobins.github.io/gtfobins/yelp/) | `file-read` |
| [`yt-dlp`](https://gtfobins.github.io/gtfobins/yt-dlp/) | `shell` |
| [`yum`](https://gtfobins.github.io/gtfobins/yum/) | `command`, `download`, `inherit` |
| [`zathura`](https://gtfobins.github.io/gtfobins/zathura/) | `shell` |
| [`zcat`](https://gtfobins.github.io/gtfobins/zcat/) | `file-read` |
| [`zgrep`](https://gtfobins.github.io/gtfobins/zgrep/) | `file-read` |
| [`zic`](https://gtfobins.github.io/gtfobins/zic/) | `command` |
| [`zip`](https://gtfobins.github.io/gtfobins/zip/) | `file-read`, `shell` |
| [`zless`](https://gtfobins.github.io/gtfobins/zless/) | `inherit` |
| [`zsh`](https://gtfobins.github.io/gtfobins/zsh/) | `download`, `file-read`, `file-write`, `inherit`, `reverse-shell`, `shell`, `upload` |
| [`zsoelim`](https://gtfobins.github.io/gtfobins/zsoelim/) | `file-read` |
| [`zypper`](https://gtfobins.github.io/gtfobins/zypper/) | `shell` |

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
