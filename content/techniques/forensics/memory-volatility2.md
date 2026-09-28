---
title: "Memory Forensics - Volatility 2 When You Must"
category: forensics
subcategory: memory
type: technique
tags: [volatility, volatility2, vol2, vol-py, imageinfo, kdbgscan, profile, memory-dump, ram-dump, userassist, shellbags, shimcache, iehistory, python2, plugin-translation, dfir]
difficulty: medium
summary: "Getting Volatility 2 running in 2026, picking the right --profile, and the full vol2-to-vol3 plugin translation table."
when_to_use:
  - "The challenge is old and every writeup you can find uses vol.py"
  - "You need a plugin vol3 does not have: userassist, shellbags, shimcache, iehistory, apihooks"
  - "vol3 reports 'unsatisfied requirement' but vol2 kdbgscan finds a valid KDBG"
  - "You have a custom Linux/Mac profile zip but no ISF symbol table"
tools: [volatility, volatility3, python2, docker]
related: [memory-volatility3-workflow, memory-credential-extraction, memory-injected-code]
---

## TL;DR

Volatility 2 is Python 2 and dead upstream, but it still wins on Windows user-activity plugins
(`userassist`, `shellbags`, `shimcache`, `iehistory`) and on any image where vol3 cannot resolve
symbols. The workflow is always: `imageinfo` -> pick a `--profile` -> run plugins. If `imageinfo`
is slow or wrong, use `kdbgscan` and pass `--kdbg` explicitly.

## Recognise it

- Writeup or challenge text mentions `vol.py`, `--profile=Win7SP1x64`, `imageinfo`.
- vol3 cannot find a symbol table for an XP/Vista/Win7 image.
- You need a plugin that only ever existed in the vol2 community repo.
- The provided artefact is a Linux dump plus a `.zip` profile (that is a vol2 profile, not an ISF).

## Getting it to run in 2026

Python 2.7 is gone from most distros. Four options, best first:

```sh
# 1) docker: the least painful, no python2 on your host
docker run --rm -it -v "$PWD":/data phocean/volatility -f /data/mem.raw imageinfo
# 1b) build your own pinned image if you want the community plugins baked in
printf 'FROM python:2.7-slim\nRUN pip install pycrypto distorm3==3.4.4 yara-python==3.8.1 openpyxl\nADD . /vol\nWORKDIR /vol\n' > Dockerfile

# 2) pyenv + virtualenv on the host
pyenv install 2.7.18 && pyenv virtualenv 2.7.18 vol2 && pyenv activate vol2
pip install pycryptodome distorm3 yara-python pytz openpyxl
git clone https://github.com/volatilityfoundation/volatility /opt/volatility
python2 /opt/volatility/vol.py -h

# 3) the standalone binary release (no python needed at all)
chmod +x volatility_2.6_lin64_standalone && ./volatility_2.6_lin64_standalone -h

# 4) distro package where it still exists
apt-get install -y volatility volatility-tools
```

Dependency notes: `distorm3` gives you disassembly in `malfind`/`apihooks`; `yara-python`
enables `yarascan`; `pycrypto`/`pycryptodome` enables `hashdump`/`lsadump`/`truecryptmaster`.
Without them the plugins silently do less.

## Workflow

### Step 1 - find the profile

```sh
# scans for KDBG signatures and suggests profiles; slow on big images but thorough
vol.py -f mem.raw imageinfo
# faster and more precise: score every KDBG candidate, take the one with most processes/modules
vol.py -f mem.raw kdbgscan
# list every profile this install knows about
vol.py --info | grep -A400 'Profiles'
# once chosen, every command needs the profile
vol.py -f mem.raw --profile=Win7SP1x64 pslist
# if imageinfo guessed wrong, force the KDBG address kdbgscan printed
vol.py -f mem.raw --profile=Win7SP1x64 --kdbg=0xf80002c410a0 pslist
```

Rules of thumb:

- `imageinfo` prints `Suggested Profile(s)` in order of likelihood. Try them left to right.
- The real signal is **which profile makes `pslist` return a sane process tree** with `System`,
  `smss.exe`, `csrss.exe`, `services.exe`, `lsass.exe`. If you see garbage, the profile is wrong.
- `kdbgscan` output with the highest `Profile suggestion` + non-zero `PsActiveProcessHead` wins.
- x86 vs x64 matters: `Win7SP1x86` and `Win7SP1x64` are different profiles.
- `--dtb=0x...` can rescue an image where the DTB autodetect fails.

### Step 2 - the core runs

```sh
# processes three ways; the union is your ground truth
vol.py -f mem.raw --profile=Win7SP1x64 pslist
vol.py -f mem.raw --profile=Win7SP1x64 psscan
vol.py -f mem.raw --profile=Win7SP1x64 pstree
# the killer plugin: cross-references pslist/psscan/thrdproc/csrss/session/deskthrd
vol.py -f mem.raw --profile=Win7SP1x64 psxview
# command lines and console scrollback
vol.py -f mem.raw --profile=Win7SP1x64 cmdline
vol.py -f mem.raw --profile=Win7SP1x64 consoles
vol.py -f mem.raw --profile=Win7SP1x64 cmdscan
# network (XP/2003 use connections/sockets, Vista+ use netscan)
vol.py -f mem.raw --profile=WinXPSP3x86 connscan
vol.py -f mem.raw --profile=WinXPSP3x86 sockets
vol.py -f mem.raw --profile=Win7SP1x64 netscan
```

### Step 3 - extraction

```sh
# dump one process' executable image
vol.py -f mem.raw --profile=Win7SP1x64 procdump -p 1234 -D ./out/
# dump one process' entire addressable memory (heap, stack, injected blobs)
vol.py -f mem.raw --profile=Win7SP1x64 memdump -p 1234 -D ./out/
# dump a DLL loaded by a process
vol.py -f mem.raw --profile=Win7SP1x64 dlldump -p 1234 -D ./out/
# dump a kernel driver
vol.py -f mem.raw --profile=Win7SP1x64 moddump -D ./out/
# find a file in the pool, then extract it by its physical offset
vol.py -f mem.raw --profile=Win7SP1x64 filescan | grep -i 'flag'
vol.py -f mem.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003e8b7c40 -D ./out/
# dump all cached files for a PID (both DataSectionObject and ImageSectionObject)
vol.py -f mem.raw --profile=Win7SP1x64 dumpfiles -p 1234 -D ./out/ -n
```

### Step 4 - the plugins vol3 does not have

```sh
# UserAssist: GUI program execution with run counts and focus time (ROT13 key names)
vol.py -f mem.raw --profile=Win7SP1x64 userassist
# Shellbags: folders the user browsed in Explorer, including deleted and removable paths
vol.py -f mem.raw --profile=Win7SP1x64 shellbags
# ShimCache / AppCompatCache: binaries the shim engine saw
vol.py -f mem.raw --profile=Win7SP1x64 shimcache
# Internet Explorer / WinINet cache entries, including for non-IE apps
vol.py -f mem.raw --profile=Win7SP1x64 iehistory
# TrueCrypt/VeraCrypt master keys still resident in RAM
vol.py -f mem.raw --profile=Win7SP1x64 truecryptsummary
vol.py -f mem.raw --profile=Win7SP1x64 truecryptmaster
# inline hooks in userland and kernel (needs distorm3)
vol.py -f mem.raw --profile=Win7SP1x64 apihooks
# raw notepad buffer, on-screen windows, and edit-control text
vol.py -f mem.raw --profile=WinXPSP3x86 notepad
vol.py -f mem.raw --profile=Win7SP1x64 editbox
vol.py -f mem.raw --profile=Win7SP1x64 screenshot -D ./out/
# BIOS keyboard buffer (pre-boot typed password on old images)
vol.py -f mem.raw --profile=WinXPSP3x86 bioskbd
# saved clipboard contents
vol.py -f mem.raw --profile=Win7SP1x64 clipboard
# firefox/chrome plugins from the community repo, and mimikatz
vol.py --plugins=/opt/volatility-plugins -f mem.raw --profile=Win7SP1x64 mimikatz
vol.py --plugins=/opt/volatility-plugins -f mem.raw --profile=Win7SP1x64 chromehistory
```

`--plugins=DIR` (note: comes **before** `-f`) loads any `.py` plugin file in `DIR`. The community
repo is a flat directory of such files; clone it once and point at it.

## vol2 -> vol3 plugin translation table

| Volatility 2 | Volatility 3 |
| --- | --- |
| `imageinfo`, `kdbgscan` | `windows.info` (no profile needed) |
| `pslist` | `windows.pslist` |
| `psscan` | `windows.psscan` |
| `pstree` | `windows.pstree` |
| `psxview` | *(none)* - diff `pslist` vs `psscan` manually |
| `cmdline` | `windows.cmdline` |
| `consoles` | `windows.consoles` |
| `cmdscan` | `windows.cmdscan` |
| `dlllist` | `windows.dlllist` |
| `handles` | `windows.handles` |
| `getsids` | `windows.getsids` |
| `envars` | `windows.envars` |
| `privs` | `windows.privileges.Privs` |
| `filescan` | `windows.filescan` |
| `dumpfiles -Q/-p` | `windows.dumpfiles --physaddr/--virtaddr/--pid` |
| `memdump -p` | `windows.memmap --pid N --dump` |
| `procdump -p` | `windows.pslist --pid N --dump` |
| `dlldump` | `windows.dlllist --pid N --dump` |
| `moddump` | `windows.modules --dump` |
| `vadinfo` / `vadtree` / `vaddump` | `windows.vadinfo` / `windows.vadwalk` / `windows.vadinfo --dump` |
| `malfind` | `windows.malfind` |
| `ldrmodules` | `windows.ldrmodules` |
| `hollowfind` (community) | *(none)* - use `malfind` + `ldrmodules` + `vadinfo` |
| `apihooks` | *(none)* |
| `threads` | `windows.threads.Threads` |
| `mutantscan` | `windows.mutantscan.MutantScan` |
| `svcscan` | `windows.svcscan` |
| `modules` / `modscan` | `windows.modules` / `windows.modscan` |
| `driverscan` / `driverirp` | `windows.driverscan` / `windows.driverirp` |
| `ssdt` | `windows.ssdt` |
| `callbacks` | `windows.callbacks` |
| `idt` / `gdt` | *(none)* |
| `netscan` | `windows.netscan` |
| `connections` / `connscan` / `sockets` / `sockscan` | `windows.netscan` (all four merged) |
| `hivelist` / `hivescan` | `windows.registry.hivelist` / `windows.registry.hivescan` |
| `printkey -K "..."` | `windows.registry.printkey --key "..."` |
| `hashdump` | `windows.hashdump.Hashdump` |
| `lsadump` | `windows.lsadump.Lsadump` |
| `cachedump` | `windows.cachedump.Cachedump` |
| `clipboard` | `windows.clipboard` |
| `mftparser` | `windows.mftscan.MFTScan` |
| `timeliner` | `timeliner.Timeliner` |
| `yarascan` | `yarascan.YaraScan` / `windows.vadyarascan` |
| `volshell` | `windows.volshell` (`vol3 -f img windows.volshell`) |
| `userassist` | *(none)* |
| `shellbags` | *(none)* |
| `shimcache` | *(none)* |
| `iehistory` | *(none)* |
| `truecryptsummary` / `truecryptmaster` | *(none)* |
| `bioskbd` / `notepad` / `editbox` / `screenshot` | *(none)* |
| `linux_bash` | `linux.bash.Bash` |
| `linux_pslist` / `linux_pstree` / `linux_psaux` | `linux.pslist` / `linux.pstree` / `linux.psaux` |
| `linux_netstat` | `linux.sockstat.Sockstat` |
| `linux_lsof` | `linux.lsof.Lsof` |
| `linux_proc_maps` | `linux.proc.Maps` |
| `linux_check_syscall` / `linux_check_modules` | `linux.check_syscall` / `linux.check_modules` |
| `mac_pslist` / `mac_netstat` | `mac.pslist` / `mac.netstat` |

## Custom profiles (Linux / Mac)

vol3 uses ISF JSON. vol2 uses a **profile zip** containing a `module.dwarf` and a `System.map`.

```sh
# on a box matching the target kernel, build the dwarf module
apt-get install -y build-essential dwarfdump linux-headers-$(uname -r)
cd /opt/volatility/tools/linux && make
# that produces module.dwarf; pair it with the running kernel's System.map
zip Ubuntu2204-5.15.0-91-generic.zip module.dwarf /boot/System.map-$(uname -r)
# drop the zip where volatility looks for profiles
cp Ubuntu2204-*.zip /opt/volatility/volatility/plugins/overlays/linux/
# confirm the profile registered
vol.py --info | grep -i linux
# then use it
vol.py -f mem.lime --profile=LinuxUbuntu2204-5_15_0-91-genericx64 linux_bash
```

## Code

```python
#!/usr/bin/env python3
"""Translate a Volatility 2 command line into the Volatility 3 equivalent.

Usage:
    python3 vol2to3.py 'vol.py -f mem.raw --profile=Win7SP1x64 dumpfiles -Q 0x3e8b7c40 -D out/'
    python3 vol2to3.py            # runs the built-in self-test
"""
from __future__ import annotations

import shlex
import sys

PLUGIN_MAP: dict[str, str] = {
    "imageinfo": "windows.info", "kdbgscan": "windows.info",
    "pslist": "windows.pslist", "psscan": "windows.psscan", "pstree": "windows.pstree",
    "cmdline": "windows.cmdline", "consoles": "windows.consoles", "cmdscan": "windows.cmdscan",
    "dlllist": "windows.dlllist", "handles": "windows.handles", "getsids": "windows.getsids",
    "envars": "windows.envars", "privs": "windows.privileges.Privs",
    "filescan": "windows.filescan", "dumpfiles": "windows.dumpfiles",
    "memdump": "windows.memmap", "procdump": "windows.pslist", "dlldump": "windows.dlllist",
    "moddump": "windows.modules",
    "vadinfo": "windows.vadinfo", "vadtree": "windows.vadwalk", "vaddump": "windows.vadinfo",
    "malfind": "windows.malfind", "ldrmodules": "windows.ldrmodules",
    "threads": "windows.threads.Threads", "mutantscan": "windows.mutantscan.MutantScan",
    "svcscan": "windows.svcscan", "modules": "windows.modules", "modscan": "windows.modscan",
    "driverscan": "windows.driverscan", "driverirp": "windows.driverirp",
    "ssdt": "windows.ssdt", "callbacks": "windows.callbacks",
    "netscan": "windows.netscan", "connections": "windows.netscan", "connscan": "windows.netscan",
    "sockets": "windows.netscan", "sockscan": "windows.netscan",
    "hivelist": "windows.registry.hivelist", "hivescan": "windows.registry.hivescan",
    "printkey": "windows.registry.printkey",
    "hashdump": "windows.hashdump.Hashdump", "lsadump": "windows.lsadump.Lsadump",
    "cachedump": "windows.cachedump.Cachedump", "clipboard": "windows.clipboard",
    "mftparser": "windows.mftscan.MFTScan", "timeliner": "timeliner.Timeliner",
    "yarascan": "yarascan.YaraScan", "volshell": "windows.volshell",
    "linux_bash": "linux.bash.Bash", "linux_pslist": "linux.pslist",
    "linux_pstree": "linux.pstree", "linux_psaux": "linux.psaux",
    "linux_netstat": "linux.sockstat.Sockstat", "linux_lsof": "linux.lsof.Lsof",
    "linux_proc_maps": "linux.proc.Maps", "linux_check_syscall": "linux.check_syscall",
    "linux_check_modules": "linux.check_modules",
    "mac_pslist": "mac.pslist", "mac_netstat": "mac.netstat",
}
NO_EQUIVALENT = {
    "psxview": "diff windows.pslist against windows.psscan",
    "userassist": "no vol3 plugin - parse NTUSER.DAT offline instead",
    "shellbags": "no vol3 plugin - dump UsrClass.dat and use shellbags parsers",
    "shimcache": "no vol3 plugin - dump SYSTEM hive and use AppCompatCacheParser",
    "iehistory": "no vol3 plugin - carve WebCacheV01.dat / index.dat",
    "apihooks": "no vol3 plugin",
    "hollowfind": "no vol3 plugin - windows.malfind + windows.ldrmodules + windows.vadinfo",
    "truecryptmaster": "no vol3 plugin", "truecryptsummary": "no vol3 plugin",
    "bioskbd": "no vol3 plugin", "notepad": "no vol3 plugin",
    "editbox": "no vol3 plugin", "screenshot": "no vol3 plugin",
    "idt": "no vol3 plugin", "gdt": "no vol3 plugin",
}
# vol2 flag -> (vol3 flag, whether it belongs before the plugin name)
FLAG_MAP = {"-p": ("--pid", False), "--pid": ("--pid", False),
            "-Q": ("--physaddr", False), "-V": ("--virtaddr", False),
            "-D": ("-o", True), "--dump-dir": ("-o", True),
            "-K": ("--key", False), "--key": ("--key", False),
            "-Y": ("--yara-rules", False), "-y": ("--yara-file", False),
            "-o": ("--offset", False)}
DUMPING_PLUGINS = {"memdump", "procdump", "dlldump", "moddump", "vaddump"}


def translate(cmdline: str) -> str:
    argv = shlex.split(cmdline)
    image, pre, post, plugin, notes = None, [], [], None, []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("vol.py", "vol", "volatility", "python2", "python"):
            i += 1
            continue
        if tok == "-f" or tok == "--filename":
            image = argv[i + 1]
            i += 2
            continue
        if tok.startswith("--profile") or tok.startswith("--kdbg") or tok.startswith("--dtb"):
            i += 1 if "=" in tok else 2
            notes.append(f"dropped {tok.split('=')[0]} (vol3 resolves symbols automatically)")
            continue
        if tok.startswith("--plugins"):
            i += 1 if "=" in tok else 2
            notes.append("dropped --plugins (vol3 uses -p / PLUGIN_PATH)")
            continue
        if plugin is None and not tok.startswith("-"):
            plugin = tok
            i += 1
            continue
        if tok in FLAG_MAP:
            new, is_global = FLAG_MAP[tok]
            val = argv[i + 1] if i + 1 < len(argv) else ""
            (pre if is_global else post).extend([new, val])
            i += 2
            continue
        post.append(tok)
        i += 1

    if plugin is None:
        return "# could not find a plugin name in that command line"
    if plugin in NO_EQUIVALENT:
        return f"# {plugin}: {NO_EQUIVALENT[plugin]}"
    new_plugin = PLUGIN_MAP.get(plugin)
    if new_plugin is None:
        return f"# unknown vol2 plugin {plugin!r}; check `vol3 -h`"
    if plugin in DUMPING_PLUGINS:
        post.append("--dump")
        notes.append(f"{plugin} becomes {new_plugin} --dump")
    parts = ["vol3"] + pre + ["-f", image or "mem.raw", new_plugin] + post
    out = " ".join(shlex.quote(p) if " " in p else p for p in parts)
    for n in notes:
        out += f"\n# note: {n}"
    return out


def _selftest() -> None:
    got = translate("vol.py -f mem.raw --profile=Win7SP1x64 pslist")
    assert got.startswith("vol3 -f mem.raw windows.pslist"), got
    got = translate("vol.py -f mem.raw --profile=Win7SP1x64 memdump -p 1234 -D out/")
    assert "--pid 1234" in got and "-o out/" in got and "--dump" in got, got
    got = translate("vol.py -f m.raw --profile=Win7SP1x64 psxview")
    assert got.startswith("# psxview"), got
    got = translate("vol.py -f m.raw --profile=WinXPSP3x86 printkey -K 'Microsoft\\Windows'")
    assert "windows.registry.printkey" in got and "--key" in got, got
    print("self-test OK")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "--selftest":
        _selftest()
    else:
        print(translate(" ".join(args)))
```

## Variants & pitfalls

- `--plugins=` must appear **before** `-f` or vol2 will not pick the directory up.
- `-D out/` directories must already exist; vol2 does not create them.
- `dumpfiles -Q` takes a **physical** offset (the first column of `filescan`), `-V` a virtual one.
  Add `-n` to keep the original file names, `-u` to also dump unlinked.
- `hashdump` needs both the SYSTEM and SAM hives resident; on Win10 1607+ the NT hashes are often
  not recoverable this way - dump `lsass.exe` and use `pypykatz` instead.
- `pycrypto` fails to build on modern toolchains; install `pycryptodome` and it satisfies the same
  imports for most plugins.
- The standalone binary has **no** community plugins and no `--plugins` support in older builds.
- Profiles are per-kernel-build. `Win7SP1x64` covers many builds; `Win10x64_19041` does not cover
  19045. When in doubt, use vol3 for Win10/11 and vol2 only for XP-through-Win8.1 plus the
  user-activity plugins.

## Tools

`volatility` 2.6.1, `volatility3`, `pyenv`, Docker, the community plugin repository,
`pypykatz` (replaces the `mimikatz` plugin), `RegRipper` (replaces `userassist`/`shellbags`
once you have dumped the hives).

## References

- `vol.py --info` lists every profile, plugin, address space and scanner your build has.
- `vol.py <plugin> -h` for per-plugin flags.
