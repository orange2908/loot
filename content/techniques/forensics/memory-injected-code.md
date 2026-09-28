---
title: "Memory Forensics - Finding Injected Code and Malware"
category: forensics
subcategory: memory
type: technique
tags: [malfind, hollowfind, ldrmodules, vadinfo, vad, process-injection, process-hollowing, dll-injection, volatility3, volatility, yara, yarascan, rootkit, ssdt, callbacks, modscan, memory-dump, dfir]
difficulty: hard
summary: "Spot process injection, hollowing and unlinked drivers in a RAM image using malfind, ldrmodules, VAD protections and pslist-vs-psscan diffs."
when_to_use:
  - "The scenario says 'malware was running' but nothing suspicious is in pslist"
  - "A legitimate process (svchost, explorer, notepad) has network connections it should not have"
  - "You need to extract a shellcode blob or a hidden PE from RAM"
  - "A driver or process is hidden from the live lists but appears in a pool scan"
tools: [volatility3, volatility, yara, capa, strings, binwalk, radare2]
related: [memory-volatility3-workflow, memory-volatility2, memory-credential-extraction, network-c2-analysis]
---

## TL;DR

Injected code is memory that is **private**, **executable**, and **not backed by a file on disk**.
`malfind` finds exactly that. Hollowing is the opposite trick: a legitimate mapped image whose
in-memory content no longer matches the file, betrayed by `ldrmodules` gaps and VAD protection
mismatches. Cross-check with parent/child anomalies and unlinked kernel modules.

## Recognise it

- `pstree` shows `svchost.exe` whose parent is not `services.exe`, or `lsass.exe` with children.
- Two `explorer.exe`, or a `csrss.exe` with a path under `C:\Users\...\AppData\`.
- `netscan` attributes an outbound connection to `notepad.exe` / `calc.exe` / `rundll32.exe`.
- A process present in `psscan` but missing from `pslist`.
- `dlllist` shows a DLL loaded from `\Temp\`, `\AppData\Local\Temp\`, `\ProgramData\`, or a path
  with no file name extension.
- Misspelled system binaries: `scvhost.exe`, `svch0st.exe`, `lsasss.exe`, `csrsss.exe`,
  `services .exe` (trailing space), `explore.exe`, `winlogin.exe`.

## Theory - the VAD

Every user-mode allocation is described by a node in the process' **Virtual Address Descriptor**
tree. The two fields that matter:

- **Type**: `VadS` (private, no file object) vs `Vad`/`VadImage` (mapped, has a `ControlArea`
  pointing at a `FILE_OBJECT`).
- **Protection**: `PAGE_EXECUTE_READWRITE` (0x40) is the injection tell. Legitimate code is
  mapped `PAGE_EXECUTE_WRITECOPY` from an image and never needs RWX.

`malfind` enumerates VADs where *(private OR no mapped file)* AND *(protection includes EXECUTE)*
AND the first bytes do not look like a normal PE prologue, then disassembles the head.

Hollowing (RunPE) works differently: the loader maps the legitimate image, the malware
`NtUnmapViewOfSection`s it and `WriteProcessMemory`s a different PE into the same base. The PEB
still claims the original path, so:

- `ldrmodules` shows the base present in one or two of the three loader lists but not all three
  (`InLoad`, `InInit`, `InMem`), or with an empty `MappedPath`.
- `vadinfo` shows the image base as **private** memory or with `PAGE_EXECUTE_READWRITE`.
- The on-disk file's size/hash does not match the in-memory image.

## Workflow

### 1. malfind

```sh
# the one-liner that finds most injection
vol3 -f mem.raw windows.malfind
# write every hit to disk as a raw blob for offline analysis
vol3 -f mem.raw -o ./inj windows.malfind --dump
# narrow to one process
vol3 -f mem.raw windows.malfind --pid 1234
# vol2 form (needs distorm3 for the disassembly column)
vol.py -f mem.raw --profile=Win7SP1x64 malfind -D ./inj/
```

Reading the output: each hit prints the VAD start/end, protection, the first 64 bytes as hex, and
a short disassembly. What you want to see in the disassembly:

- `MZ` (`4D 5A`) at offset 0 -> a whole PE was written into private memory. Carve it.
- `55 8B EC` / `48 89 5C 24` -> a real function prologue. Real code.
- `E8 00 00 00 00` `5?` -> call-pop, classic position-independent shellcode getting EIP.
- `FC 48 83 E4 F0` -> the canonical x64 Metasploit/Cobalt Strike stager prologue.
- `EB xx` / `E9 xxxxxxxx` at offset 0 -> a jump stub, follow it.
- All zeros or `00 00 ADD [EAX], AL` -> a false positive, ignore.

Known false positives: .NET JIT regions (`clr.dll` loaded), Chrome/Edge V8 code pages, `csrss.exe`
and `wininit.exe` shim regions, `dwm.exe`, antivirus hooking engines. Correlate with the process
name before you call it malicious.

### 2. Carve the injected PE out

```sh
# malfind --dump writes files like pid.1234.vad.0x2a0000-0x2affff.dmp
ls -l ./inj/
file ./inj/*.dmp
# if the blob starts with MZ, it is a PE: fix it up and analyse
python3 -c "import sys;d=open(sys.argv[1],'rb').read();print(d[:2], len(d))" ./inj/pid.1234.*.dmp
# strings both ways
strings -a ./inj/*.dmp | grep -aiE '(http|\.onion|cmd\.exe|powershell|user-agent)'
strings -a -el ./inj/*.dmp | sort -u | head -50
# capability triage
capa ./inj/pid.1234.vad.0x2a0000-0x2affff.dmp
# quick disassembly of the head
objdump -D -b binary -m i386:x86-64 ./inj/blob.dmp | head -60
r2 -a x86 -b 64 -qc 'pd 40' ./inj/blob.dmp
```

### 3. ldrmodules and hollowing

```sh
# three loader lists per module; any False is worth a look
vol3 -f mem.raw windows.ldrmodules --pid 1234
# vol2 has the friendlier column layout and a -v for full paths
vol.py -f mem.raw --profile=Win7SP1x64 ldrmodules -p 1234 -v
# the vol2 community plugin that automates hollowing detection
vol.py --plugins=/opt/volatility-plugins -f mem.raw --profile=Win7SP1x64 hollowfind
# VAD protections: look for PAGE_EXECUTE_READWRITE on the image base
vol3 -f mem.raw windows.vadinfo --pid 1234 | grep -i execute
# walk the whole VAD tree with parent/child structure
vol3 -f mem.raw windows.vadwalk --pid 1234
# dump a specific VAD range
vol3 -f mem.raw -o ./vads windows.vadinfo --pid 1234 --address 0x2a0000 --dump
```

Interpretation table:

| ldrmodules pattern | Meaning |
| --- | --- |
| InLoad=True InInit=True InMem=True | normal |
| all three False, MappedPath set | manually mapped DLL (reflective loading) |
| InLoad=True, InInit=False | commonly the main EXE (normal) or unlinked DLL |
| MappedPath empty for the image base | classic process hollowing |
| Path present but VAD is private | hollowed / overwritten image |

### 4. Process-list anomalies

```sh
# hidden processes: in the pool but unlinked from the active list
vol3 -f mem.raw -r csv windows.pslist > ps.csv
vol3 -f mem.raw -r csv windows.psscan > pss.csv
diff <(cut -d, -f3 ps.csv | sort -n) <(cut -d, -f3 pss.csv | sort -n)
# vol2's multi-source cross-check, still the best single view
vol.py -f mem.raw --profile=Win7SP1x64 psxview
# threads whose start address is outside any mapped module
vol.py -f mem.raw --profile=Win7SP1x64 threads -F OrphanThread
# handles that betray injection targets
vol3 -f mem.raw windows.handles --pid 1234 | grep -iE '(Process|Thread|Section)'
```

### 5. Kernel land

```sh
# module list walk vs pool scan: a gap means an unlinked (hidden) driver
vol3 -f mem.raw windows.modules > mods.txt
vol3 -f mem.raw windows.modscan > modscan.txt
# names in modscan but not modules
comm -13 <(awk '{print $3}' mods.txt | sort -u) <(awk '{print $3}' modscan.txt | sort -u)
# SSDT entries pointing outside ntoskrnl/win32k
vol3 -f mem.raw windows.ssdt | grep -v -E 'ntoskrnl|win32k'
# process/thread/image-load notification routines registered by drivers
vol3 -f mem.raw windows.callbacks
# driver objects and their IRP major function tables
vol3 -f mem.raw windows.driverscan
vol3 -f mem.raw windows.driverirp
# dump a suspicious driver for static analysis
vol3 -f mem.raw -o ./drv windows.modules --dump
```

### 6. YARA over memory

```sh
# scan every process VAD with an inline rule
vol3 -f mem.raw windows.vadyarascan --yara-rules 'This program cannot be run in DOS mode'
# scan the whole physical address space with a rule file
vol3 -f mem.raw yarascan.YaraScan --yara-file ./inject.yar
# vol2 forms
vol.py -f mem.raw --profile=Win7SP1x64 yarascan -Y 'flag{'
vol.py -f mem.raw --profile=Win7SP1x64 yarascan -y ./inject.yar -p 1234
```

```yara
rule injected_shellcode_prologues
{
    meta:
        description = "Common shellcode stubs found in RWX private memory"
        author = "ctf-brain"
    strings:
        $msf_x64   = { fc 48 83 e4 f0 e8 }          // metasploit/CS x64 stager
        $msf_x86   = { fc e8 8? 00 00 00 60 }       // metasploit x86 block_api
        $callpop   = { e8 00 00 00 00 5? }          // get-EIP
        $peb_x86   = { 64 a1 30 00 00 00 }          // mov eax, fs:[0x30]
        $peb_x64   = { 65 48 8b 04 25 60 00 00 00 } // mov rax, gs:[0x60]
        $mz        = "MZ"
        $dos       = "This program cannot be run in DOS mode"
        $reflect   = "ReflectiveLoader" ascii wide
    condition:
        any of ($msf_x64, $msf_x86, $callpop, $peb_x86, $peb_x64, $reflect)
        or ($mz at 0 and $dos)
}
```

## Code

```python
#!/usr/bin/env python3
"""Score processes in a memory image for injection/anomaly indicators.

Feeds on volatility3 JSON output. Either point it at an image and let it call vol3,
or hand it pre-rendered JSON files.

    python3 procscore.py --image mem.raw
    python3 procscore.py --pslist ps.json --psscan pss.json --malfind mal.json \\
                         --cmdline cmd.json --netscan net.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from typing import Any

EXPECTED_PARENT = {
    "smss.exe": {"System"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "spoolsv.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe", "winlogon.exe"},
    "runtimebroker.exe": {"svchost.exe"},
}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
          "visio.exe", "acrord32.exe", "acrobat.exe"}
LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
           "msbuild.exe", "installutil.exe", "wmic.exe", "curl.exe"}
SINGLETONS = {"lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe"}
LOOKALIKES = {
    "scvhost.exe": "svchost.exe", "svch0st.exe": "svchost.exe", "svchost32.exe": "svchost.exe",
    "lsasss.exe": "lsass.exe", "lsas.exe": "lsass.exe", "1sass.exe": "lsass.exe",
    "csrsss.exe": "csrss.exe", "explore.exe": "explorer.exe", "expIorer.exe": "explorer.exe",
    "winlogin.exe": "winlogon.exe", "rundl132.exe": "rundll32.exe",
}


def vol_json(vol: str, image: str, plugin: str) -> list[dict[str, Any]]:
    cmd = [vol, "-q", "-r", "json", "-f", image, plugin]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)
        if p.returncode != 0:
            return []
        data = json.loads(p.stdout or "[]")
        return data if isinstance(data, list) else []
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def load(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else []


def col(row: dict[str, Any], *names: str, default: Any = "") -> Any:
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    return default


def score(pslist, psscan, malfind, cmdline, netscan) -> dict[int, dict[str, Any]]:
    procs: dict[int, dict[str, Any]] = {}
    for r in pslist:
        pid = int(col(r, "PID", default=0) or 0)
        procs[pid] = {
            "pid": pid,
            "ppid": int(col(r, "PPID", default=0) or 0),
            "name": str(col(r, "ImageFileName", "Name")),
            "score": 0,
            "why": [],
            "hidden": False,
        }
    names_by_pid = {p: d["name"] for p, d in procs.items()}

    live = set(procs)
    for r in psscan:
        pid = int(col(r, "PID", default=0) or 0)
        if pid and pid not in live:
            procs[pid] = {"pid": pid, "ppid": int(col(r, "PPID", default=0) or 0),
                          "name": str(col(r, "ImageFileName", "Name")),
                          "score": 40, "why": ["not in pslist (unlinked or exited)"],
                          "hidden": True}

    counts: dict[str, int] = {}
    for d in procs.values():
        counts[d["name"].lower()] = counts.get(d["name"].lower(), 0) + 1

    for d in procs.values():
        name = d["name"].lower()
        parent = names_by_pid.get(d["ppid"], "").lower()
        expected = {e.lower() for e in EXPECTED_PARENT.get(name, set())}
        if expected and parent and parent not in expected:
            d["score"] += 30
            d["why"].append(f"parent is {parent}, expected {'/'.join(sorted(expected))}")
        if parent in OFFICE and name in LOLBINS:
            d["score"] += 35
            d["why"].append(f"{parent} spawned {name}")
        if name in SINGLETONS and counts.get(name, 0) > 1:
            d["score"] += 25
            d["why"].append(f"{counts[name]} instances of a singleton process")
        if name in LOOKALIKES:
            d["score"] += 45
            d["why"].append(f"lookalike of {LOOKALIKES[name]}")

    for r in malfind:
        pid = int(col(r, "PID", default=0) or 0)
        if pid in procs:
            procs[pid]["score"] += 20
            prot = str(col(r, "Protection", default="?"))
            procs[pid]["why"].append(f"malfind hit ({prot})")

    for r in cmdline:
        pid = int(col(r, "PID", default=0) or 0)
        line = str(col(r, "Args", "CmdLine", default="")).lower()
        if pid not in procs or not line:
            continue
        for needle, pts, msg in (
            ("-enc", 30, "encoded powershell"),
            ("frombase64string", 30, "base64 decode in command line"),
            ("downloadstring", 30, "in-memory download"),
            ("\\temp\\", 20, "runs from Temp"),
            ("\\appdata\\", 20, "runs from AppData"),
            ("-w hidden", 15, "hidden window"),
            ("-nop", 10, "-NoProfile"),
            ("iex", 20, "Invoke-Expression"),
        ):
            if needle in line:
                procs[pid]["score"] += pts
                procs[pid]["why"].append(msg)

    for r in netscan:
        pid_raw = col(r, "PID", default=0)
        try:
            pid = int(pid_raw)
        except (TypeError, ValueError):
            continue
        fa = str(col(r, "ForeignAddr", "Foreign Addr", default=""))
        if pid in procs and fa and not fa.startswith(("127.", "10.", "192.168.", "0.0.0.0", "::", "-")):
            nm = procs[pid]["name"].lower()
            if nm in {"notepad.exe", "calc.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"}:
                procs[pid]["score"] += 35
                procs[pid]["why"].append(f"{nm} talking to {fa}")
    return procs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image")
    ap.add_argument("--vol", default=shutil.which("vol") or "vol")
    for name in ("pslist", "psscan", "malfind", "cmdline", "netscan"):
        ap.add_argument(f"--{name}")
    args = ap.parse_args()

    if args.image:
        pslist = vol_json(args.vol, args.image, "windows.pslist")
        psscan = vol_json(args.vol, args.image, "windows.psscan")
        malfind = vol_json(args.vol, args.image, "windows.malfind")
        cmdline = vol_json(args.vol, args.image, "windows.cmdline")
        netscan = vol_json(args.vol, args.image, "windows.netscan")
    else:
        pslist = load(args.pslist)
        psscan = load(args.psscan)
        malfind = load(args.malfind)
        cmdline = load(args.cmdline)
        netscan = load(args.netscan)

    if not pslist and not psscan:
        print("nothing to score: pass --image or at least --pslist/--psscan", file=sys.stderr)
        return 1

    procs = score(pslist, psscan, malfind, cmdline, netscan)
    ranked = sorted(procs.values(), key=lambda d: -d["score"])
    print(f"{'score':>5}  {'pid':>6}  {'ppid':>6}  name")
    for d in ranked:
        if d["score"] == 0:
            continue
        print(f"{d['score']:>5}  {d['pid']:>6}  {d['ppid']:>6}  {d['name']}")
        for w in dict.fromkeys(d["why"]):
            print(f"         - {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **malfind is noisy.** On a modern Win10/11 image expect 50+ hits. Filter by process first:
  anything that is not a browser, .NET app, or AV agent.
- **malfind is also blind** to injection into already-executable mapped regions (module stomping,
  DLL hollowing of a legitimate loaded DLL). Use `ldrmodules` plus a hash comparison against the
  on-disk file.
- **APC and thread-hijack injection** may leave no RWX VAD at all; look at `threads` for start
  addresses outside module ranges.
- A **single `svchost.exe` with no `-k` argument** is suspicious; real ones always have
  `-k netsvcs`/`-k LocalService` etc.
- `psscan` false positives are common on large images (pool memory reuse). A "hidden" PID with a
  nonsensical name and a zero CreateTime is usually garbage.
- Extracted VAD blobs are **not** loadable PEs: sections are already expanded to their virtual
  layout. Use `pe_unmapper`/`pe-sieve`-style fixups or analyse the blob raw.
- On kernel-side findings, remember signed legitimate drivers (AV, VPN, VM tools) also register
  callbacks and modify the SSDT on old systems.

## Tools

`volatility3` (`windows.malfind`, `windows.ldrmodules`, `windows.vadinfo`, `windows.vadyarascan`),
`volatility` 2 (`malfind`, `ldrmodules`, `hollowfind`, `apihooks`, `threads`, `psxview`),
`yara`, `capa`, `pe-sieve`/`hollows_hunter` (live systems), `radare2`, `objdump`, `strings`.

## References

- `vol3 -f img windows.malfind -h` and `windows.vadinfo -h` for the exact flag names in your build.
- The Volatility source under `volatility3/framework/plugins/windows/malfind.py` documents the
  exact VAD predicate used.
