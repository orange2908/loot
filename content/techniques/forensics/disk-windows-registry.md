---
title: "Windows Registry Forensics - Hives, Run Keys, USB, Shellbags, SRUM"
category: forensics
subcategory: registry
type: technique
tags: [registry, hive, ntuser-dat, usrclass-dat, sam, amcache, shimcache, shellbags, userassist, rot13, usbstor, mountpoints2, srum, recentdocs, runmru, regripper, reglookup, recmd, python-registry, dfir]
difficulty: medium
summary: "Where the hives live, how to replay their transaction logs, and the exact key paths for persistence, USB history, shellbags, UserAssist and SRUM."
when_to_use:
  - "You mounted a Windows image and need persistence, execution or USB evidence"
  - "The challenge gives you NTUSER.DAT, SYSTEM, SOFTWARE or UsrClass.dat as loose files"
  - "You must prove a folder existed or a USB device was plugged in"
  - "Event logs were cleared and you need a second source for user activity"
  - "You need local account hashes or the computer name / timezone / network profiles"
tools: [regripper, reglookup, recmd, python-registry, hivexsh, chntpw, samdump2, impacket, srum-dump]
related: [disk-image-triage, disk-ntfs-mft, disk-windows-execution-artifacts]
---

## TL;DR

Five system hives plus one or two per user. Grab them from the mounted image, replay the `.LOG1`/
`.LOG2` transaction logs so you are not reading a stale copy, then run RegRipper or RECmd over the
lot. For a 20-minute CTF: `rip.pl -r NTUSER.DAT -f ntuser` and `rip.pl -r SYSTEM -f system` dump
almost every artifact below in one shot. Run keys give persistence, UserAssist and ShimCache give
execution, USBSTOR+MountedDevices give devices, shellbags prove a folder was browsed.

## Recognise it

- `file NTUSER.DAT` says `MS Windows registry file, NT/2000 or above`; magic is `regf` at offset 0.
- Loose files named `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `NTUSER.DAT`,
  `UsrClass.dat`, `Amcache.hve` with no extension.
- Sibling `.LOG1` / `.LOG2` files, and `SOFTWARE{...guid}.TM.blf` / `.regtrans-ms` (TxR).
- A `SRUDB.dat` in `C:\Windows\System32\sru\` is an ESE database, not a hive.

## Where the hives live

| Hive | Path on disk | Mounts as |
| --- | --- | --- |
| `SYSTEM` | `C:\Windows\System32\config\SYSTEM` | `HKLM\SYSTEM` |
| `SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | `HKLM\SOFTWARE` |
| `SAM` | `C:\Windows\System32\config\SAM` | `HKLM\SAM` |
| `SECURITY` | `C:\Windows\System32\config\SECURITY` | `HKLM\SECURITY` |
| `DEFAULT` | `C:\Windows\System32\config\DEFAULT` | `HKU\.DEFAULT` |
| `NTUSER.DAT` | `C:\Users\<user>\NTUSER.DAT` | `HKCU` |
| `UsrClass.dat` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKCU\Software\Classes` |
| `Amcache.hve` | `C:\Windows\AppCompat\Programs\Amcache.hve` | not mounted |
| `BCD` | `\Boot\BCD` on the EFI/system partition | `HKLM\BCD00000000` |
| Backups | `C:\Windows\System32\config\RegBack\` (empty by default on Win10 1803+) | - |

```sh
# pull every hive off a mounted image in one go
mkdir -p hives && cd hives
cp /mnt/img/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT} .
cp /mnt/img/Windows/System32/config/*.LOG1 /mnt/img/Windows/System32/config/*.LOG2 .
cp /mnt/img/Windows/AppCompat/Programs/Amcache.hve .
cp /mnt/img/Users/bob/NTUSER.DAT ./NTUSER_bob.DAT
cp '/mnt/img/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat' ./UsrClass_bob.dat
# or straight out of the image without mounting: find the inode then icat
fls -o 2048 -r -p disk.dd | grep -i 'config/SYSTEM$'
icat -o 2048 disk.dd 34567 > SYSTEM
# confirm each one is really a hive
for f in *; do printf '%s ' "$f"; xxd -l 4 "$f" | awk '{print $2$3}'; done
```

### Replay the transaction logs

Windows writes changes to `.LOG1`/`.LOG2` first and lazily flushes them into the hive. A hive
copied from a live or hibernated system is often hours out of date, and the *newest* keys - the
ones the attacker just wrote - are only in the logs.

```sh
# Eric Zimmerman's replayer: -d for a whole directory of hives + logs
RLA.exe -d C:\hives --out C:\hives_clean
# single hive
RLA.exe -f C:\hives\SYSTEM --out C:\hives_clean
# yarp (python) ships a replay helper
python3 yarp-print --replay-log SYSTEM.LOG1 SYSTEM > /dev/null
# registry-explorer will offer to replay dirty hives interactively
# check dirtiness first: the primary sequence != secondary sequence in the regf header
xxd -s 4 -l 8 SYSTEM
```

## Tools

```sh
# RegRipper: plugin per artifact, the fastest path to an answer
rip.pl -r NTUSER.DAT -f ntuser > ntuser.txt
rip.pl -r SYSTEM -f system > system.txt
rip.pl -r SOFTWARE -f software > software.txt
rip.pl -r SAM -f sam > sam.txt
rip.pl -r Amcache.hve -p amcache > amcache.txt
# one specific plugin
rip.pl -r NTUSER.DAT -p userassist
rip.pl -r SYSTEM -p usbstor
rip.pl -r UsrClass.dat -p shellbags
# list every plugin available
rip.pl -l | less
# reglookup: grep-friendly flat dump of the whole hive
reglookup -H NTUSER.DAT | head
reglookup NTUSER.DAT | grep -i run
# only one subtree
reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' NTUSER.DAT
# timestamps of every key, sorted - a poor man's registry timeline
reglookup -t KEY NTUSER.DAT | sort -t, -k2
# RECmd with the Kroll batch file: hundreds of artifacts to CSV in one command
RECmd.exe -d C:\hives --bn BatchExamples\Kroll.reg --csv C:\out
RECmd.exe -f C:\hives\SYSTEM --sk USBSTOR --csv C:\out
# interactive shell (libhivex)
hivexsh NTUSER.DAT
# inside hivexsh:  cd Software\Microsoft\Windows\CurrentVersion\Run  /  ls  /  lsval
hivexget SYSTEM '\ControlSet001\Control\ComputerName\ComputerName' ComputerName
# chntpw: list local users straight out of SAM
chntpw -l SAM
# reged: export a subtree to a .reg text file
reged -x SOFTWARE HKEY_LOCAL_MACHINE\SOFTWARE '\Microsoft\Windows\CurrentVersion\Run' out.reg
# python-registry one-liner
python3 -c "from Registry import Registry; h=Registry.Registry('NTUSER.DAT'); print(h.root().timestamp())"
```

## Key artifacts (full paths)

### Persistence

```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon           -> Shell, Userinit, Taskman, Notify
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>  -> Debugger, GlobalFlag
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows            -> AppInit_DLLs, LoadAppInit_DLLs
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32
SYSTEM\CurrentControlSet\Services\<name>                        -> ImagePath, Start, ServiceDll
SYSTEM\CurrentControlSet\Services\<name>\Parameters             -> ServiceDll for svchost services
SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\<name>
SOFTWARE\Classes\<ext>\shell\open\command                       -> file-association hijack
SOFTWARE\Microsoft\Command Processor                            -> AutoRun
NTUSER.DAT\Environment                                          -> UserInitMprLogonScript
SOFTWARE\Microsoft\Active Setup\Installed Components\<guid>      -> StubPath
```

Winlogon defaults are `Shell = explorer.exe` and `Userinit = C:\Windows\system32\userinit.exe,`
(trailing comma is normal). Anything appended after a comma runs at logon. IFEO `Debugger` makes
Windows launch the debugger instead of the target - the sticky-keys trick is
`Image File Execution Options\sethc.exe\Debugger = C:\Windows\System32\cmd.exe`.

```
SYSTEM\Select   -> Current, Default, Failed, LastKnownGood
```

`Select\Current` (a DWORD, usually 1) tells you whether `ControlSet001` or `ControlSet002` is the
live `CurrentControlSet`. Offline tools do not resolve `CurrentControlSet` for you - read `Select`
first, then use the matching `ControlSet00N`.

### USB and removable media

```
SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\<serial>
        -> FriendlyName, ContainerID, and Properties\{83da6326-...}\0064/0065/0066
           (first connect, last connect, last removal timestamps)
SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_yyyy\<serial>
SYSTEM\MountedDevices
        -> \DosDevices\E:  and  \??\Volume{GUID}  -> binary blob containing the serial
SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_...
SOFTWARE\Microsoft\Windows Portable Devices\Devices\<device>   -> FriendlyName = volume label
SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt           -> ReadyBoost, volume serial + label
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{GUID}
        -> which USER mounted the volume (the key's LastWrite is the mount time)
```

A serial ending in `&0` means the device reports a real serial number; a second character other
than `&` in position 2 means Windows generated one (the device has no unique serial).

```sh
# the non-registry corroboration: setupapi logs every first-ever device install with a timestamp
grep -i -A3 'Device Install (Hardware initiated)' /mnt/img/Windows/INF/setupapi.dev.log | head -50
# older systems
less /mnt/img/Windows/setupapi.log
# RegRipper does the whole USB story in three plugins
rip.pl -r SYSTEM -p usbstor; rip.pl -r SYSTEM -p mounteddevices; rip.pl -r NTUSER.DAT -p mp2
```

### Execution evidence

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
        -> value NAMES are ROT13-encoded paths; the DATA holds run count + focus time
SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache   -> ShimCache
Amcache.hve\Root\InventoryApplicationFile   -> FileId (SHA1), LowerCaseLongPath, LinkDate, Size
Amcache.hve\Root\InventoryApplication        -> installed programs
Amcache.hve\Root\InventoryDriverBinary       -> drivers incl. unsigned ones
SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>   -> BAM, last exec time per exe
SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>   -> DAM (desktop activity moderator)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
```

The two UserAssist GUIDs that matter:
`{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` = executable file execution,
`{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` = shortcut (.lnk) execution.
Win7+ `Count` value data is 72 bytes: session id (0), **run count at offset 4**, **focus count at
8**, **focus time in ms at 12**, and a **FILETIME at offset 60**. XP-era data was 16 bytes with the
run count at offset 4 biased by 5.

`Amcache` `FileId` is the SHA1 of the first 31,457,280 bytes of the file, prefixed with four zeros.
Strip the leading `0000` to get a hash you can look up.

### Files and folders the user touched

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.<ext>
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery   -> Start-menu searches
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\<ext>
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers    -> outbound RDP targets
NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default    -> MRU0..MRUn
```

`RunMRU` values are `a`, `b`, `c`... with a `MRUList` string giving the order; each value is the
typed text plus `\1`. `WordWheelQuery` values are UTF-16LE with a `MRUListEx` DWORD array.

### Shellbags

Shellbags record the view settings of every folder the user opened in Explorer - and therefore
prove the folder existed and was browsed, even if the folder and its contents are long gone
(removable drives, network shares, deleted directories, zip archives opened in Explorer).

```
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU     -> the folder tree
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\Bags       -> the view settings
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU                      -> older/desktop entries
NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam\BagMRU                -> XP era
```

Each `BagMRU` subkey is a numbered node holding a binary **shell item ID list** (the same structure
found inside LNK files) with embedded DOS 8.3 names and FAT-style MAC timestamps.

```sh
# the standard parsers
SBECmd.exe -d C:\hives --csv C:\out
rip.pl -r UsrClass.dat -p shellbags
python3 shellbags.py UsrClass.dat
```

### SRUM (System Resource Usage Monitor)

SRUM records per-process network bytes sent/received, CPU time and energy use, in hourly buckets,
for roughly 30-60 days. It is the best "how much data did they exfiltrate" source on Windows.

```
C:\Windows\System32\sru\SRUDB.dat            <- the ESE database (the actual data)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{GUID}   <- table-to-provider map
   {973F5D5C-1D90-4944-BE8E-24B94231A174}  Network Data Usage
   {DD6636C4-8929-4683-974E-22C046A43763}  Network Connectivity Usage
   {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  Application Resource Usage
   {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}  Energy Usage
```

```sh
# srum_dump needs both the ESE db and SOFTWARE (for the SID/interface lookups)
python3 srum_dump2.py -i SRUDB.dat -r SRUM_TEMPLATE2.xlsx -o srum.xlsx
srum_dump.exe -i SRUDB.dat -t SRUM_TEMPLATE2.xlsx -o srum.xlsx
# Eric Zimmerman's version, CSV out, no Excel needed
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat -r C:\Windows\System32\config\SOFTWARE --csv C:\out
# the db is usually dirty; repair it first if the parser refuses
esentutl.exe /p SRUDB.dat
# linux: libesedb
esedbexport -t srum SRUDB.dat
```

### System identity

```
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName          -> hostname
SYSTEM\CurrentControlSet\Control\TimeZoneInformation                -> Bias, TimeZoneKeyName, DST
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID} -> IP, DHCP server, lease times
SOFTWARE\Microsoft\Windows NT\CurrentVersion                        -> ProductName, CurrentBuild,
                                                                       InstallDate (unix epoch),
                                                                       RegisteredOwner
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}
        -> ProfileName (SSID), DateCreated, DateLastConnected (128-bit SYSTEMTIME, not FILETIME)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\<hash>
        -> the gateway MAC address of that network
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>      -> ProfileImagePath (user -> SID)
SYSTEM\CurrentControlSet\Control\Windows                            -> ShutdownTime (FILETIME)
SYSTEM\CurrentControlSet\Control\CrashControl
```

`TimeZoneInformation\Bias` is minutes **west** of UTC: UTC = local + Bias. Get this before you
build any timeline, because Explorer-derived artifacts are local-time.

### SAM, users and hashes

```
SAM\SAM\Domains\Account\Users\<RID hex>        -> V (username, comment, hash blobs), F (logon data)
SAM\SAM\Domains\Account\Users\Names\<username> -> the key's default value TYPE is the RID
SAM\SAM\Domains\Account\F                      -> domain-wide policy
SECURITY\Policy\Secrets                        -> LSA secrets (service account passwords, DPAPI)
SECURITY\Cache                                 -> domain cached credentials (mscash2)
SYSTEM\CurrentControlSet\Control\Lsa\JD,Skew1,GBG,Data  -> the four parts of the bootkey/syskey
```

Well-known RIDs: 500 Administrator, 501 Guest, 503 DefaultAccount, 504 WDAGUtilityAccount,
501+ local accounts start at **1000**.

```sh
# classic: needs SYSTEM for the bootkey to decrypt SAM
samdump2 SYSTEM SAM
# the modern one - also does LSA secrets and cached domain creds
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# just the user list and last-logon times, no cracking
rip.pl -r SAM -p samparse
chntpw -l SAM
# crack the NT hashes offline
hashcat -m 1000 nt_hashes.txt rockyou.txt
john --format=nt nt_hashes.txt --wordlist=rockyou.txt
```

## Code

```python
#!/usr/bin/env python3
"""reg_triage.py - dump Run keys, UserAssist and USBSTOR serials from a hive.

Requires python-registry for the hive walk:
    pip install python-registry

The ROT13 and FILETIME helpers below are stdlib-only and are exercised by the
self-test in __main__, so `python3 reg_triage.py --selftest` runs with no
dependencies at all.

Usage:
    python3 reg_triage.py <hive> [<hive> ...]
    python3 reg_triage.py --selftest

It auto-detects what each hive is (NTUSER.DAT / SYSTEM / SOFTWARE) and runs the
applicable extractors.
"""
from __future__ import annotations

import binascii
import codecs
import datetime as dt
import struct
import sys

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "shortcut",
}

RUN_PATHS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon",
]

USBSTOR_PATHS = [
    r"ControlSet001\Enum\USBSTOR",
    r"ControlSet002\Enum\USBSTOR",
    r"CurrentControlSet\Enum\USBSTOR",
]


# ---------------------------------------------------------------- stdlib helpers

def rot13(text: str) -> str:
    """UserAssist value names are ROT13'd. Letters only; digits/punctuation pass through."""
    return codecs.decode(text, "rot_13")


def filetime_to_dt(raw: int) -> dt.datetime | None:
    """100-ns ticks since 1601-01-01 UTC -> aware datetime, or None if implausible."""
    if raw <= 0 or raw > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def parse_userassist_value(data: bytes) -> dict:
    """Decode the binary blob behind a UserAssist Count value.

    Win7+ layout is 72 bytes: session(0) runcount(4) focuscount(8) focustime_ms(12)
    ... last-executed FILETIME at offset 60. XP layout is 16 bytes with the run
    count at offset 4 and a +5 bias.
    """
    out: dict = {"raw_len": len(data)}
    if len(data) >= 68:
        session, run_count, focus_count, focus_ms = struct.unpack_from("<IIII", data, 0)
        (ft,) = struct.unpack_from("<Q", data, 60)
        out.update({
            "layout": "win7+",
            "session": session,
            "run_count": run_count,
            "focus_count": focus_count,
            "focus_seconds": round(focus_ms / 1000.0, 2),
            "last_run": filetime_to_dt(ft),
        })
    elif len(data) >= 16:
        session, run_count = struct.unpack_from("<II", data, 0)
        (ft,) = struct.unpack_from("<Q", data, 8)
        out.update({
            "layout": "winxp",
            "session": session,
            "run_count": max(run_count - 5, 0),
            "focus_count": None,
            "focus_seconds": None,
            "last_run": filetime_to_dt(ft),
        })
    else:
        out["layout"] = "unknown"
    return out


def usbstor_serial(key_name: str) -> tuple[str, bool]:
    """Split a USBSTOR instance id and say whether the serial is device-supplied.

    A '&' as the second character of the instance id means Windows generated the
    serial because the device did not supply one.
    """
    serial = key_name
    device_supplied = not (len(serial) > 1 and serial[1] == "&")
    return serial, device_supplied


# ---------------------------------------------------------------- hive walking

def _load_registry():
    try:
        from Registry import Registry  # type: ignore
    except ImportError:
        print(
            "[!] python-registry is not installed.\n"
            "    pip install python-registry\n"
            "    (the ROT13/FILETIME helpers still work: run with --selftest)",
            file=sys.stderr,
        )
        return None
    return Registry


def open_key(hive, path: str):
    try:
        return hive.open(path)
    except Exception:
        return None


def dump_run_keys(hive, label: str) -> None:
    print(f"\n== Run / autostart keys ({label}) ==")
    found = False
    for path in RUN_PATHS:
        key = open_key(hive, path)
        if key is None:
            continue
        ts = key.timestamp()
        for value in key.values():
            name = value.name() or "(Default)"
            try:
                data = value.value()
            except Exception:
                data = "<unreadable>"
            if path.endswith("Winlogon") and name not in ("Shell", "Userinit", "Taskman", "Notify"):
                continue
            found = True
            print(f"  [{ts}] {path}\\{name} = {data}")
    if not found:
        print("  (none)")


def dump_userassist(hive) -> None:
    print("\n== UserAssist ==")
    base = open_key(hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    if base is None:
        print("  (no UserAssist key - not an NTUSER.DAT?)")
        return
    rows = []
    for guid_key in base.subkeys():
        kind = USERASSIST_GUIDS.get(guid_key.name().upper(), "other")
        count = None
        for sub in guid_key.subkeys():
            if sub.name().lower() == "count":
                count = sub
        if count is None:
            continue
        for value in count.values():
            name = rot13(value.name())
            try:
                data = value.value()
            except Exception:
                continue
            if not isinstance(data, bytes):
                continue
            info = parse_userassist_value(data)
            rows.append((info.get("last_run"), kind, name, info))
    rows.sort(key=lambda r: (r[0] is None, r[0]))
    for last_run, kind, name, info in rows:
        when = last_run.strftime("%Y-%m-%d %H:%M:%S") if last_run else "-"
        print(f"  {when}  runs={info.get('run_count', 0):<5} "
              f"focus={info.get('focus_seconds') or 0:<8} [{kind}] {name}")
    if not rows:
        print("  (empty)")


def dump_usbstor(hive) -> None:
    print("\n== USBSTOR devices ==")
    any_found = False
    for path in USBSTOR_PATHS:
        base = open_key(hive, path)
        if base is None:
            continue
        for dev in base.subkeys():
            for inst in dev.subkeys():
                any_found = True
                serial, real = usbstor_serial(inst.name())
                friendly = ""
                for v in inst.values():
                    if v.name() == "FriendlyName":
                        friendly = str(v.value())
                print(f"  {dev.name()}")
                print(f"      serial={serial}  device_supplied={real}")
                print(f"      friendly={friendly}")
                print(f"      key_last_write={inst.timestamp()}")
    if not any_found:
        print("  (no USBSTOR key - not a SYSTEM hive?)")


def triage(path: str) -> None:
    Registry = _load_registry()
    if Registry is None:
        return
    try:
        hive = Registry.Registry(path)
    except Exception as exc:
        print(f"[!] cannot open {path}: {exc}", file=sys.stderr)
        return
    names = {k.name().upper() for k in hive.root().subkeys()}
    print(f"\n######## {path}  (root subkeys: {', '.join(sorted(names))})")
    if "SOFTWARE" in names or "SELECT" in names or "CONTROLSET001" in names:
        dump_usbstor(hive)
        dump_run_keys(hive, "system/software")
    else:
        dump_run_keys(hive, "user")
        dump_userassist(hive)


def selftest() -> int:
    assert rot13("Microsoft.Windows.Shell") == "Zvpebfbsg.Jvaqbjf.Furyy"
    assert rot13(rot13("C:\\Windows\\System32\\cmd.exe")) == "C:\\Windows\\System32\\cmd.exe"
    known = 0x01D5B1A4A9F0C000
    got = filetime_to_dt(known)
    assert got is not None and got.year == 2019, got
    assert filetime_to_dt(0) is None
    blob = (struct.pack("<IIII", 0, 7, 9, 12000) + b"\x00" * 44
            + struct.pack("<Q", known) + b"\x00" * 4)
    assert len(blob) == 72, len(blob)
    info = parse_userassist_value(blob)
    assert info["layout"] == "win7+", info
    assert info["run_count"] == 7 and info["focus_count"] == 9, info
    assert abs(info["focus_seconds"] - 12.0) < 1e-6, info
    assert info["last_run"] is not None and info["last_run"].year == 2019
    assert usbstor_serial("0123456789ABCDEF&0") == ("0123456789ABCDEF&0", True)
    assert usbstor_serial("7&1234abcd&0") == ("7&1234abcd&0", False)
    assert binascii.hexlify(b"\x01").decode() == "01"
    print("selftest OK")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] == "--selftest":
        return selftest()
    for path in args:
        triage(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Read `Select\Current` first.** `CurrentControlSet` does not exist in an offline hive; it is a
  symlink the running kernel creates. Use `ControlSet001` or `ControlSet002` accordingly.
- **Key LastWrite times, not value times.** The registry timestamps *keys*. A Run value's write
  time is the parent key's LastWrite, so two values written a week apart share one timestamp.
- **Replay the logs.** An unreplayed hive can be missing the exact key the challenge wants.
- **`NTUSER.DAT` from a logged-on user is locked** on a live system; on an image it is fine, but
  it may be dirty. `RegBack` copies are stale (and empty on Win10 1803+ unless re-enabled).
- **UserAssist proves GUI launches only.** Something run from a command line never appears there.
- **ShimCache/AppCompatCache** presence is not execution on Win8+ - see the execution-artifacts
  file. Amcache is a better execution/existence source and carries a SHA1.
- **Shellbags prove browsing, not content.** They also record folders inside zip files and on
  network shares, which is what makes them valuable.
- **`NetworkList` `DateCreated`/`DateLastConnected` are 128-bit SYSTEMTIME**
  (year, month, dayofweek, day, hour, minute, second, ms - eight little-endian `uint16`), not
  FILETIME. Decoding them as FILETIME gives nonsense dates.
- **`InstallDate` under `CurrentVersion`** is a 32-bit Unix epoch; `InstallTime` next to it is a
  64-bit FILETIME. Two different encodings in the same key.
- **`strings -el` the hive** when a parser fails: hives store names as ASCII or UTF-16LE and a
  quick `strings -a -el SOFTWARE | grep -i flag` has solved plenty of challenges.
- **`SECURITY\Policy\Secrets`** needs the bootkey from SYSTEM. `secretsdump ... LOCAL` does it.
- **Deleted registry keys** live in hive slack. `yarp` + `registry-recover`, RegRipper's
  `del` plugins, and `bulk_extractor` recover them.

## Tools

`RegRipper` (`rip.pl` / `rip.exe`), `RECmd` + `Registry Explorer` + `RLA` + `SBECmd`
(Eric Zimmerman), `reglookup`, `python-registry`, `yarp`, `regipy`, `libhivex`
(`hivexsh`, `hivexget`, `hivexregedit`), `chntpw`, `reged`, `samdump2`, `impacket-secretsdump`,
`srum_dump` / `SrumECmd`, `libesedb` (`esedbexport`), `AmcacheParser`, `AppCompatCacheParser`,
`plaso` (`winreg` parsers), `Autopsy` registry module.

## References

- RegRipper plugin sources double as the documentation for each key's binary layout.
- Microsoft documents `SYSTEMTIME`, `FILETIME` and the `USBSTOR` device property GUIDs used above.
- `rip.pl -l` and `RECmd.exe --help` enumerate what your build actually supports.
