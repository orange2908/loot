---
title: "Windows Artifacts Reference - Path, Proof, Parser"
category: forensics
subcategory: windows-artifacts
type: reference
tags: [windows-artifacts, registry, prefetch, evtx, srum, amcache, shellbags, lnk, jumplists, usnjrnl, mft, browser-history, userassist, shimcache, bam, recycle-bin, eric-zimmerman, regripper, dfir]
summary: "Every Windows forensic artifact: exact path or registry key, what it proves and what it does not, plus the parser command line."
tools: [MFTECmd, PECmd, LECmd, JLECmd, AmcacheParser, SrumECmd, RECmd, SBECmd, EvtxECmd, regripper, chainsaw, hayabusa, plaso, kape]
related: [forensics-triage-cheatsheet, file-magic-bytes, disk-forensics-cheatsheet, volatility-cheatsheet]
---

Column meaning: **Proves** = the strongest claim the artifact alone supports.
**Does NOT prove** = the wrong conclusion people reach from it in CTF writeups.
Paths are relative to the volume root (`C:\`) unless stated. `%U%` = a user profile.

## Registry hives on disk

| Hive | Path | Proves | Does NOT prove | Parser |
|---|---|---|---|---|
| SYSTEM | `\Windows\System32\config\SYSTEM` | Hardware, services, USB, timezone, ControlSet | Nothing about a specific user | `rip.pl -r SYSTEM -f system` |
| SOFTWARE | `\Windows\System32\config\SOFTWARE` | Installed apps, OS build, network profiles, machine-wide autoruns | Which user ran the app | `rip.pl -r SOFTWARE -f software` |
| SAM | `\Windows\System32\config\SAM` | Local accounts, RIDs, last logon, bad-password counts | Domain accounts | `rip.pl -r SAM -f sam` |
| SECURITY | `\Windows\System32\config\SECURITY` | LSA secrets, cached domain creds, audit policy | Plaintext passwords without SYSTEM bootkey | `secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL` |
| DEFAULT | `\Windows\System32\config\DEFAULT` | HKU\.DEFAULT, pre-logon/service context settings | Interactive user actions | `rip.pl -r DEFAULT -f default` |
| NTUSER.DAT | `\Users\%U%\NTUSER.DAT` | Per-user config, MRU, UserAssist, RunMRU, TypedPaths | Actions by other users or by SYSTEM | `rip.pl -r NTUSER.DAT -f ntuser` |
| UsrClass.dat | `\Users\%U%\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags (folder browsing), COM/shell classes | File content ever existed on this disk | `SBECmd.exe -d . --csv out` |
| Amcache.hve | `\Windows\AppCompat\Programs\Amcache.hve` | Binary present on disk, SHA1, PE metadata, install entries | Execution (it is a presence/inventory artifact) | `AmcacheParser.exe -f Amcache.hve --csv out` |
| Transaction logs | `<hive>.LOG1`, `<hive>.LOG2` | Recent writes not yet flushed into the hive | Anything if you ignore them - keys can be missing from the hive | `rla.exe -d . --out replayed` |

## Registry keys - persistence

| Key | Full path | Proves | Does NOT prove | Notes |
|---|---|---|---|---|
| Run | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `NTUSER.DAT\Software\...\Run` | Intent to start at logon | It ever started | Check key LastWrite time |
| RunOnce | `...\CurrentVersion\RunOnce` | One-shot startup intent | Persistence survived | Value deleted after firing |
| Winlogon Shell | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell replacement; default is `explorer.exe` | User awareness | Appended `,evil.exe` is the classic |
| Winlogon Userinit | `...\Winlogon\Userinit` | Logon hijack; default `C:\Windows\system32\userinit.exe,` | Which user triggered it | Trailing comma is normal |
| IFEO Debugger | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger` | Launch hijack of that exe (sticky-keys trick) | The target exe was modified | `GlobalFlag`+`SilentProcessExit` variant too |
| AppInit_DLLs | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | DLL injected into every user32-linked process | Loaded if `LoadAppInit_DLLs`=0 or Secure Boot on | Check both values |
| Services | `SYSTEM\CurrentControlSet\Services\<name>` | Service exists; `ImagePath`, `Start`, `ServiceDll` | Service ran successfully | `Start`=2 auto, 3 manual, 4 disabled |
| Scheduled task cache | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree|Tasks` | Task registered, GUID, hidden tasks | Task executed | Cross-check `\Windows\System32\Tasks\` |

## Registry keys - system identity and network

| Key | Full path | Proves | Does NOT prove |
|---|---|---|---|
| ControlSet select | `SYSTEM\Select\Current`, `\LastKnownGood` | Which `ControlSet00N` was live at acquisition | Which was live at incident time |
| ComputerName | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | Hostname | DNS/NetBIOS name used on the wire |
| TimeZoneInformation | `SYSTEM\ControlSet001\Control\TimeZoneInformation` | `Bias`, `DaylightBias`, `TimeZoneKeyName` for local-time conversion | Timestamps in artifacts are already local |
| NetworkList Profiles | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{guid}` | SSID/domain name, first+last connect (local time, binary SYSTEMTIME) | Traffic content |
| SysinternalsEulaAccepted | `NTUSER.DAT\Software\Sysinternals\<Tool>\EulaAccepted` | That user accepted the EULA -> tool was run interactively | Which binary path or when it last ran |
| Terminal Server Client | `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<host>` | Outbound RDP target and `UsernameHint` | The connection succeeded |

## Registry keys - USB and removable media

| Key | Full path | Proves |
|---|---|---|
| USBSTOR | `SYSTEM\ControlSet001\Enum\USBSTOR\<Ven_Prod_Rev>\<serial>` | Device class, vendor, product, serial (2nd char `&` = no unique serial) |
| USB | `SYSTEM\ControlSet001\Enum\USB\VID_xxxx&PID_xxxx\<serial>` | VID/PID; `Properties\{83da6326-...}\0064|0066|0067` = first install, last connect, last removal |
| MountedDevices | `SYSTEM\MountedDevices` | Drive letter <-> disk signature / volume GUID mapping at last mount |
| MountPoints2 | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{guid}` | THIS user mounted that volume (the user-attribution link) |
| Portable Devices | `SOFTWARE\Microsoft\Windows Portable Devices\Devices\*` | Volume label + drive letter for MTP/USB devices |
| setupapi | `\Windows\INF\setupapi.dev.log` (file, not registry) | First-ever device install timestamp in local time |

## Registry keys - execution evidence

| Artifact | Full path | Proves | Does NOT prove |
|---|---|---|---|
| ShimCache / AppCompatCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` | Full path + `$STANDARD_INFORMATION` modified time; the file EXISTED and was seen by the shim engine | Execution. On Win8+ the "executed" flag is gone. Order = LRU, newest first |
| BAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Last execution time (FILETIME) of that path BY THAT SID | Duration or count. Rolls over ~7 days |
| DAM | `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>` | Same as BAM for Desktop Activity Moderator | Same limits |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count` | GUI-launched program, run count, focus time, last run; ROT13 value names | Command-line launches (cmd/script) |
| Amcache InventoryApplicationFile | `Amcache.hve\Root\InventoryApplicationFile` | SHA1 (skip first 4 chars of the 44-char value), path, publisher, link date | Execution |
| RunMRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | What was typed into Win+R, in `MRUList` order | It launched |

## Registry keys - user activity and MRU

| Artifact | Full path | Proves |
|---|---|---|
| RecentDocs | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.<ext>` | File opened via shell, per extension, MRU ordered |
| TypedPaths | `...\Explorer\TypedPaths` | Path typed into the Explorer address bar (url1..url25) |
| TypedURLs | `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs` | URL typed into IE/Edge Legacy; `TypedURLsTime` has FILETIMEs |
| WordWheelQuery | `...\Explorer\WordWheelQuery` | Terms typed into Explorer search box (UTF-16LE), MRU ordered |
| OpenSavePidlMRU | `...\Explorer\ComDlg32\OpenSavePidlMRU\<ext>` | Files opened/saved through the common dialog, as shell item IDs |
| LastVisitedPidlMRU | `...\Explorer\ComDlg32\LastVisitedPidlMRU` | Which executable used the dialog and the directory it landed in |
| Shellbags | `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` + `Bags`; also `NTUSER.DAT\...\Shell\BagMRU` | A folder was BROWSED in Explorer, its view settings and MRU position; survives folder deletion; covers removable and network paths |
| Office MRU | `NTUSER.DAT\Software\Microsoft\Office\<ver>\<App>\File MRU` | Document opened in Office; value has `[F00000000][T01D...][O00000000]*path` with a FILETIME in hex |
| Office Trusted Documents | `NTUSER.DAT\Software\Microsoft\Office\<ver>\<App>\Security\Trusted Documents\TrustRecords` | User clicked "Enable Content" (macro enabled) - last DWORD `0xFFFFFFFF` |
| Office User MRU | `...\Office\<ver>\Common\Identity` / `...\User MRU\LiveId_*\File MRU` | Cloud-account-scoped recent files |

## Filesystem artifacts

| Artifact | Path | Proves | Does NOT prove |
|---|---|---|---|
| `$MFT` | `\$MFT` (root, hidden) | Every file record: name, size, `$SI` and `$FN` MACB, resident data <~700 bytes, ADS, deleted-but-unallocated entries | File content if non-resident and clusters overwritten |
| `$LogFile` | `\$LogFile` | NTFS transactions for the last minutes-hours: renames, creates, deletes | Long-term history (it wraps fast) |
| `$UsnJrnl:$J` | `\$Extend\$UsnJrnl` ADS `$J` | Per-file change reasons (`FILE_CREATE`, `RENAME_OLD_NAME`, `FILE_DELETE`, `DATA_OVERWRITE`) with USN + timestamp | Who did it |
| Recycle Bin (Vista+) | `\$Recycle.Bin\<SID>\$I<6chars>` and `$R<6chars>` | `$I` = original path + size + deletion FILETIME; `$R` = the content | Deletion by that SID if Bin was moved |
| Recycler (XP) | `\RECYCLER\<SID>\INFO2` + `Dc<n>.<ext>` | Same, INFO2 is one 800-byte record per file | - |
| Prefetch | `\Windows\Prefetch\<NAME>-<HASH>.pf` | EXECUTION: up to 8 run times (Win8+; 1 on Win7), run count, loaded file+dir list, volume serial | The user who ran it. Absent if SSD-disabled or `EnablePrefetcher`=0 |
| SRUM | `\Windows\System32\sru\SRUDB.dat` (+ `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`) | Per-app bytes sent/received per interface, CPU time, SID, hourly buckets, ~30-60 days | Second-level precision (hourly rollup) |
| Amcache | `\Windows\AppCompat\Programs\Amcache.hve` | See registry table | Execution |
| LNK (Recent) | `\Users\%U%\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` | Target path, target MACB, target size, volume serial, drive type, MAC address (pre-Vista), machine ID | That the target still exists |
| LNK (Office/desktop) | `\Users\%U%\AppData\Roaming\Microsoft\Office\Recent\*.lnk` | Office-opened documents incl. removable paths | - |
| Jump Lists (auto) | `...\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` | OLE-CF container of LNK streams + DestList MRU: app + file + access count + times | Manual pinning |
| Jump Lists (custom) | `...\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms` | Pinned/app-declared items, concatenated LNKs | Access times |
| Timeline | `\Users\%U%\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` | SQLite: app + document + start/end times + focus duration; `Activity` and `Activity_PackageId` tables | Win10 1803-2004 mainly; may be off |
| WebCacheV01.dat | `\Users\%U%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` | ESE DB: IE/Edge-Legacy history, cookies, cache, and Explorer/Office download records | Chrome/Firefox activity |
| Thumbs.db | `<folder>\Thumbs.db` (XP-era, per folder) | A picture with that name existed in that folder | The file is still there |
| thumbcache | `\Users\%U%\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db` | Thumbnail bitmaps + Windows Property Store ID; `thumbcache_idx.db` maps entries | Filename without the index or `Windows.edb` |
| IconCache.db | `\Users\%U%\AppData\Local\IconCache.db` | Icons of programs that were present | Execution |
| Windows.edb | `\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | Indexed file names, paths, and often full text/email bodies | Anything outside indexed locations |
| hiberfil.sys | `\hiberfil.sys` | Compressed RAM image at hibernation (Xpress Huffman) | RAM at acquisition time |
| pagefile.sys | `\pagefile.sys` | Paged-out memory fragments, strings, keys | Structure (no page tables) |
| swapfile.sys | `\swapfile.sys` | Suspended Modern/UWP app memory | Win32 process memory |
| Volume Shadow Copies | `\System Volume Information\{3808876b-c176-4e48-b7ae-04046e6cc752}` | Point-in-time older copies of every artifact above | That snapshots still mount cleanly |
| WMI repository | `\Windows\System32\wbem\Repository\OBJECTS.DATA` (+ `INDEX.BTR`, `MAPPING*.MAP`) | WMI event-consumer persistence (`__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`) | Execution without the WMI-Activity log |
| Scheduled Tasks | `\Windows\System32\Tasks\**` (XML, no extension) | Task XML: `<Command>`, `<Arguments>`, principal SID, triggers, author | Last run - that is in `Tasks\*.job` (XP) or the TaskScheduler log |
| Startup folders | `\Users\%U%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` and `\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` | Autostart intent | Execution |
| setupapi.dev.log | `\Windows\INF\setupapi.dev.log` | First install of a device, LOCAL time | Later connections |
| Outlook OST/PST | `\Users\%U%\AppData\Local\Microsoft\Outlook\*.ost|*.pst` | Mail, attachments, calendar, deleted-item recovery | Server-side mail not synced |
| PS console history | `\Users\%U%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commands TYPED into an interactive PowerShell, plaintext, no timestamps | Commands run via `-EncodedCommand` or non-interactive |
| BITS queue | `\ProgramData\Microsoft\Network\Downloader\qmgr.db` (Win10) / `qmgr*.dat` | Pending/complete BITS transfers and URLs | Completed-and-cleared jobs |
| Windows Defender | `\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log` | Scanned paths, detections, process names | Full command lines always |

## Event logs

Path: `\Windows\System32\winevt\Logs\<name>.evtx`

| Log | Key event IDs | Proves |
|---|---|---|
| `Security.evtx` | 4624 logon (type 2 console, 3 network, 10 RDP), 4625 fail, 4634/4647 logoff, 4648 explicit creds, 4672 admin logon, 4688 process create (+cmdline if audited), 4697 service install, 4720/4726 user add/del, 4732 group add, 4768/4769/4771 Kerberos, 5140/5145 share access, 1102 log cleared | Authentication and, if auditing was on, process creation |
| `System.evtx` | 7045 service installed, 7034/7036 service state, 6005/6006 boot/shutdown, 6013 uptime, 1074 planned shutdown, 104 log cleared, 219 driver load | Service and driver installs, uptime windows |
| `Application.evtx` | 1000/1001 app crash + WER, 11707/11724 MsiInstaller install/remove | Crashes and MSI installs |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | 1 process create (with hashes + parent), 3 network connect, 7 image load, 8 remote thread, 10 process access, 11 file create, 12/13/14 registry, 22 DNS query, 23 file delete archived | The richest execution + network evidence when Sysmon is installed |
| `Microsoft-Windows-PowerShell%4Operational.evtx` | 4103 module logging, 4104 script block logging (the deobfuscated script text), 40961/53504 host start | Actual PowerShell source executed |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 106 registered, 140 updated, 141 deleted, 200/201 action start/complete, 129 created process | Task registration AND execution |
| `...TerminalServices-LocalSessionManager%4Operational.evtx` | 21 logon, 22 shell start, 23 logoff, 24 disconnect, 25 reconnect | RDP session lifecycle with source IP and username |
| `...TerminalServices-RemoteConnectionManager%4Operational.evtx` | 1149 user authentication succeeded (source IP) | Inbound RDP reached auth |
| `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx` | 131 connection attempt, 98 transport connected | Source IP of RDP attempts |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | 1116 malware detected, 1117 action taken, 5001 realtime protection disabled, 5007 config changed | Detections and tampering |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` | 5857 provider loaded, 5858 query error (with client PID), 5860/5861 permanent consumer registered | WMI persistence and remote WMI use |
| `Microsoft-Windows-Bits-Client%4Operational.evtx` | 3 job created, 59 job started (URL), 60 job stopped, 4 job complete | Download via `bitsadmin`/BITS |

## Browser artifacts

| Browser | File | Key tables / content |
|---|---|---|
| Chrome/Edge (Chromium) | `\Users\%U%\AppData\Local\Google\Chrome\User Data\Default\History` | SQLite: `urls`, `visits` (visit_time WebKit epoch, `transition` low byte = link/typed/reload), `downloads`, `downloads_url_chains` |
| Chrome/Edge | `...\Default\Cookies` | `cookies` table; `encrypted_value` prefixed `v10`/`v11`, AES-GCM key in `Local State` DPAPI blob |
| Chrome/Edge | `...\Default\Login Data` | `logins` table: origin_url, username_value, DPAPI/AES-GCM `password_value` |
| Chrome/Edge | `...\Default\Web Data` | Autofill, credit cards, `keywords` (search engines) |
| Chrome/Edge | `...\Default\Top Sites`, `Favicons`, `Shortcuts`, `Network Action Predictor` | Frequented sites, favicon-to-URL map, omnibox typing history |
| Chrome/Edge | `...\Default\Sessions\Session_*`, `Tabs_*` | Open tabs and back/forward stacks at last run (SNSS format) |
| Chrome/Edge | `...\Default\Preferences`, `Local State`, `Bookmarks` (JSON) | Profile config, extensions list, DPAPI-wrapped key |
| Chrome/Edge | `...\Default\Local Storage\leveldb\*.ldb|*.log`, `IndexedDB\*` | Site-local data, tokens, chat drafts |
| Edge extras | `\Users\%U%\AppData\Local\Microsoft\Edge\User Data\Default\` | Same layout as Chrome |
| Firefox | `\Users\%U%\AppData\Roaming\Mozilla\Firefox\Profiles\<rand>.default*\places.sqlite` | `moz_places`, `moz_historyvisits` (microseconds UNIX), `moz_bookmarks`, `moz_annos` (downloads) |
| Firefox | `...\cookies.sqlite`, `formhistory.sqlite`, `permissions.sqlite` | Cookies (plaintext), typed form values, per-site permissions |
| Firefox | `...\key4.db` + `logins.json` | NSS master key + encrypted saved logins (crack with `firepwd`/`firefox_decrypt`) |
| Firefox | `...\sessionstore.jsonlz4`, `recovery.jsonlz4` | Open tabs; mozlz4 = `mozLz40\0` + LZ4 block |
| Firefox | `...\cache2\entries\*` | Cached response bodies + original URL in the trailer |
| IE / Edge Legacy | `\Users\%U%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` | ESE containers: History, Cookies, Content, DownloadHistory, iedownload |
| Any | `:Zone.Identifier` ADS on downloaded files | `ZoneId=3` + `HostUrl`/`ReferrerUrl` = exact download source |

## Parser command lines - Eric Zimmerman tools

```bash
# Parse $MFT to CSV, --csv is the directory and --csvf the file name
MFTECmd.exe -f "E:\C\$MFT" --csv "F:\out" --csvf mft.csv

# Parse the USN journal; -f accepts the extracted $J stream
MFTECmd.exe -f "E:\C\$Extend\$UsnJrnl_$J" --csv "F:\out" --csvf usn.csv

# Dump a single MFT record in full detail by entry number, for resident-data recovery
MFTECmd.exe -f "E:\C\$MFT" --de 12345

# Parse all prefetch files in a directory, recursively, into one CSV
PECmd.exe -d "E:\C\Windows\Prefetch" -q --csv "F:\out" --csvf prefetch.csv

# Same but emit the "run times" as one row each, which is what you want for a timeline
PECmd.exe -d "E:\C\Windows\Prefetch" --csv "F:\out" --csvf pf.csv --mp

# Parse every LNK under a tree and include the target MAC times
LECmd.exe -d "E:\C\Users" -q --csv "F:\out" --csvf lnk.csv

# Parse jump lists (both Automatic and Custom Destinations)
JLECmd.exe -d "E:\C\Users\alice\AppData\Roaming\Microsoft\Windows\Recent" -q --csv "F:\out"

# ShimCache from a SYSTEM hive; -c picks the control set (-1 = all)
AppCompatCacheParser.exe -f "E:\C\Windows\System32\config\SYSTEM" -c -1 --csv "F:\out"

# Amcache including unassociated file entries, which is where dropped binaries show up
AmcacheParser.exe -f "E:\C\Windows\AppCompat\Programs\Amcache.hve" -i --csv "F:\out"

# SRUM needs both the ESE database and the SOFTWARE hive for the app/interface ID maps
SrumECmd.exe -f "E:\C\Windows\System32\sru\SRUDB.dat" -r "E:\C\Windows\System32\config\SOFTWARE" --csv "F:\out"

# Shellbags for one user: point -d at the directory holding UsrClass.dat/NTUSER.DAT
SBECmd.exe -d "E:\C\Users\alice" --csv "F:\out" --dedupe

# RECmd with the batch file that dumps every known forensic value from a hive
RECmd.exe -f "E:\C\Windows\System32\config\SYSTEM" --bn BatchExamples\Kroll_Batch.reb --csv "F:\out"

# RECmd free-text: find any value whose data contains a string, across the whole hive
RECmd.exe -f "E:\C\Users\alice\NTUSER.DAT" --sd "powershell" --csv "F:\out"

# Replay dirty transaction logs into the hives before parsing anything
rla.exe -d "E:\C\Windows\System32\config" --out "F:\clean_hives"

# EvtxECmd over a whole log directory with the maps that normalise fields
EvtxECmd.exe -d "E:\C\Windows\System32\winevt\Logs" --csv "F:\out" --csvf evtx.csv

# Single log, filtered to the event IDs you care about
EvtxECmd.exe -f "E:\C\...\Security.evtx" --inc 4624,4625,4688,4697,1102 --csv "F:\out"

# Recycle bin: -d for a whole $Recycle.Bin tree, handles $I and INFO2
RBCmd.exe -d "E:\C\$Recycle.Bin" --csv "F:\out"

# Windows Timeline ActivitiesCache.db
WxTCmd.exe -f "E:\C\Users\alice\AppData\Local\ConnectedDevicesPlatform\abc123\ActivitiesCache.db" --csv "F:\out"

# Timeline Explorer is GUI-only: open every CSV above, then sort by the timestamp column
TimelineExplorer.exe
```

## Parser command lines - open source

```bash
# RegRipper: run every plugin in a hive-specific profile
rip.pl -r ./SYSTEM -f system > system.txt

# RegRipper: run one plugin only (fastest way to answer one question)
rip.pl -r ./NTUSER.DAT -p userassist

# RegRipper: list all plugins that apply to the ntuser profile
rip.pl -l -c | grep -i ntuser

# reglookup: dump every key and value as pipe-delimited text for grepping
reglookup -H ./NTUSER.DAT | grep -i 'runmru'

# python-registry: recursively print keys with their last-write times
regview.py ./SOFTWARE 2>/dev/null || python3 -m Registry.RegistryParse ./SOFTWARE

# evtx_dump (Rust): convert an EVTX to JSON lines, one event per line
evtx_dump -o jsonl Security.evtx > security.jsonl

# Filter those JSON lines for 4688 process creations and print the command line
jq -r 'select(.Event.System.EventID==4688) | .Event.EventData.CommandLine' security.jsonl

# Chainsaw: hunt a log directory with the Sigma rules and the built-in mapping
chainsaw hunt ./Logs -s ./sigma --mapping ./mappings/sigma-event-logs-all.yml --csv -o out

# Chainsaw: plain keyword search across all EVTX, case-insensitive
chainsaw search -i 'mimikatz' ./Logs

# Hayabusa: fast triage timeline with the bundled detection rules
hayabusa csv-timeline -d ./Logs -o timeline.csv -p super-verbose

# Hayabusa: one-page summary of which detections fired
hayabusa metrics -d ./Logs

# Zircolite: Sigma over EVTX via an in-memory SQLite database
python3 zircolite.py --evtx ./Logs --ruleset rules/rules_windows_generic.json -o detected.json

# KAPE: collect the standard triage target set from a live or mounted volume
kape.exe --tsource E: --tdest F:\triage --target !SANS_Triage --vhdx triage

# KAPE: run the parsing modules over what you just collected
kape.exe --msource F:\triage --mdest F:\parsed --module !EZParser --mflush

# rifiuti2 for Vista+ $I files (use rifiuti for XP INFO2)
rifiuti-vista -o recycle.txt ./\$Recycle.Bin/S-1-5-21-1234-1001/

# libscca prefetch parser, prints run times and the loaded-file list
sccainfo -v CMD.EXE-12345678.pf

# LnkParse3 on a single shortcut, JSON output for scripting
lnkparse -j "./Recent/report.lnk"

# srum_dump2 needs the template workbook that names the ESE tables
python3 srum_dump2.py -i SRUDB.dat -t SRUM_TEMPLATE2.xlsx -r SOFTWARE -o srum.xlsx

# USN journal to CSV with the pure-python parser
python3 usn.py -f '$UsnJrnl_$J' -o usn.csv

# analyzeMFT as a pure-python fallback when MFTECmd is unavailable
analyzeMFT.py -f '$MFT' -o mft.csv --bodyfull

# Sleuthkit: MAC-time bodyfile straight from a raw image partition offset
fls -r -m C: -o 2048 disk.raw > bodyfile

# Turn that bodyfile into a sorted timeline
mactime -b bodyfile -d -z UTC > timeline.csv

# plaso: ingest an entire image or triage folder into a single storage file
log2timeline.py --storage-file case.plaso ./triage

# plaso: filter the storage file to a date window and a set of artifact sources
psort.py -o dynamic -w super.csv case.plaso "date > '2024-01-01' AND date < '2024-02-01'"

# plaso: list every parser available so you can restrict with --parsers
log2timeline.py --parsers list | head -40

# bulk_extractor: pull emails, URLs, and credit-card-shaped strings from any blob
bulk_extractor -o bulk_out disk.raw

# Extract and mount a Volume Shadow Copy from a raw image (Linux)
vshadowmount -o 2048 disk.raw /mnt/vss && ls /mnt/vss
```

## Timestamp epochs

| Format | Epoch | Unit | Where it appears | Convert |
|---|---|---|---|---|
| Windows FILETIME | 1601-01-01 UTC | 100 ns | Registry, LNK, EVTX, MFT, Prefetch, Amcache, BAM | `(v/10000000)-11644473600` -> UNIX |
| Windows SYSTEMTIME | n/a | 8 x uint16 struct | NetworkList first/last connect (LOCAL time) | parse fields directly |
| UNIX epoch | 1970-01-01 UTC | seconds | Linux, Zone.Identifier none, Chrome `Bookmarks` date_added is WebKit | `date -u -d @v` |
| WebKit/Chrome | 1601-01-01 UTC | microseconds | Chrome `visits.visit_time`, `cookies.creation_utc` | `(v/1000000)-11644473600` |
| Firefox PRTime | 1970-01-01 UTC | microseconds | `moz_historyvisits.visit_date` | `v/1000000` |
| Mac absolute | 2001-01-01 UTC | seconds (or float) | Safari, bplist `NSDate` | `v+978307200` |
| OLE Automation date | 1899-12-30 | days (double) | Office documents, some ESE columns | `(v-25569)*86400` |
| DOS date/time | 1980-01-01 | packed 2+2 bytes, 2 s resolution | ZIP entries, FAT | bit-unpack |
| SQLite julianday | -4713-11-24 | days (real) | some app DBs | `strftime('%s', v)` |
| ESE `DateTime` | varies by column | FILETIME or OLE | SRUDB.dat, WebCacheV01.dat | check the column type |

```bash
# Convert a decimal FILETIME to UTC on Linux/macOS
python3 -c "import sys,datetime;v=int(sys.argv[1]);print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10))" 133500000000000000

# Convert a Chrome WebKit timestamp taken straight out of sqlite
python3 -c "import sys,datetime;v=int(sys.argv[1]);print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v))" 13350000000000000

# Convert a hex FILETIME as it appears in an Office File MRU value
python3 -c "import sys,datetime;v=int(sys.argv[1],16);print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10))" 01D9A1B2C3D4E5F6
```

## Where to find it in a mounted image

```bash
# Identify partitions and note the sector offset of the NTFS volume
mmls disk.raw

# Mount the NTFS partition read-only at the offset mmls reported (offset = sector * 512)
mount -o ro,loop,offset=$((2048*512)),show_sys_files,streams_interface=windows disk.raw /mnt/c

# List the NTFS metafiles that only appear with show_sys_files
ls -la /mnt/c/'$MFT' /mnt/c/'$LogFile' /mnt/c/'$Extend'

# Pull the USN journal ADS out of a mounted volume (streams_interface=windows exposes it)
cp '/mnt/c/$Extend/$UsnJrnl:$J' ./UsnJrnl_J

# Extract metafiles without mounting, using Sleuthkit inode numbers (0 = $MFT, 2 = $LogFile)
icat -o 2048 disk.raw 0 > '$MFT'

# Copy the whole config directory including the dirty transaction logs
cp /mnt/c/Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}* ./hives/

# Enumerate user profiles so you know how many NTUSER.DAT files to parse
ls -1 /mnt/c/Users

# Grab per-user hives and the shell-item hive in one go
for u in /mnt/c/Users/*/; do cp "$u/NTUSER.DAT" "./hives/$(basename $u)-NTUSER.DAT" 2>/dev/null; done

# Map a SID in an artifact back to a username via the profile list
reglookup -H ./SOFTWARE | grep -i 'ProfileList'

# Recursively find every EVTX regardless of case or nesting
find /mnt/c -iname '*.evtx' 2>/dev/null

# Search unallocated space and slack for a flag pattern in UTF-16LE (Windows strings)
strings -el disk.raw | grep -aoiE '[a-z0-9_]+\{[^}]{4,80}\}'

# Same search in plain ASCII, which catches artifacts written by Unix-side tooling
strings -a disk.raw | grep -aoE 'flag\{[^}]+\}'

# Find alternate data streams on a mounted NTFS volume
find /mnt/c -exec getfattr -d -m '.*' {} \; 2>/dev/null | grep -i 'ntfs.streams'
```

## Tools

Eric Zimmerman suite (MFTECmd, PECmd, LECmd, JLECmd, AppCompatCacheParser, AmcacheParser,
SrumECmd, RECmd, SBECmd, EvtxECmd, RBCmd, WxTCmd, rla, Timeline Explorer), RegRipper,
reglookup, python-registry, libyal (libscca, libesedb, libevtx, libregf, libvshadow),
evtx_dump, chainsaw, hayabusa, zircolite, KAPE, rifiuti2, LnkParse3, srum_dump2,
analyzeMFT, Sleuthkit, plaso, bulk_extractor, Autopsy, Velociraptor.

## References

- Eric Zimmerman tools documentation and the KAPE target/module repository
- RegRipper plugin source (each plugin header documents the key it reads)
- libyal project documentation for the ESE, REGF, EVTX and SCCA formats
- SANS DFIR "Windows Forensic Analysis" poster for artifact-to-question mapping
