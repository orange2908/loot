---
title: "Anti-VM and Anti-Sandbox - Environment Checks and Their Bypasses"
category: rev
subcategory: anti-vm
type: technique
tags: [anti-vm, anti-sandbox, antivm, cpuid, hypervisor-bit, vmware, virtualbox, qemu, kvm, dmi, smbios, mac-oui, docker-detection, sandbox-evasion, environment-check, patching, unicorn, registry, evasion]
difficulty: medium
summary: "cpuid hypervisor bits, DMI strings, MAC OUIs, /dev nodes and registry keys - how a binary knows it is in a VM, and how to make it believe otherwise."
when_to_use:
  - "The binary behaves differently (or refuses to run) inside your analysis VM or container"
  - "You see cpuid, /sys/class/dmi, VBoxGuest, vmtoolsd or hypervisor vendor strings"
  - "A malware-style CTF challenge only decrypts its payload on 'real' hardware"
  - "You need to know which magic constants to grep for to find the checks fast"
tools: [ghidra, radare2, gdb, qemu, libvirt, unicorn, strings, dmidecode]
related: [anti-debug-bypass, binary-patching, packers-and-unpacking, windows-pe-reversing, triage-unknown-binary]
---

## TL;DR

Anti-VM is a checklist of environment fingerprints: the CPUID hypervisor bit and vendor
string, DMI/SMBIOS product names, virtual NIC MAC prefixes, guest-tool processes and device
nodes, and resource thresholds (RAM, cores, disk). None of it is cryptographic - find the
check, then either patch the branch or spoof the artefact. In CTFs the check is almost
always just a gate in front of the interesting code.

## Recognise it

```sh
# 1. The magic vendor strings are plain ASCII in .rodata - one grep finds most checks
strings -a ./sample | grep -aiE 'vmware|virtualbox|vbox|qemu|kvm|xen|hyper-?v|parallels|bochs|sandbox|cuckoo|wine'
# 2. cpuid appears as a raw instruction; xref its callers in your disassembler
objdump -d ./sample | grep -n cpuid
# 3. Paths probed at runtime
strings -a ./sample | grep -aE '/sys/class/dmi|/proc/scsi|/dev/vbox|/dev/vmci|/\.dockerenv|/proc/self/cgroup'
# 4. Windows: registry and process enumeration APIs plus the key paths
rabin2 -zz sample.exe | grep -iE 'HARDWARE\\\\ACPI|VBoxGuest|vmtoolsd|RegOpenKey|Process32'
```

Behavioural tells: instant clean exit on a VM, "Analysis environment detected", a decryption
routine whose output is garbage, or a long sleep followed by nothing.

## The fingerprint catalogue

### CPUID

```c
/* hypervisor-present bit: leaf 1, ECX bit 31. Set by essentially every hypervisor. */
unsigned int eax, ebx, ecx, edx;
__asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
if (ecx & (1u << 31)) puts("hypervisor present");

/* leaf 0x40000000: EBX:ECX:EDX hold a 12-byte vendor signature */
__asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x40000000));
/* ebx|ecx|edx == "VMwareVMware" / "KVMKVMKVM\0\0\0" / ... */
```

| CPUID 0x40000000 signature | Hypervisor |
|---|---|
| `VMwareVMware` | VMware |
| `KVMKVMKVM\0\0\0` | KVM |
| `Microsoft Hv` | Hyper-V / WSL2 |
| `XenVMMXenVMM` | Xen |
| `VBoxVBoxVBox` | VirtualBox (with the VBox hypervisor leaf) |
| `TCGTCGTCGTCG` | QEMU TCG (no KVM) |
| `prl hyperv  ` | Parallels |
| `bhyve bhyve ` | bhyve |
| `ACRNACRNACRN` | ACRN |

Also seen: leaf 0 vendor string `"GenuineIntel"` vs QEMU's default, and checking the brand
string (leaves 0x80000002-4) for `"QEMU Virtual CPU"`.

### Timing: RDTSC vs a forced VM exit

```c
/* cpuid is an unconditional VM exit; on bare metal the delta is ~100-200 cycles,
   under a hypervisor it is typically thousands. */
unsigned long long t0 = __rdtsc();
__asm__ volatile("cpuid" ::: "eax", "ebx", "ecx", "edx");
unsigned long long t1 = __rdtsc();
if (t1 - t0 > 1000) puts("virtualised");
```

### The VMware backdoor port

```c
/* magic 0x564D5868 ("VMXh") in EAX, port 0x5658 ("VX"), command 0x0A in CX.
   On a real machine the `in` faults (SIGSEGV); on VMware it returns VMXh in EBX. */
unsigned int magic = 0, port = 0x5658;
__asm__ volatile("in %%dx, %%eax" : "=a"(magic) : "a"(0x564D5868), "c"(0x0A), "d"(port));
if (magic == 0x564D5868) puts("VMware");
```

Grep for the constants `0x564D5868` (`68 58 4D 56` little-endian) and `0x5658`.

### Linux artefacts

| Artefact | Value that exposes a VM |
|---|---|
| `/sys/class/dmi/id/product_name` | `VMware Virtual Platform`, `VirtualBox`, `KVM`, `Standard PC (Q35 + ICH9, 2009)` |
| `/sys/class/dmi/id/sys_vendor` | `QEMU`, `innotek GmbH`, `VMware, Inc.`, `Microsoft Corporation` |
| `/sys/class/dmi/id/bios_vendor` | `SeaBIOS`, `Phoenix Technologies LTD` (VBox) |
| `/proc/scsi/scsi` | `VBOX HARDDISK`, `VMware Virtual S`, `QEMU HARDDISK` |
| `/proc/cpuinfo` | flags contain `hypervisor` |
| `/proc/modules`, `lsmod` | `vboxguest`, `vboxsf`, `vmw_balloon`, `virtio_*` |
| `/dev/vboxguest`, `/dev/vmci`, `/dev/vmmon` | device nodes |
| `/proc/ide/hd*/model` | `VBOX HARDDISK` |
| MAC address prefix | see OUI table |
| `dmesg` | `Hypervisor detected: KVM` |
| `/.dockerenv`, `/proc/1/cgroup` | container, not a VM |
| `/proc/self/status` `Seccomp:` | sandbox |

```sh
# What an anti-VM check actually reads, all in one place
cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/bios_vendor
grep -c hypervisor /proc/cpuinfo
cat /proc/scsi/scsi 2>/dev/null
ls -l /dev/vboxguest /dev/vmci 2>/dev/null
ip link | grep -i ether
```

### MAC OUI prefixes

| Prefix | Vendor |
|---|---|
| `00:05:69`, `00:0C:29`, `00:1C:14`, `00:50:56` | VMware |
| `08:00:27`, `0A:00:27` | VirtualBox |
| `52:54:00` | QEMU / KVM (virtio) |
| `00:16:3E` | Xen |
| `00:15:5D` | Hyper-V |
| `00:1C:42` | Parallels |
| `00:03:FF` | Microsoft Virtual PC |

### Windows artefacts

| Check | Detail |
|---|---|
| Registry `HKLM\HARDWARE\ACPI\DSDT\VBOX__` | VirtualBox ACPI table |
| `HKLM\HARDWARE\ACPI\FADT\VBOX__`, `..\RSDT\VBOX__` | VirtualBox |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest\|VBoxMouse\|VBoxSF` | VBox guest additions |
| `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` | VMware tools |
| `HKLM\HARDWARE\DEVICEMAP\Scsi\...\Identifier` | `VBOX`, `VMware`, `QEMU` |
| `HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation\SystemProductName` | product name |
| Processes | `vmtoolsd.exe`, `vmwaretray.exe`, `VBoxService.exe`, `VBoxTray.exe`, `vmusrvc.exe`, `prl_cc.exe`, `xenservice.exe` |
| Files | `C:\Windows\System32\drivers\VBoxMouse.sys`, `vmhgfs.sys`, `vmci.sys` |
| WMI | `SELECT * FROM Win32_ComputerSystem` -> Manufacturer/Model |
| `GetSystemInfo` | `dwNumberOfProcessors < 2` |
| `GlobalMemoryStatusEx` | `ullTotalPhys < 2 GB` |
| `GetDiskFreeSpaceEx` | disk < 60 GB |
| `GetTickCount` / uptime | uptime < 10 minutes means a freshly reverted snapshot |
| `GetCursorPos` twice | no mouse movement means no human |
| `Sleep(300000)` then `GetTickCount` delta | a sandbox that skips sleeps is exposed |
| `NtQuerySystemInformation(SystemFirmwareTableInformation)` | reads raw SMBIOS to bypass API hooks |
| Username / hostname | `SANDBOX`, `MALWARE`, `VIRUS`, `JOHN-PC`, `CUCKOO` |
| Loaded modules | `sbiedll.dll` (Sandboxie), `dbghelp.dll`, `api_log.dll` |

## Attack - finding and killing the checks

1. **Grep for the constants** (script below). This finds 80% of checks in seconds.
2. **Xref `cpuid`, `in`, and the string hits** in Ghidra/IDA. Each check is usually a small
   function returning bool, called from one place with a `test al, al; jne bail`.
3. **Patch**. Two options: flip the branch at the call site, or patch the detector function
   itself to `xor eax,eax; ret` (31 c0 c3). The second is better when the same detector is
   called from several places. See `binary-patching`.
4. **Or spoof the artefact** if you would rather not modify the binary:

```sh
# --- Linux: fake the DMI strings and /proc files in a private mount namespace ---
mkdir -p /tmp/fakedmi
printf 'Precision 5570\n'      > /tmp/fakedmi/product_name
printf 'Dell Inc.\n'           > /tmp/fakedmi/sys_vendor
unshare -m --map-root-user sh -c '
  mount --bind /tmp/fakedmi/product_name /sys/class/dmi/id/product_name
  mount --bind /tmp/fakedmi/sys_vendor  /sys/class/dmi/id/sys_vendor
  ./sample'

# --- Change the guest MAC to a non-virtual OUI (host side, libvirt) -----------
# <mac address="3c:52:82:11:22:33"/> in the <interface> element of the domain XML

# --- KVM/libvirt: hide the hypervisor CPUID leaf entirely --------------------
# <feature policy="disable" name="hypervisor"/>   inside <cpu>
# <kvm><hidden state="on"/></kvm>                 inside <features>
# plus SMBIOS spoofing:
# <sysinfo type="smbios"><system>
#   <entry name="manufacturer">Dell Inc.</entry>
#   <entry name="product">Precision 5570</entry>
# </system></sysinfo>
# and <os><smbios mode="sysinfo"/></os>

# --- QEMU command line equivalents ------------------------------------------
qemu-system-x86_64 -cpu host,-hypervisor,kvm=off \
  -smbios type=1,manufacturer="Dell Inc.",product="Precision 5570" \
  -device e1000,mac=3c:52:82:11:22:33 -m 8192 -smp 8 disk.qcow2

# --- Rename the guest tools so process scans miss them ----------------------
sudo systemctl stop vboxadd vboxadd-service 2>/dev/null
```

5. **Or emulate**. Under Unicorn you control `cpuid` directly, so no check ever fires:

```python
#!/usr/bin/env python3
"""cpuid_spoof.py - emulate x86-64 code under Unicorn with a lying CPUID.

Reports: no hypervisor bit, GenuineIntel vendor, and an empty 0x40000000 leaf.
Useful for running an anti-VM-protected decryption routine in isolation.
"""
from unicorn import UC_ARCH_X86, UC_HOOK_INSN, UC_MODE_64, Uc
from unicorn.x86_const import (
    UC_X86_INS_CPUID,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_RIP,
)

BASE = 0x400000
STACK = 0x200000

# mov eax,1 ; cpuid ; hlt   -> we watch what the guest sees in ECX
CODE = b"\xb8\x01\x00\x00\x00\x0f\xa2\xf4"


def hook_cpuid(uc, _user):
    leaf = uc.reg_read(UC_X86_REG_EAX)
    if leaf == 1:
        # Standard feature bits with ECX bit 31 (hypervisor) cleared
        uc.reg_write(UC_X86_REG_EAX, 0x000906EA)
        uc.reg_write(UC_X86_REG_EBX, 0x00100800)
        uc.reg_write(UC_X86_REG_ECX, 0x7FFAFBFF & ~(1 << 31))
        uc.reg_write(UC_X86_REG_EDX, 0xBFEBFBFF)
    elif leaf == 0:
        uc.reg_write(UC_X86_REG_EAX, 0x16)
        uc.reg_write(UC_X86_REG_EBX, 0x756E6547)   # "Genu"
        uc.reg_write(UC_X86_REG_EDX, 0x49656E69)   # "ineI"
        uc.reg_write(UC_X86_REG_ECX, 0x6C65746E)   # "ntel"
    else:
        for reg in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            uc.reg_write(reg, 0)
    uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + 2)   # skip the cpuid
    return True     # tell Unicorn we handled it


def main() -> int:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BASE, 0x1000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(BASE, CODE)
    uc.hook_add(UC_HOOK_INSN, hook_cpuid, None, 1, 0, UC_X86_INS_CPUID)
    try:
        uc.emu_start(BASE, BASE + len(CODE) - 1)
    except Exception:
        pass
    ecx = uc.reg_read(UC_X86_REG_ECX)
    print(f"ECX = {ecx:#010x}  hypervisor bit = {(ecx >> 31) & 1}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Code - scan a binary for every anti-VM artefact

```python
#!/usr/bin/env python3
"""antivm_scan.py - report every known anti-VM string and magic constant in a binary.

Usage: python3 antivm_scan.py ./sample
"""
import re
import sys

STRINGS = [
    b"VMwareVMware", b"KVMKVMKVM", b"Microsoft Hv", b"XenVMMXenVMM", b"VBoxVBoxVBox",
    b"TCGTCGTCGTCG", b"prl hyperv", b"bhyve bhyve", b"ACRNACRNACRN",
    b"VMware", b"VirtualBox", b"VBOX", b"vboxguest", b"vboxsf", b"VBoxService",
    b"VBoxTray", b"vmtoolsd", b"vmwaretray", b"vmusrvc", b"prl_cc", b"xenservice",
    b"QEMU", b"Bochs", b"innotek", b"Parallels", b"Hyper-V", b"Virtual Machine",
    b"/sys/class/dmi/id", b"product_name", b"sys_vendor", b"/proc/scsi/scsi",
    b"/proc/cpuinfo", b"hypervisor", b"/dev/vmci", b"/dev/vboxguest", b"/dev/vmmon",
    b"/.dockerenv", b"/proc/self/cgroup", b"SbieDll.dll", b"sandbox", b"cuckoo",
    b"HARDWARE\\ACPI\\DSDT", b"VMware Tools", b"VBoxGuest", b"VBoxMouse.sys",
    b"Win32_ComputerSystem", b"SystemProductName", b"wine_get_version",
]

# (name, little-endian byte pattern)
CONSTANTS = [
    ("VMware backdoor magic 0x564D5868", b"\x68\x58\x4d\x56"),
    ("VMware backdoor port 0x5658", b"\x58\x56"),
    ("cpuid hypervisor leaf 0x40000000", b"\x00\x00\x00\x40"),
    ("cpuid raw instruction (0f a2)", b"\x0f\xa2"),
    ("rdtsc raw instruction (0f 31)", b"\x0f\x31"),
    ("rdtscp raw instruction (0f 01 f9)", b"\x0f\x01\xf9"),
    ("sidt (0f 01 /1) - red pill", b"\x0f\x01"),
    ("VBox OUI 08:00:27 ascii", b"08:00:27"),
    ("VMware OUI 00:0C:29 ascii", b"00:0C:29"),
    ("QEMU OUI 52:54:00 ascii", b"52:54:00"),
]

UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def widen(s: bytes) -> bytes:
    """UTF-16LE form, as used by Windows registry-path constants."""
    return b"".join(bytes([c, 0]) for c in s)


def scan(path: str) -> int:
    with open(path, "rb") as fh:
        data = fh.read()

    hits = 0
    print(f"[*] {path}: {len(data)} bytes")
    print("--- ascii / utf-16 artefacts ---")
    for needle in STRINGS:
        for form, label in ((needle, "ascii"), (widen(needle), "utf16")):
            start = 0
            while True:
                idx = data.find(form, start)
                if idx < 0:
                    break
                print(f"  {idx:#010x}  [{label}] {needle.decode(errors='replace')}")
                hits += 1
                start = idx + 1

    print("--- magic constants / instructions ---")
    for name, pattern in CONSTANTS:
        offsets = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + 1
            if len(offsets) >= 20:
                break
        if offsets:
            shown = " ".join(f"{o:#x}" for o in offsets[:20])
            print(f"  {name}: {len(offsets)} hit(s) -> {shown}")
            hits += len(offsets)

    print(f"\n[+] {hits} total artefact hit(s)")
    if hits == 0:
        print("    (no anti-VM artefacts found - the check may be computed or encrypted)")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: antivm_scan.py <binary>")
        return 1
    return scan(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
```

Note that `cpuid`/`rdtsc` byte patterns produce false positives inside data; treat them as
leads for xref analysis, not as proof.

## Variants & pitfalls

- **The check result feeds the decryption key**, not just a branch:
  `key = is_vm ? junk : real_key`. Patching the branch yields garbage. You must make the
  detector return the *bare-metal* answer.
- **Thresholds instead of signatures**: `< 2 cores`, `< 4 GB RAM`, `< 100 GB disk`,
  `uptime < 10 min`. Give the VM more resources and let it run a while; that is faster than
  patching.
- **Stalling**: `Sleep(600000)` before the payload. Do not patch the sleep out blindly -
  some samples check `GetTickCount` deltas around it and detect the skip. Patch both, or
  hook `Sleep` to actually advance the fake clock.
- **Human-interaction checks**: cursor movement, scroll events, recently-opened documents,
  number of processes. Wiggle the mouse, or patch.
- **Wine detection**: `wine_get_version` exported from ntdll. Trivial to patch.
- **Container detection** is not anti-VM: `/.dockerenv`, `/proc/1/cgroup` containing
  `docker`/`kubepods`, and `/proc/1/comm` != `systemd`. Bind-mount or run on a plain VM.
- **Checks in TLS callbacks / `.init_array`** run before `main` - see
  `windows-pe-reversing` and `anti-debug-bypass`.
- **The straightforward CTF answer** is usually: NOP the detector, or run the payload
  function in Unicorn where none of this exists.

## Tools

- `dmidecode -t system` - see exactly what a check reads.
- `libvirt` / `qemu` CPU and SMBIOS options - spoof at the hypervisor level.
- `unicorn` - full control over `cpuid`, `rdtsc` and I/O ports.
- `pafish` / `al-khaser` - open-source test suites that implement this entire catalogue;
  reading their source is the fastest way to learn a new check.
- `capa` - flags "check for virtual machine" behaviours automatically.

## References

- Intel SDM Volume 2, `CPUID` instruction: leaf 1 ECX bit 31 is reserved for the hypervisor
  present flag; leaves 0x40000000-0x400000FF are the hypervisor vendor range.
- `al-khaser` and `pafish` source trees (comprehensive check catalogues).
- `man 8 dmidecode` for the SMBIOS field names used by Linux checks.
