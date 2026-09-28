---
title: "Obfuscation - CSAW CTF Qualification Round 2024"
category: "rev"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["rev", "xor", "angr", "obfuscation", "symbolic-execution", "csaw-ctf-qualification-round", "csaw-ctf-qualification-round-2024", "2024", "ctf-writeup"]
summary: "Obfuscation - CSAW CTF Qualifiers 2024"
source:
  name: "CTFtime writeup #39482"
  url: "https://ctftime.org/writeup/39482"
original_source: "https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/README"
ctf:
  name: "CSAW CTF Qualification Round 2024"
  year: 2024
  challenge: "Obfuscation"
---

## Metadata

- **CTF:** CSAW CTF Qualification Round 2024
- **Task:** Obfuscation
- **Author team:** STT
- **CTFtime:** <https://ctftime.org/writeup/39482>
- **Original writeup:** <https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/README>

---
Obfuscation – CSAW CTF Qualifiers 2024

## Given

Remote: `nc obfuscation.ctf.csaw.io 5000`

Input: `wh47 15 7h3 r1ck 457l3y p4r4d0x?\n`

## Source

[obfuscated](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/handouts/obfuscated)

* * *

### Overview

Obfuscated really is the appropriate title for this challenge, because this binary was indeed (**_very_**) obfuscated. Likely done with Tigress.

We could have been smart and fancy, and tried to deobfuscate it in some way, but we just pummeled through the disassembly and tried to make sense of it.

It was clear that the original binary’s functions were split into several smaller stubs and jumped in between via `jmp rax` jumps, since all the virtualized instructions jmp to 0x1ECFB which holds this instruction.

It also soon became apparent that there was a considerable amount of deadcode (which is quite _cringe_ , if you ask me).

## The challenge

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image0.png)

When we run the binary we are greeted with a message that hints for a checker. We have to guess the password they want.

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image1.png)

The main function is… not presentable at all. We can see some familiar faces, nevertheless, like IO functions.

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image2.png) ![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image3.png) ![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image4.png)

We can check with the debugger that the `fgets` gets 0x22 chars, which is presumably the flag length. We can check a debugger and move the program counter to both blocks and we see that one of the routes falls into an error message and the other is a path that will open a `flag.txt` and execute a `script.sh`… Well, interesting…

There it is, we just have to see what that funky function is doing and…

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image5.png)

We found out the virtualization…

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image6.png)

We figured `rbp-0x2a38` will be holding the program counter of the VM as in pointing to the instructions which are references to their interpreter code and a number that may be used as offset for jumping to another instruction, for instance (times `sizeof(uintptr_t)`).

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image7.png)

## Finding out what depends on the chars

Tracing the characters from RAM and seeing when they would be used was not being that trivial, so we used ANGR to find the first splitting point.

```
    import angr
    import claripy
    
    waw = 0
    
    p = angr.Project('./obfuscated', load_options={'auto_load_libs': False})
    
    stdin_symbols = claripy.BVS('stdin', 8 * 0x22)
    
    state = p.factory.full_init_state(
        add_options=angr.options.unicorn,
        remove_options={angr.options.LAZY_SOLVES},
        stdin=stdin_symbols
    )
    
    
    
    def step_func(lsm):
        global waw
    
        if waw == 0:
            lsm.active[0].add_constraints(*[stdin_symbols.get_byte(i) < 0x80 for i in range(0x20)])
            lsm.active[0].add_constraints(*[stdin_symbols.get_byte(i) > 0x20 for i in range(0x20)])
            waw = 1
    
        if len(lsm.active) > 1:
            print(f"solver @ {lsm.active[0].addr:X}: {lsm.active[0].solver.constraints}")
            print(f"solver @ {lsm.active[1].addr:X}: {lsm.active[1].solver.constraints}")
            lsm.stashes['active'] = []
    
    
    
    avoid = [0x40b1f0]
    find = [0x40A01E]
    simgr = p.factory.simgr(state)
    simgr.run(step_func=step_func, avoid=avoid, find=find)
```

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image8.png)

We notice the first branch depending on the flag.

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image9.png)

The logic tells us this branching is done on a boolean value – this is a pattern we will see further ahead. But the things that determine that value were executed beforehand. We used the debugger and eventually found it, besides finding out that this was just a useless loop to match the value itself with a counter, because it would go to the next char, and then update that counter as well, and that was the value that was being accessed by the program, so we just abused hardware breakpoints on it.

And with more breakpoint abuse, we found out the place where the flag was ending up after that loop (`RBP + 0x9f70`).

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image10.png)

For the input `"passpasspass"` we saw then some value was being replaced on the chars… We noticed the big function that was initializing an SBOX and deduced it was from there.

### S-Box

The S-box that was applied to the string was filled in at the entry to main, and reading off the disassembly showed each entry and its corresponding substitution.

From this, we got the reverse S-box.

```
    ; void sbox_B872()
    sbox_B872 proc near
    ; __unwind { // 555555554000
    endbr64
    push    rbp
    mov     rbp, rsp
    mov     cs:byte_5555555931E0, 1         ; 1 maps to \x78
    mov     cs:byte_5555555931E1, 78h ; 'x' 
    mov     cs:byte_5555555931E2, 2         ; 2 maps to \xec
    mov     cs:byte_5555555931E3, 0ECh      
    mov     cs:byte_5555555931E4, 3         ; 3 maps to \x8e
    mov     cs:byte_5555555931E5, 8Eh
    mov     cs:byte_5555555931E6, 4         ; 4 maps to \x76
    mov     cs:byte_5555555931E7, 76h ; 'v'
    mov     cs:byte_5555555931E8, 5
    mov     cs:byte_5555555931E9, 2Ch ; ','
    mov     cs:byte_5555555931EA, 6
    mov     cs:byte_5555555931EB, 10h
    mov     cs:byte_5555555931EC, 7
    mov     cs:byte_5555555931ED, 30h ; '0'
    mov     cs:byte_5555555931EE, 8
    mov     cs:byte_5555555931EF, 0ADh
    mov     cs:byte_5555555931F0, 9
    mov     cs:byte_5555555931F1, 26h ; '&'
    [...] ; snipped
```

Fiddling around with more Breakpoint Abuse™️, we realized that the input bytes went three rounds through a substitution box and later something would happen… We supposed. We found out the first 4 chars were being fed into `strtol` -> `srand` and with breakpoints (_this time not hardware watchpoints, but conventional breakpoints as we know them 😉_), we noticed that increasing the flag would not result in more calls, so we formed the conjecture that those ones would be to derive the seed for srand. Hopefully we would be correct, and not absolutely trolled (_Foreshadowing is a literary device in which –_).

More breakpoint abuse led to us finding where the values that resulted from calling `rand` were being led to and (_gasps_) we found out a xor with those values that was being stored and accessed by the VM (_with tons of useless NOP instructions_).

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image11.png)

This little XOR in the middle of so many instructions was what mattered here for this instruction.

With more breakpoint abuse we found out a `cmp` that was comparing the xor’red value against something and setting on memory the flags. A pattern we have seen used before to control flow when we used ANGR to find the useless loop. We knew the fork was some instructions ahead.

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image12.png)

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image13.png)

So we decided to that so that we make sure `r8` is `0`, and we would see if we get the value we put into our own `flag.txt` appears.

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image14.png)

![](https://sectt.github.io/writeups/CSAW24-quals/rev_obfuscation/imgs/image15.png)

Huzzah! We got our local flag!

Now we can dump all the values that were being `cmp`‘d with a gdbscript:

```
    import gdb
    
    gdb.execute("break *(0x297ad + 0x000555555554000)")
    gdb.execute("run")
    
    rax_values = []
    
    def breakpoint_handler(event):
        global rax_values
        rax_values.append(gdb.execute("print/x $rax", to_string=True).split()[-1])
    
    gdb.events.stop.connect(breakpoint_handler)
    
    while True:
        gdb.execute("continue")
        with open("out.txt", "w") as f:
            f.write(str(rax_values))
```

Stepping through the execution, we found the `cmp` instruction that validated the final value of the substitution and xor’ing, and learned that the bytes had to be the following:

```
    [0xa5, 0xcd, 0xff, 0xe4, 0xe9, 0x6f, 0xfa, 0x54, 0xbe, 0xc6, 0x87, 0x13, 0xfd, 0x6b, 0xf9, 0x80, 0xc4, 0x54, 0xe4, 0x6f, 0x58, 0xd5, 0x23, 0x35, 0xad, 0xcc, 0x21, 0xf5, 0x93, 0x62, 0xc, 0xad, 0x5a, 0x32, 0xd]
```

Now, to reverse this into an actual input, we just had to reverse the S-box and find out the seed to `srand`. Since it is `strtol`‘ed with the 4 chars, it should be between -999 and 9999, right, right???

### Srand

Long story short, we went insane for 3 hours playing with spaces and 0s and whatever else we thought `strtol` could use since going through that range was not giving us any match. So we just gave up on this…

To find out the seed used for `rand` we bruteforced the 32 bit space of inputs for `srand`, but, as it turns out, the seed was just `0` (_We should have probably seen that one coming_).

At the time, we also, got the first four bytes of the S-boxed input string: `0xC2 0x0B 0x96 0x97`.

```
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <string.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <signal.h>
    #include <errno.h>
    #include <pthread.h>
    #include <sched.h>
    
    int stick_this_thread_to_core(int core_id) {
       int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
       if (core_id < 0 || core_id >= num_cores)
          return EINVAL;
    
       cpu_set_t cpuset;
       CPU_ZERO(&cpuset);
       CPU_SET(core_id, &cpuset);
    
       pthread_t current_thread = pthread_self();    
       return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    }
    
    #define PARALLEL 32
    
    int main(){
      unsigned long long brute = 0;
      uint64_t upto = (0x100000000L / (uint64_t)PARALLEL);
      int worker = 0;
      for (;worker < PARALLEL; worker++) {
          if (!fork()) {
              stick_this_thread_to_core(worker);
              printf("worker %d, %x to %lx\n", worker,brute,upto);
              break; // child
          }
          brute = upto;
          upto += (0x100000000L / (uint64_t)PARALLEL);
      }
      uint32_t start = brute;
    
      do {
        long val = strtol((const char*)&brute, NULL, 10);
    
        srand(val);
    
        if ((unsigned char)((rand() & 0xff) ^ ((const char*)&brute)[0]) == (unsigned char)0xa5) {
            if ((unsigned char)((rand() & 0xff) ^ ((const char*)&brute)[1]) == (unsigned char)0xcd) {
                if ((unsigned char)((rand() & 0xff) ^ ((const char*)&brute)[2]) == (unsigned char)0xff) {
                    if ((unsigned char)((rand() & 0xff) ^ ((const char*)&brute)[3]) == (unsigned char)0xe4) {
                            printf("%hhX %hhX %hhX %hhX\n", 
                                   ((const char*)&brute)[0], ((const char*)&brute)[1], ((const char*)&brute)[2], ((const char*)&brute)[3]
                            );
                    }
                }
            }
        }
    
        brute += 1;
      } while(brute < upto);
    
      return 0;
    }
```

## Solution

Knowing the `rand` seed, and knowing the S-box, the solve ended just up being xor’ing the expected bytes with `rand` and applying the reverse S-box three times.

Well, turns out that the match we got was `"C2 0B 96 97"`. Hence, srand will be fed 0 from strtol. Our conjecture was wrong and something that we thought was too good to be true but that we should have checked nonetheless to keep our sanity was in fact the answer.

Now, we have everything to cook a solver for the password.

```
    from ctypes import CDLL
    from itertools import permutations
    from pwn import xor
    
    libc = CDLL("libc.so.6")
    
    info = [0xa5, 0xcd, 0xff, 0xe4, 0xe9, 0x6f, 0xfa, 0x54, 0xbe, 0xc6, 0x87, 0x13, 0xfd, 0x6b, 0xf9, 0x80, 0xc4, 0x54, 0xe4, 0x6f, 0x58, 0xd5, 0x23, 0x35, 0xad, 0xcc, 0x21, 0xf5, 0x93, 0x62, 0xc, 0xad, 0x5a, 0x32, 0xd]
    
    poop = {1: 120, 2: 236, 3: 142, 4: 118, 5: 44, 6: 16, 7: 48, 8: 173, 9: 38, 10: 197, 11: 243, 12: 201, 13: 104, 14: 249, 15: 188, 16: 124, 17: 66, 18: 214, 19: 97, 20: 186, 21: 141, 22: 81, 23: 240, 24: 126, 25: 88, 26: 161, 27: 202, 28: 2, 29: 62, 30: 107, 31: 216, 32: 56, 33: 106, 34: 68, 35: 102, 36: 162, 37: 167, 38: 133, 39: 160, 40: 9, 41: 143, 42: 125, 43: 29, 44: 224, 45: 168, 46: 23, 47: 158, 48: 49, 49: 215, 50: 189, 51: 90, 52: 132, 53: 35, 54: 231, 55: 76, 56: 185, 57: 153, 58: 123, 59: 169, 60: 113, 61: 246, 62: 207, 63: 60, 64: 98, 65: 239, 66: 229, 67: 61, 68: 244, 69: 234, 70: 25, 71: 181, 72: 251, 73: 225, 74: 86, 75: 85, 76: 213, 77: 42, 78: 93, 79: 237, 80: 41, 81: 101, 82: 108, 83: 150, 84: 77, 85: 155, 86: 40, 87: 199, 88: 71, 89: 178, 90: 67, 91: 110, 92: 32, 93: 233, 94: 163, 95: 149, 96: 206, 97: 180, 98: 139, 99: 172, 100: 130, 101: 187, 102: 176, 103: 147, 104: 211, 105: 58, 106: 105, 107: 191, 108: 51, 109: 226, 110: 196, 111: 37, 112: 156, 113: 55, 114: 242, 115: 53, 116: 230, 117: 235, 118: 228, 119: 36, 120: 136, 121: 91, 122: 254, 123: 209, 124: 137, 125: 138, 126: 82, 127: 205, 128: 95, 129: 70, 130: 39, 131: 78, 132: 83, 133: 114, 134: 145, 135: 8, 136: 10, 137: 103, 138: 6, 139: 24, 140: 80, 141: 121, 142: 73, 143: 175, 144: 122, 145: 72, 146: 179, 147: 174, 148: 128, 149: 203, 150: 157, 151: 18, 152: 119, 153: 218, 154: 248, 155: 4, 156: 192, 157: 116, 158: 59, 159: 195, 160: 69, 161: 1, 162: 194, 163: 14, 164: 31, 165: 15, 166: 129, 167: 232, 168: 21, 169: 134, 170: 210, 171: 170, 172: 217, 173: 89, 174: 171, 175: 20, 176: 200, 177: 190, 178: 115, 179: 47, 180: 221, 181: 255, 182: 252, 183: 75, 184: 45, 185: 184, 186: 87, 187: 28, 188: 109, 189: 46, 190: 220, 191: 247, 192: 219, 193: 54, 194: 100, 195: 112, 196: 183, 197: 63, 198: 30, 199: 84, 200: 79, 201: 96, 202: 52, 203: 245, 204: 146, 205: 13, 206: 19, 207: 238, 208: 154, 209: 111, 210: 148, 211: 250, 212: 140, 213: 151, 214: 27, 215: 253, 216: 43, 217: 26, 218: 159, 219: 34, 220: 204, 221: 33, 222: 222, 223: 74, 224: 182, 225: 177, 226: 57, 227: 3, 228: 152, 229: 135, 230: 223, 231: 166, 232: 208, 233: 117, 234: 92, 235: 193, 236: 17, 237: 227, 238: 64, 239: 127, 240: 241, 241: 212, 242: 165, 243: 7, 244: 12, 245: 94, 246: 5, 247: 198, 248: 50, 249: 22, 250: 11, 251: 65, 252: 131, 253: 144, 254: 164, 255: 99}
    poop2 = {v: k for k, v in poop.items()}
    
    # value from the c script
    start = bytes(map(lambda x: poop2[poop2[poop2[x]]], bytes.fromhex("C2 0B 96 97")))
    
    libc.srand(0)
    
    print(start + bytes(map(lambda x : poop2[poop2[poop2[x]]], xor(info[4:], bytes(list([(libc.rand() % 256)&0xff for _ in range(35)][4:]))[:-2]))))
```

Running the solve on the remote got us the flag and a rick-roll, so the win was bitter-sweet. At least, now the breakpoints were free from abuse.
