---
title: "yasashiimon - hxp 38C3 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "yasashiimon", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Tue, 31 December 2024 ~ kirschju"
source:
  name: "CTFtime writeup #39754"
  url: "https://ctftime.org/writeup/39754"
original_source: "https://hxp.io/blog/119/hxp-38C3-CTF-yasashiimon/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "yasashiimon"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** yasashiimon
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39754>
- **Original writeup:** <https://hxp.io/blog/119/hxp-38C3-CTF-yasashiimon/>

---
Tue, 31 December 2024 ~ kirschju

## hxp 38C3 CTF: yasashiimon

REV (714 points, 5 solves)

Here we explain the solution for the reversing challenge [yasashiimon](https://2024.ctf.link/internal/challenge/7be6bf7e-3173-48e7-838f-3bad78f05cb7/) from our recent CTF.

The challenge is about a malicious emulator patching the game.

### Description

Let’s face it, this “hacking” hobby of yours can be quite daunting at times. How about you get out your Gameboy and have some fun instead?

Note: You’re looking for a Gameboy Advance game. Replace `<` and `>` by `{` and `}` before submitting your flag.

### Starting up the Emulator

In this challenge we’re presented with a compiled version of the [Visual Boy Advance](https://github.com/visualboyadvance-m/visualboyadvance-m) emulator. When trying to open any (legally owned) ROM image of a game, we’re greeted with the following error message, indicating that we’re dealing with a modified version of the emulator:

![](https://hxp.io/assets/data/posts/119-yasashiimon/locked.png)

Decompiling the binary and searching for references to the string of the error message, we find a suspcious looking check in the pseudocode:

```
    for ( i = 0; i != 20; ++i )
      v76[i] = (unsigned __int32)v77.m128i_i32[(unsigned int)i >> 2] >> (8 * (~(_BYTE)i & 3));
    if ( *(_QWORD *)v76 ^ 0x1DE2CBDE7BC66278LL | *(_QWORD *)&v76[8] ^ 0x2743E32C08CE691DLL
      || *(_DWORD *)&v76[16] != 0x5EEDC6E1 )
    {
      sub_14005AF70(
        9,
        "Error opening image %s.\n"
        "To comply with international anti-piracy laws, hxp locked down this emulator. Your flag is in another castle. Much sad.",
        a1);
      return 0;
    }
```

Digging a bit more, we find familiar-looking pieces of code and data (for example `sub_14076D050`, `xmmword_14106A8B0`, state initialization at `loc_14076FF98`, …) that we quickly recognize as a SHA-1 implementation. Making an educated guess that the SHA1 input is probably the loaded ROM file, and converting the magic constants to a proper hash

```
    >>> struct.pack("<QQI", 0x1DE2CBDE7BC66278, 0x2743E32C08CE691D, 0x5EEDC6E1).hex()
    '7862c67bdecbe21d1d69ce082ce34327e1c6ed5e'
```

a quick internet research reveals that the check can be satisfied by loading a copy of Pokemon Leafgreen (Revision 1). This is a game for which source code has been almost fully restored by the [pret project](https://github.com/pret/pokefirered), which obviously simplifies our reversing efforts substantially.

### Emulator Patches to the Game

To understand what happens inside the emulator when loading the correct ROM file, we inspect the function with the lockdown error code (`sub_14076FED0`) a bit more. The prologue makes use of some global variables:

```
    __int64 __fastcall sub_14076FED0(const char *a1)
    {
      // [ local variable declarations removed for brevity ]
      dword_140EB1C08 = 0x2000000;
      if ( unk_1418689A8 )
        sub_14076CF30();
      dword_1414656D0 = 0;
      unk_1418689A8 = malloc(0x2000000);
      v2 = unk_1418689A8;
      if ( !unk_1418689A8 )
      {
        sub_14005AF70(41, "Failed to allocate memory for %s", "ROM");
        return 0;
      }
      v3 = calloc(1, 0x40000);
      unk_141868998 = v3;
      if ( !v3 )
      {
        sub_14005AF70(41, "Failed to allocate memory for %s", "WRAM");
        return 0;
      }
      if ( unk_140EAE240 )
        v2 = v3;
```

We can recover meaningful names surprisingly easily by compiling a copy of the Visual Boy Advance source code and comparing the debugging-symbols-enhanced binary to the challenge binary (this also works well when comparing across operating system versions). Finding the right functions to match is again conveniently made possible by following string references (such as, for example, `"Error opening image %s"`). This way we are able to identify `sub_14076FED0` as `CPULoadRom`, and steal some rather useful global variable names (such as `g_rom`, and `g_workRAM`):

```
    __int64 __fastcall CPULoadRom(const char *file, __m128i a2)
    {
      // [ local variable declarations removed for brevity ]
    
      v384[1] = __readfsqword(0x28u);
      romSize = 0x2000000;
      if ( g_rom )
        CPUCleanUp();
      systemSaveUpdateCounter = 0;
      g_rom = (uint8_t *)malloc(0x2000000);
      v4 = g_rom;
      if ( !g_rom )
      {
        systemMessage(41, "Failed to allocate memory for %s", "ROM");
        return 0;
      }
      g_workRAM = (voidp)calloc(1, 0x40000);
      v5 = (uint8_t *)g_workRAM;
      if ( !g_workRAM )
      {
        systemMessage(41, "Failed to allocate memory for %s", "WRAM");
        return 0;
      }
      if ( !coreOptions )
        v5 = v4;
```

With this information available, it becomes immediately clear that the code triggered after loading the right ROM performs some interesting updates to the game:

```
    v33 = _mm_loadu_si128((const __m128i *)&xmmword_14106A8D0);
    *(_BYTE *)(g_rom_ptr + 186238) = 3;
    *(_BYTE *)(g_rom_ptr + 522804) = -108;
    *(_WORD *)(g_rom_ptr + 1441752) = -30584;
    *(__m128i *)(g_rom_ptr + 4183584) = v33;
    v34 = _mm_loadu_si128((const __m128i *)&xmmword_14106A8F0);
    *(_WORD *)(g_rom_ptr + 3860764) = 3632;
    *(__m128i *)(g_rom_ptr + 4294298) = v34;
    v35 = _mm_loadu_si128((const __m128i *)&xmmword_14106A920);
    *(_QWORD *)(g_rom_ptr + 4183600) = 0xC6BBBC00CCBFCECDuLL;
    *(__m128i *)(g_rom_ptr + 4490381) = v35;
    *(_WORD *)(g_rom_ptr + 4183608) = -21562;
    *(_BYTE *)(g_rom_ptr + 1441754) = -21;
    *(_DWORD *)(g_rom_ptr + 4294314) = -1378101792;
    *(_BYTE *)(g_rom_ptr + 3860760) = 2;
    *(_QWORD *)(g_rom_ptr + 4295006) = 0xCAC1BBC6C0BCC3C1uLL;
    *(_BYTE *)(g_rom_ptr + 3860766) = -21;
    *(_DWORD *)(g_rom_ptr + 4295014) = -843333690;
    *(_BYTE *)(g_rom_ptr + 4183610) = -1;
    *(_DWORD *)(g_rom_ptr + 4490397) = -603925248;
    *(_BYTE *)(g_rom_ptr + 4294318) = -1;
    *(_WORD *)(g_rom_ptr + 4490401) = -6932;
    *(_QWORD *)(g_rom_ptr + 4490404) = 0xA5A3A1A300C0CEBDuLL;
    v36 = _mm_loadu_si128((const __m128i *)&xmmword_14106A950);
    *(_BYTE *)(g_rom_ptr + 4490418) = -1;
    *(_DWORD *)(g_rom_ptr + 4490412) = -706684416;
    *(__m128i *)(g_rom_ptr + 15404592) = v36;
    v37 = _mm_loadu_si128((const __m128i *)&xmmword_14106A960);
    *(_WORD *)(g_rom_ptr + 4490416) = -21029;
    *(__m128i *)(g_rom_ptr + 15404608) = v37;
    v38 = _mm_loadu_si128((const __m128i *)&xmmword_14106A990);
    *(_QWORD *)(g_rom_ptr + 15404624) = 2051;
    *(__m128i *)(g_rom_ptr + 15404647) = v38;
    v39 = _mm_loadu_si128((const __m128i *)&xmmword_14106A9A0);
    *(_DWORD *)(g_rom_ptr + 15404632) = 149622368;
    *(__m128i *)(g_rom_ptr + 15404663) = v39;
    v40 = _mm_loadu_si128((const __m128i *)&xmmword_14106A9B0);
    *(_WORD *)(g_rom_ptr + 15404636) = 774;
    *(__m128i *)(g_rom_ptr + 15404679) = v40;
    v41 = _mm_loadu_si128((const __m128i *)&xmmword_14106A9D0);
    *(_DWORD *)(g_rom_ptr + 15404640) = 17904489;
    *(__m128i *)(g_rom_ptr + 15405056) = v41;
    v42 = _mm_loadu_si128((const __m128i *)&unk_14106A9E0);
    *(_WORD *)(g_rom_ptr + 15404644) = 20224;
    *(__m128i *)(g_rom_ptr + 15405072) = v42;
    v43 = _mm_loadu_si128((const __m128i *)&xmmword_14106A9F0);
    *(_DWORD *)(g_rom_ptr + 15404695) = 33605669;
    *(__m128i *)(g_rom_ptr + 15405088) = v43;
    v44 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA00);
    *(_BYTE *)(g_rom_ptr + 15405106) = 8;
    *(__m128i *)(g_rom_ptr + 15405120) = v44;
    v45 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA10);
    *(_WORD *)(g_rom_ptr + 15405104) = 6802;
    *(__m128i *)(g_rom_ptr + 15405136) = v45;
    v46 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA20);
    *(_WORD *)(g_rom_ptr + 15405200) = -21017;
    *(__m128i *)(g_rom_ptr + 15405152) = v46;
    v47 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA30);
    *(_QWORD *)(g_rom_ptr + 15435944) = 0xA00000113A03000LL;
    *(__m128i *)(g_rom_ptr + 15405168) = v47;
    v48 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA40);
    *(_DWORD *)(g_rom_ptr + 15435952) = -507432784;
    *(__m128i *)(g_rom_ptr + 15405184) = v48;
    v49 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA60);
    *(_DWORD *)(g_rom_ptr + 15435974) = 805364048;
    *(__m128i *)(g_rom_ptr + 15435912) = v49;
    v50 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA70);
    *(_WORD *)(g_rom_ptr + 15435978) = 5024;
    *(__m128i *)(g_rom_ptr + 15435928) = v50;
    v51 = _mm_loadu_si128((const __m128i *)&xmmword_14106AA90);
    *(_BYTE *)(g_rom_ptr + 15435956) = 30;
    *(__m128i *)(g_rom_ptr + 15435958) = v51;
    v52 = _mm_loadu_si128((const __m128i *)&xmmword_14106AAB0);
    *(_BYTE *)(g_rom_ptr + 15435980) = -9;
    *(__m128i *)(g_rom_ptr + 15435983) = v52;
    v53 = g_rom;
    v54 = _mm_loadu_si128((const __m128i *)&xmmword_14106AAD0);
    *(_BYTE *)(g_rom_ptr + 15436063) = 0;
    *(_DWORD *)(g_rom_ptr + 15435999) = -1607466783;
    *(__m128i *)(g_rom_ptr + 15436007) = v54;
    v55 = _mm_loadu_si128((const __m128i *)&xmmword_14106AAF0);
    *(_WORD *)(g_rom_ptr + 15436003) = -3821;
    *(__m128i *)(g_rom_ptr + 15436035) = v55;
    *(_QWORD *)(g_rom_ptr + 15436023) = unk_14106AAE0;
    *(_WORD *)(g_rom_ptr + 15436031) = -5613;
    *(_QWORD *)(g_rom_ptr + 15436051) = 0x1E1B00000A0200LL;
    *(_DWORD *)(g_rom_ptr + 15436059) = 1259264;
```

Taking a binary diff of the original ROM and bytes of the game when running inside the emulator, we see that the following patches are applied:

```
    0x0802d77e 0x04 -> 0x03
    0x0807fa34 0x85 -> 0x94
    0x0815ffd8 0xa9 -> 0x88
    0x0815ffd9 0xad -> 0x88
    0x0815ffda 0x0c -> 0xeb
    0x083ae918 0x01 -> 0x02
    0x083ae91c 0xcc -> 0x30
    0x083ae91d 0xe8 -> 0x0e
    0x083ae91e 0x3a -> 0xeb
    0x083fd620 0xc3 -> 0xdc
    0x083fd621 0xe8 -> 0xec
    0x083fd622 0x00 -> 0xe4
    0x083fd623 0xeb -> 0x00
    0x083fd624 0xd5 -> 0xd6
    0x083fd625 0xe7 -> 0xe3
    0x083fd626 0x00 -> 0xe6
    0x083fd627 0xe7 -> 0xdf
    0x083fd628 0xe3 -> 0xd9
    0x083fd629 0x00 -> 0xd8
    0x083fd62a 0xd7 -> 0x00
    0x083fd62b 0xe0 -> 0xe1
    0x083fd62c 0xe3 -> 0xed
    0x083fd62d 0xe7 -> 0x00
    0x083fd62e 0xd9 -> 0xc7
    0x083fd62f 0xb8 -> 0xbb
    0x083fd630 0x00 -> 0xcd
    0x083fd631 0xe8 -> 0xce
    0x083fd632 0xe3 -> 0xbf
    0x083fd633 0xe3 -> 0xcc
    0x083fd634 0xab -> 0x00
    0x083fd635 0xff -> 0xbc
    0x083fd636 0x26 -> 0xbb
    0x083fd637 0x09 -> 0xc6
    0x083fd638 0x27 -> 0xc6
    0x083fd639 0x2a -> 0xab
    0x083fd63a 0x10 -> 0xff
    0x0841869a 0xd5 -> 0xe8
    0x0841869b 0xe2 -> 0xe3
    0x0841869c 0xd8 -> 0x00
    0x0841869d 0x00 -> 0xeb
    0x0841869e 0xda -> 0xdd
    0x0841869f 0xdd -> 0xe2
    0x084186a0 0xe0 -> 0x00
    0x084186a1 0xe0 -> 0xd5
    0x084186a2 0x00 -> 0xe2
    0x084186a3 0xe3 -> 0x00
    0x084186a4 0xe9 -> 0xd9
    0x084186a5 0xe8 -> 0xd5
    0x084186a6 0x00 -> 0xe7
    0x084186a7 0xe8 -> 0xed
    0x084186a8 0xdc -> 0x00
    0x084186a9 0xd9 -> 0xda
    0x084186aa 0x00 -> 0xe0
    0x084186ab 0xe5 -> 0xd5
    0x084186ac 0xe9 -> 0xdb
    0x084186ad 0xd9 -> 0xad
    0x084186ae 0xe7 -> 0xff
    0x0841895e 0xcb -> 0xc1
    0x0841895f 0xcf -> 0xc3
    0x08418960 0xbf -> 0xbc
    0x08418961 0xcd -> 0xc0
    0x08418962 0xce -> 0xc6
    0x08418963 0xc3 -> 0xbb
    0x08418964 0xc9 -> 0xc1
    0x08418965 0xc8 -> 0xca
    0x08418966 0xc8 -> 0xc6
    0x08418967 0xbb -> 0xbf
    0x08418968 0xc3 -> 0xbb
    0x08418969 0xcc -> 0xcd
    0x0844848d 0xc9 -> 0xc3
    0x0844848e 0xe2 -> 0xe8
    0x0844848f 0xe0 -> 0x00
    0x08448490 0xed -> 0xe7
    0x08448491 0x00 -> 0xd9
    0x08448492 0xd5 -> 0xd9
    0x08448493 0x00 -> 0xe1
    0x08448494 0xda -> 0xe7
    0x08448495 0xd9 -> 0x00
    0x08448496 0xeb -> 0xe8
    0x08448497 0x00 -> 0xe3
    0x08448498 0xe4 -> 0xfe
    0x08448499 0xd9 -> 0xdf
    0x0844849a 0xe3 -> 0xe2
    0x0844849b 0xe4 -> 0xe3
    0x0844849c 0xe0 -> 0xeb
    0x0844849d 0xd9 -> 0x00
    0x0844849e 0xfe -> 0xd5
    0x0844849f 0xdc -> 0x00
    0x084484a0 0xd5 -> 0xdc
    0x084484a1 0xea -> 0xec
    0x084484a2 0xd9 -> 0xe4
    0x084484a4 0xe7 -> 0xbd
    0x084484a5 0xd9 -> 0xce
    0x084484a6 0xd9 -> 0xc0
    0x084484a7 0xe2 -> 0x00
    0x084484a8 0x00 -> 0xa3
    0x084484a9 0xdd -> 0xa1
    0x084484aa 0xe8 -> 0xa3
    0x084484ab 0x00 -> 0xa5
    0x084484ac 0xeb -> 0x00
    0x084484ad 0xe3 -> 0xda
    0x084484ae 0xe6 -> 0xe0
    0x084484af 0xe0 -> 0xd5
    0x084484b0 0xd8 -> 0xdb
    0x084484b1 0xeb -> 0xad
    0x084484b2 0xdd -> 0xff
    0x08eb0e30 0xff -> 0x01
    0x08eb0e31 0xff -> 0x97
    0x08eb0e32 0xff -> 0x00
    0x08eb0e33 0xff -> 0x00
    0x08eb0e34 0xff -> 0x1e
    0x08eb0e35 0xff -> 0x00
    0x08eb0e36 0xff -> 0x10
    0x08eb0e37 0xff -> 0x00
    0x08eb0e38 0xff -> 0x01
    0x08eb0e39 0xff -> 0x08
    0x08eb0e3a 0xff -> 0x11
    0x08eb0e3b 0xff -> 0x00
    0x08eb0e3c 0xff -> 0x00
    0x08eb0e3d 0xff -> 0x00
    0x08eb0e3e 0xff -> 0x00
    0x08eb0e3f 0xff -> 0x00
    0x08eb0e40 0xff -> 0x00
    0x08eb0e41 0xff -> 0x00
    0x08eb0e42 0xff -> 0x00
    0x08eb0e43 0xff -> 0x00
    0x08eb0e44 0xff -> 0x87
    0x08eb0e45 0xff -> 0x00
    0x08eb0e46 0xff -> 0x00
    0x08eb0e47 0xff -> 0x00
    0x08eb0e48 0xff -> 0x02
    0x08eb0e49 0xff -> 0x8c
    0x08eb0e4a 0xff -> 0x00
    0x08eb0e4b 0xff -> 0x00
    0x08eb0e4c 0xff -> 0x3a
    0x08eb0e4d 0xff -> 0x00
    0x08eb0e4e 0xff -> 0x02
    0x08eb0e4f 0xff -> 0x00
    0x08eb0e50 0xff -> 0x03
    0x08eb0e51 0xff -> 0x08
    0x08eb0e52 0xff -> 0x00
    0x08eb0e53 0xff -> 0x00
    0x08eb0e54 0xff -> 0x00
    0x08eb0e55 0xff -> 0x00
    0x08eb0e56 0xff -> 0x00
    0x08eb0e57 0xff -> 0x00
    0x08eb0e58 0xff -> 0x60
    0x08eb0e59 0xff -> 0x0e
    0x08eb0e5a 0xff -> 0xeb
    0x08eb0e5b 0xff -> 0x08
    0x08eb0e5c 0xff -> 0x06
    0x08eb0e5d 0xff -> 0x03
    0x08eb0e60 0xff -> 0x69
    0x08eb0e61 0xff -> 0x33
    0x08eb0e62 0xff -> 0x11
    0x08eb0e63 0xff -> 0x01
    0x08eb0e64 0xff -> 0x00
    0x08eb0e65 0xff -> 0x4f
    0x08eb0e67 0xff -> 0x00
    0x08eb0e68 0xff -> 0x2f
    0x08eb0e69 0xff -> 0x76
    0x08eb0e6a 0xff -> 0x1a
    0x08eb0e6b 0xff -> 0x08
    0x08eb0e6c 0xff -> 0x51
    0x08eb0e6d 0xff -> 0x00
    0x08eb0e6e 0xff -> 0x00
    0x08eb0e6f 0xff -> 0x28
    0x08eb0e70 0xff -> 0x6f
    0x08eb0e71 0xff -> 0x00
    0x08eb0e72 0xff -> 0x16
    0x08eb0e73 0xff -> 0x04
    0x08eb0e74 0xff -> 0x80
    0x08eb0e75 0xff -> 0x0e
    0x08eb0e76 0xff -> 0x00
    0x08eb0e77 0xff -> 0x97
    0x08eb0e78 0xff -> 0x01
    0x08eb0e79 0xff -> 0x25
    0x08eb0e7a 0xff -> 0x5f
    0x08eb0e7b 0xff -> 0x00
    0x08eb0e7c 0xff -> 0x97
    0x08eb0e7d 0xff -> 0x00
    0x08eb0e7e 0xff -> 0x37
    0x08eb0e7f 0xff -> 0x00
    0x08eb0e80 0xff -> 0x25
    0x08eb0e81 0xff -> 0x89
    0x08eb0e82 0xff -> 0x00
    0x08eb0e83 0xff -> 0x00
    0x08eb0e84 0xff -> 0x00
    0x08eb0e85 0xff -> 0x21
    0x08eb0e86 0xff -> 0x07
    0x08eb0e87 0xff -> 0x80
    0x08eb0e88 0xff -> 0x37
    0x08eb0e89 0xff -> 0x13
    0x08eb0e8a 0xff -> 0x06
    0x08eb0e8b 0xff -> 0x01
    0x08eb0e8c 0xff -> 0x00
    0x08eb0e8d 0xff -> 0x10
    0x08eb0e8e 0xff -> 0xeb
    0x08eb0e8f 0xff -> 0x08
    0x08eb0e90 0xff -> 0x6b
    0x08eb0e91 0xff -> 0x2f
    0x08eb0e92 0xff -> 0x0e
    0x08eb0e93 0xff -> 0x00
    0x08eb0e94 0xff -> 0x30
    0x08eb0e95 0xff -> 0x97
    0x08eb0e96 0xff -> 0x01
    0x08eb0e97 0xff -> 0x25
    0x08eb0e98 0xff -> 0xc8
    0x08eb0e99 0xff -> 0x00
    0x08eb0e9a 0xff -> 0x02
    0x08eb1000 0xff -> 0x5a
    0x08eb1001 0xff -> 0xb6
    0x08eb1002 0xff -> 0x97
    0x08eb1003 0xff -> 0x00
    0x08eb1004 0xff -> 0x64
    0x08eb1005 0xff -> 0x01
    0x08eb1006 0xff -> 0x00
    0x08eb1007 0xff -> 0x30
    0x08eb1008 0xff -> 0xa1
    0x08eb1009 0xff -> 0x97
    0x08eb100a 0xff -> 0x00
    0x08eb100b 0xff -> 0x02
    0x08eb100c 0xff -> 0x00
    0x08eb100d 0xff -> 0xc5
    0x08eb100e 0xff -> 0x28
    0x08eb100f 0xff -> 0x6f
    0x08eb1010 0xff -> 0x00
    0x08eb1011 0xff -> 0x29
    0x08eb1012 0xff -> 0x07
    0x08eb1013 0xff -> 0x08
    0x08eb1014 0xff -> 0x25
    0x08eb1015 0xff -> 0x38
    0x08eb1016 0xff -> 0x01
    0x08eb1017 0xff -> 0x27
    0x08eb1018 0xff -> 0x2a
    0x08eb1019 0xff -> 0x07
    0x08eb101a 0xff -> 0x08
    0x08eb101b 0xff -> 0x29
    0x08eb101c 0xff -> 0x06
    0x08eb101d 0xff -> 0x03
    0x08eb101e 0xff -> 0x26
    0x08eb101f 0xff -> 0x0d
    0x08eb1020 0xff -> 0x80
    0x08eb1021 0xff -> 0xb4
    0x08eb1022 0xff -> 0x00
    0x08eb1023 0xff -> 0x21
    0x08eb1024 0xff -> 0x0d
    0x08eb1025 0xff -> 0x80
    0x08eb1026 0xff -> 0x07
    0x08eb1027 0xff -> 0x00
    0x08eb1028 0xff -> 0x06
    0x08eb1029 0xff -> 0x01
    0x08eb102a 0xff -> 0x40
    0x08eb102b 0xff -> 0x10
    0x08eb102c 0xff -> 0xeb
    0x08eb102d 0xff -> 0x08
    0x08eb102e 0xff -> 0x05
    0x08eb102f 0xff -> 0x81
    0x08eb1030 0xff -> 0x92
    0x08eb1031 0xff -> 0x1a
    0x08eb1032 0xff -> 0x08
    0x08eb1040 0xff -> 0x67
    0x08eb1041 0xff -> 0x58
    0x08eb1042 0xff -> 0x10
    0x08eb1043 0xff -> 0xeb
    0x08eb1044 0xff -> 0x08
    0x08eb1045 0xff -> 0x31
    0x08eb1046 0xff -> 0x03
    0x08eb1047 0xff -> 0x01
    0x08eb1048 0xff -> 0x32
    0x08eb1049 0xff -> 0x66
    0x08eb104a 0xff -> 0x6d
    0x08eb104b 0xff -> 0x68
    0x08eb104c 0xff -> 0x05
    0x08eb104d 0xff -> 0x81
    0x08eb104e 0xff -> 0x92
    0x08eb104f 0xff -> 0x1a
    0x08eb1050 0xff -> 0x08
    0x08eb1051 0xff -> 0x02
    0x08eb1052 0xff -> 0x02
    0x08eb1053 0xff -> 0x02
    0x08eb1054 0xff -> 0x02
    0x08eb1055 0xff -> 0x02
    0x08eb1056 0xff -> 0x02
    0x08eb1057 0xff -> 0x02
    0x08eb1058 0xff -> 0xce
    0x08eb1059 0xff -> 0xdc
    0x08eb105a 0xff -> 0xdd
    0x08eb105b 0xff -> 0xe7
    0x08eb105c 0xff -> 0x00
    0x08eb105d 0xff -> 0xd7
    0x08eb105e 0xff -> 0xd5
    0x08eb105f 0xff -> 0xe2
    0x08eb1060 0xff -> 0xe2
    0x08eb1061 0xff -> 0xe3
    0x08eb1062 0xff -> 0xe8
    0x08eb1063 0xff -> 0x00
    0x08eb1064 0xff -> 0xd6
    0x08eb1065 0xff -> 0xd9
    0x08eb1066 0xff -> 0x00
    0x08eb1067 0xff -> 0xe1
    0x08eb1068 0xff -> 0xed
    0x08eb1069 0xff -> 0x00
    0x08eb106a 0xff -> 0xd8
    0x08eb106b 0xff -> 0xd9
    0x08eb106c 0xff -> 0xe7
    0x08eb106d 0xff -> 0xe8
    0x08eb106e 0xff -> 0xdd
    0x08eb106f 0xff -> 0xe2
    0x08eb1070 0xff -> 0xed
    0x08eb1071 0xff -> 0xad
    0x08eb1072 0xff -> 0xfe
    0x08eb1073 0xff -> 0xc8
    0x08eb1074 0xff -> 0xe3
    0x08eb1075 0xff -> 0xeb
    0x08eb1076 0xff -> 0x00
    0x08eb1077 0xff -> 0xe8
    0x08eb1078 0xff -> 0xdc
    0x08eb1079 0xff -> 0xd9
    0x08eb107a 0xff -> 0x00
    0x08eb107b 0xff -> 0xe7
    0x08eb107c 0xff -> 0xd9
    0x08eb107d 0xff -> 0xe6
    0x08eb107e 0xff -> 0xdd
    0x08eb107f 0xff -> 0xe3
    0x08eb1080 0xff -> 0xe9
    0x08eb1081 0xff -> 0xe7
    0x08eb1082 0xff -> 0x00
    0x08eb1083 0xff -> 0xe8
    0x08eb1084 0xff -> 0xd9
    0x08eb1085 0xff -> 0xe7
    0x08eb1086 0xff -> 0xe8
    0x08eb1087 0xff -> 0xdd
    0x08eb1088 0xff -> 0xe2
    0x08eb1089 0xff -> 0xdb
    0x08eb108a 0xff -> 0x00
    0x08eb108b 0xff -> 0xd6
    0x08eb108c 0xff -> 0xd9
    0x08eb108d 0xff -> 0xdb
    0x08eb108e 0xff -> 0xdd
    0x08eb108f 0xff -> 0xe2
    0x08eb1090 0xff -> 0xe7
    0x08eb1091 0xff -> 0xad
    0x08eb8888 0xff -> 0x74
    0x08eb8889 0xff -> 0x30
    0x08eb888a 0xff -> 0x9f
    0x08eb888b 0xff -> 0xe5
    0x08eb888c 0xff -> 0x7c
    0x08eb888d 0xff -> 0x1d
    0x08eb888e 0xff -> 0x93
    0x08eb888f 0xff -> 0xe5
    0x08eb8890 0xff -> 0x70
    0x08eb8891 0xff -> 0x30
    0x08eb8892 0xff -> 0x9f
    0x08eb8893 0xff -> 0xe5
    0x08eb8894 0xff -> 0x08
    0x08eb8895 0xff -> 0x20
    0x08eb8896 0xff -> 0x93
    0x08eb8897 0xff -> 0xe5
    0x08eb8898 0xff -> 0xd1
    0x08eb8899 0xff -> 0x3d
    0x08eb889a 0xff -> 0x82
    0x08eb889b 0xff -> 0xe2
    0x08eb889c 0xff -> 0xb8
    0x08eb889d 0xff -> 0x01
    0x08eb889e 0xff -> 0xd3
    0x08eb889f 0xff -> 0xe1
    0x08eb88a0 0xff -> 0x64
    0x08eb88a1 0xff -> 0x30
    0x08eb88a2 0xff -> 0x9f
    0x08eb88a3 0xff -> 0xe5
    0x08eb88a4 0xff -> 0x03
    0x08eb88a5 0xff -> 0x00
    0x08eb88a6 0xff -> 0x50
    0x08eb88a7 0xff -> 0xe1
    0x08eb88a8 0xff -> 0x00
    0x08eb88a9 0xff -> 0x30
    0x08eb88aa 0xff -> 0xa0
    0x08eb88ab 0xff -> 0x13
    0x08eb88ac 0xff -> 0x01
    0x08eb88ad 0xff -> 0x00
    0x08eb88ae 0xff -> 0x00
    0x08eb88af 0xff -> 0x0a
    0x08eb88b0 0xff -> 0xb0
    0x08eb88b1 0xff -> 0x30
    0x08eb88b2 0xff -> 0xc1
    0x08eb88b3 0xff -> 0xe1
    0x08eb88b4 0xff -> 0x1e
    0x08eb88b6 0xff -> 0x2f
    0x08eb88b7 0xff -> 0xe1
    0x08eb88b8 0xff -> 0xd1
    0x08eb88b9 0xff -> 0x3d
    0x08eb88ba 0xff -> 0x82
    0x08eb88bb 0xff -> 0xe2
    0x08eb88bc 0xff -> 0xba
    0x08eb88bd 0xff -> 0x01
    0x08eb88be 0xff -> 0xd3
    0x08eb88bf 0xff -> 0xe1
    0x08eb88c0 0xff -> 0x48
    0x08eb88c1 0xff -> 0x30
    0x08eb88c2 0xff -> 0x9f
    0x08eb88c3 0xff -> 0xe5
    0x08eb88c4 0xff -> 0x03
    0x08eb88c5 0xff -> 0x00
    0x08eb88c6 0xff -> 0x50
    0x08eb88c7 0xff -> 0xe1
    0x08eb88c8 0xff -> 0x00
    0x08eb88c9 0xff -> 0x30
    0x08eb88ca 0xff -> 0xa0
    0x08eb88cb 0xff -> 0x13
    0x08eb88cc 0xff -> 0xf7
    0x08eb88cf 0xff -> 0x1a
    0x08eb88d0 0xff -> 0xd1
    0x08eb88d1 0xff -> 0x3d
    0x08eb88d2 0xff -> 0x82
    0x08eb88d3 0xff -> 0xe2
    0x08eb88d4 0xff -> 0xbc
    0x08eb88d5 0xff -> 0x01
    0x08eb88d6 0xff -> 0xd3
    0x08eb88d7 0xff -> 0xe1
    0x08eb88d8 0xff -> 0x34
    0x08eb88d9 0xff -> 0x30
    0x08eb88da 0xff -> 0x9f
    0x08eb88db 0xff -> 0xe5
    0x08eb88dc 0xff -> 0x03
    0x08eb88dd 0xff -> 0x00
    0x08eb88de 0xff -> 0x50
    0x08eb88df 0xff -> 0xe1
    0x08eb88e0 0xff -> 0x00
    0x08eb88e1 0xff -> 0x30
    0x08eb88e2 0xff -> 0xa0
    0x08eb88e3 0xff -> 0x13
    0x08eb88e4 0xff -> 0xf1
    0x08eb88e7 0xff -> 0x1a
    0x08eb88e8 0xff -> 0xd1
    0x08eb88e9 0xff -> 0x2d
    0x08eb88ea 0xff -> 0x82
    0x08eb88eb 0xff -> 0xe2
    0x08eb88ec 0xff -> 0xbe
    0x08eb88ed 0xff -> 0x01
    0x08eb88ee 0xff -> 0xd2
    0x08eb88ef 0xff -> 0xe1
    0x08eb88f0 0xff -> 0x20
    0x08eb88f1 0xff -> 0x20
    0x08eb88f2 0xff -> 0x9f
    0x08eb88f3 0xff -> 0xe5
    0x08eb88f4 0xff -> 0x20
    0x08eb88f5 0xff -> 0x30
    0x08eb88f6 0xff -> 0x9f
    0x08eb88f7 0xff -> 0xe5
    0x08eb88f8 0xff -> 0x02
    0x08eb88f9 0xff -> 0x00
    0x08eb88fa 0xff -> 0x50
    0x08eb88fb 0xff -> 0xe1
    0x08eb88fc 0xff -> 0x00
    0x08eb88fd 0xff -> 0x30
    0x08eb88fe 0xff -> 0xa0
    0x08eb88ff 0xff -> 0x13
    0x08eb8900 0xff -> 0xea
    0x08eb8903 0xff -> 0xea
    0x08eb8904 0xff -> 0x00
    0x08eb8905 0xff -> 0xf0
    0x08eb8906 0xff -> 0x15
    0x08eb8907 0xff -> 0x08
    0x08eb8908 0xff -> 0x00
    0x08eb8909 0xff -> 0x50
    0x08eb890a 0xff -> 0x00
    0x08eb890b 0xff -> 0x03
    0x08eb890c 0xff -> 0x1e
    0x08eb890d 0xff -> 0x12
    0x08eb890e 0xff -> 0x00
    0x08eb890f 0xff -> 0x00
    0x08eb8910 0xff -> 0x03
    0x08eb8911 0xff -> 0x16
    0x08eb8912 0xff -> 0x00
    0x08eb8913 0xff -> 0x00
    0x08eb8914 0xff -> 0x02
    0x08eb8915 0xff -> 0x0a
    0x08eb8916 0xff -> 0x00
    0x08eb8917 0xff -> 0x00
    0x08eb8918 0xff -> 0x1b
    0x08eb8919 0xff -> 0x1e
    0x08eb891a 0xff -> 0x00
    0x08eb891b 0xff -> 0x00
    0x08eb891c 0xff -> 0x37
    0x08eb891d 0xff -> 0x13
    0x08eb891e 0xff -> 0x00
    0x08eb891f 0xff -> 0x00
```

While this list looks intimidating at first, the general intent becomes clear when taking the patched addresses, grouping them into consecutive runs, and looking up the closest preceding symbol in the ROM produced from the [PRET sources](https://github.com/pret/pokefirered):

```
    0x0802d448 Cmd_handleballthrow
    0x0802d77e 0x04 -> 0x03
    
    0x0807f9c0 StartLegendaryBattle
    0x0807fa34 0x85 -> 0x94
    
    0x0815fdb4 gSpecials
    0x0815ffd8 0xa9 -> 0x88
    0x0815ffd9 0xad -> 0x88
    0x0815ffda 0x0c -> 0xeb
    0x0815ffdb 0x08 == 0x08
    
    0x083ae918 SSAnne_Exterior_MapEvents
    0x083ae918 0x01 -> 0x02
    0x083ae91c 0xcc -> 0x30
    0x083ae91d 0xe8 -> 0x0e
    0x083ae91e 0x3a -> 0xeb
    0x083ae91f 0x08 == 0x08
    
    0x083fd619 sText_ShootSoClose
    0x083fd620 0xc3 -> 0xdc
    0x083fd621 0xe8 -> 0xec
    [ ... snip ... ]
    0x083fd637 0x09 -> 0xc6
    0x083fd638 0x27 -> 0xc6
    0x083fd63a 0x10 -> 0xff
    
    0x0841869a gText_AndFillOutTheQuestionnaire
    0x0841869a 0xd5 -> 0xe8
    0x0841869b 0xe2 -> 0xe3
    [ ... snip ... ]
    0x084186ac 0xe9 -> 0xdb
    0x084186ad 0xd9 -> 0xad
    0x084186ae 0xe7 -> 0xff
    
    0x0841895e gText_Questionnaire
    0x0841895e 0xcb -> 0xc1
    0x0841895f 0xcf -> 0xc3
    [ ... snip ... ]
    0x08418967 0xbb -> 0xbf
    0x08418968 0xc3 -> 0xbb
    0x08418969 0xcc -> 0xcd
    
    0x0844844f gMewPokedexText
    0x0844848d 0xc9 -> 0xc3
    0x0844848e 0xe2 -> 0xe8
    [ ... snip ... ]
    0x084484b0 0xd8 -> 0xdb
    0x084484b1 0xeb -> 0xad
    0x084484b2 0xdd -> 0xff
    
    [ ... all subsequent accesses removed as they target "empty" parts of the ROM ]
```

`SSAnneExterior_MapEvents`, I wonder …?

And indeed, firing up the emulator, loading a suitable savegame and checking the surroundings of S.S. Anne shows that there’s a Mew sitting right next to the truck, waiting for us:

![mew waiting for the player to approach it](https://hxp.io/assets/data/posts/119-yasashiimon/mew.png)

When approaching Mew, it asks us for a password via the game’s built-in easychat questionnaire dialog:

![find password to get a flag](https://hxp.io/assets/data/posts/119-yasashiimon/gibflag.png)

### Analyzing the Patches

To find the password, we have to analyze the ROM patches a bit more. Starting from the topmost entry point that we found earlier, this is what the map events of a regular ROM look like:

```
    .rodata:083AE918 SSAnne_Exterior_MapEvents DCB    1      ; DATA XREF: .rodata:0834F2D8↑o
    .rodata:083AE919                 DCB    5
    .rodata:083AE91A                 DCB    0
    .rodata:083AE91B                 DCB    1
    .rodata:083AE91C                 DCD SSAnne_Exterior_ObjectEvents
    .rodata:083AE920                 DCD SSAnne_Exterior_MapWarps
    .rodata:083AE924                 DCD 0
    .rodata:083AE928                 DCD SSAnne_Exterior_MapBGEvents
```

And this is the same location in the patched ROM:

```
    ROM:083AE918 SSAnne_Exterior_MapEvents DCB 2         ; DATA XREF: ROM:0834F2D8↑o
    ROM:083AE919                 DCB    5
    ROM:083AE91A                 DCB    0
    ROM:083AE91B                 DCB    1
    ROM:083AE91C                 DCD unk_8EB0E30
    ROM:083AE920                 DCD SSAnne_Exterior_MapWarps
    ROM:083AE924                 DCD 0
    ROM:083AE928                 DCD SSAnne_Exterior_MapBGEvents
```

The corresponding `struct` definition is in [`include/global.fieldmap.h`](https://github.com/pret/pokefirered/blob/master/include/global.fieldmap.h):

```
    struct MapEvents
    {
        u8 objectEventCount;
        u8 warpCount;
        u8 coordEventCount;
        u8 bgEventCount;
        struct ObjectEventTemplate *objectEvents;
        struct WarpEvent *warps;
        struct CoordEvent *coordEvents;
        struct BgEvent *bgEvents;
    };
```

So we can see that the patch added an event to the map (probably the Mew NPC) and changed the `objectEents` pointer to point somewhere else. Lets examine the `objectEvents` in both versions.

Vanilla:

```
    .rodata:083AE8CC SSAnne_Exterior_ObjectEvents DCB 1                   ; localId
    .rodata:083AE8CC                                         ; DATA XREF: .rodata:083AE91C↓o
    .rodata:083AE8CD                 DCB 0x97                ; graphicsId
    .rodata:083AE8CE                 DCB 0                   ; kind
    .rodata:083AE8CF                 DCB 0
    .rodata:083AE8D0                 DCW 0x1E                ; x
    .rodata:083AE8D2                 DCW 0x10                ; y
    .rodata:083AE8D4                 DCB 1                   ; objUnion.normal.elevation
    .rodata:083AE8D5                 DCB 8                   ; objUnion.normal.movementType
    .rodata:083AE8D6.0               .bits(4) 1              ; objUnion.normal.movementRangeX
    .rodata:083AE8D6.4               .bits(4) 1              ; objUnion.normal.movementRangeY
    .rodata:083AE8D6.8               .bits(8) 0
    .rodata:083AE8D8                 DCW 0                   ; objUnion.normal.trainerType
    .rodata:083AE8DA                 DCW 0                   ; objUnion.normal.trainerRange_berryTreeId
    .rodata:083AE8DC                 DCD 0                   ; script
    .rodata:083AE8E0                 DCW 0x87                ; flagId
```

Patched:

```
    ROM:08EB0E30 stru_8EB0E30    DCB 1                   ; localId
    ROM:08EB0E30                                         ; DATA XREF: ROM:083AE91C↑o
    ROM:08EB0E31                 DCB 0x97                ; graphicsId
    ROM:08EB0E32                 DCB 0                   ; kind
    ROM:08EB0E33                 DCB 0
    ROM:08EB0E34                 DCW 0x1E                ; x
    ROM:08EB0E36                 DCW 0x10                ; y
    ROM:08EB0E38                 DCB 1                   ; objUnion.normal.elevation
    ROM:08EB0E39                 DCB 8                   ; objUnion.normal.movementType
    ROM:08EB0E3A.0               .bits(4) 1              ; objUnion.normal.movementRangeX
    ROM:08EB0E3A.4               .bits(4) 1              ; objUnion.normal.movementRangeY
    ROM:08EB0E3A.8               .bits(8) 0
    ROM:08EB0E3C                 DCW 0                   ; objUnion.normal.trainerType
    ROM:08EB0E3E                 DCW 0                   ; objUnion.normal.trainerRange_berryTreeId
    ROM:08EB0E40                 DCD 0                   ; script
    ROM:08EB0E44                 DCW 0x87                ; flagId
    ROM:08EB0E46                 DCB 0, 0
    ROM:08EB0E48                 DCB 2                   ; localId
    ROM:08EB0E49                 DCB 0x8C                ; graphicsId
    ROM:08EB0E4A                 DCB 0                   ; kind
    ROM:08EB0E4B                 DCB 0
    ROM:08EB0E4C                 DCW 0x3A                ; x
    ROM:08EB0E4E                 DCW 2                   ; y
    ROM:08EB0E50                 DCB 3                   ; objUnion.normal.elevation
    ROM:08EB0E51                 DCB 8                   ; objUnion.normal.movementType
    ROM:08EB0E52.0               .bits(4) 0              ; objUnion.normal.movementRangeX
    ROM:08EB0E52.4               .bits(4) 0              ; objUnion.normal.movementRangeY
    ROM:08EB0E52.8               .bits(8) 0
    ROM:08EB0E54                 DCW 0                   ; objUnion.normal.trainerType
    ROM:08EB0E56                 DCW 0                   ; objUnion.normal.trainerRange_berryTreeId
    ROM:08EB0E58                 DCD unk_8EB0E60         ; script
    ROM:08EB0E5C                 DCW 0x306               ; flagId
    ROM:08EB0E5E                 DCB 0xFF, 0xFF
```

We can see that the first object event was copied without modifications, and that a second entry was added. Of this second object, the most interesting field is the non-empty `script` member. Following this pointer we end up in data that is interpreted by the game’s internal scripting engine. In order to understand the script, we can look at [`data/script_cmd_table.inc`](https://github.com/pret/pokefirered/blob/master/data/script_cmd_table.inc) for the opcode numbers, and at the corresponding header implementations for the number and size of the operands. Since the script at hand is so short, manual disassembly is enough to roughly understand what is going on:

```
    ROM:08EB0E60 byte_8EB0E60    DCB 0x69           ; lockall
    ROM:08EB0E61                 DCB 0x33           ; playbgm, MUS_GAME_CORNER
    ROM:08EB0E62                 DCW 0x111
    ROM:08EB0E64                 DCB 0
    ROM:08EB0E65                 DCB 0x4F           ; applymovement OBJ_EVENT_ID_PLAYER, Common_Movement_ExclamationMark
    ROM:08EB0E66                 DCW 0xFF
    ROM:08EB0E68                 DCD Common_Movement_ExclamationMark
    ROM:08EB0E6C                 DCB 0x51           ; waitmovement 0
    ROM:08EB0E6D                 DCW 0
    ROM:08EB0E6F                 DCB 0x28           ; delay 111
    ROM:08EB0E70                 DCW 0x6F
    ROM:08EB0E72                 DCB 0x16           ; setar VAR8004, EASY_CHAT_TYPE_QUESTIONNAIRE
    ROM:08EB0E73                 DCW 0x8004
    ROM:08EB0E75                 DCW 0xE
    ROM:08EB0E77                 DCB 0x97           ; fadescreen FADE_TO_BLACK
    ROM:08EB0E78                 DCB 1
    ROM:08EB0E79                 DCB 0x25           ; callspecial ShowEasyChatScreen (0x5f)
    ROM:08EB0E7A                 DCW 0x5F
    ROM:08EB0E7C                 DCB 0x97           ; fadescreen FADE_FROM_BLACK
    ROM:08EB0E7D                 DCB 0
    ROM:08EB0E7E                 DCB 0x37           ; fadeoutbgm
    ROM:08EB0E7F                 DCB 0
    ROM:08EB0E80                 DCB 0x25           ; callspecial ??? (0x89)
    ROM:08EB0E81                 DCD 0x89
    ROM:08EB0E85                 DCB 0x21           ; compare VAR8007, 0x1337
    ROM:08EB0E86                 DCW 0x8007
    ROM:08EB0E88                 DCW 0x1337
    ROM:08EB0E8A                 DCB 6              ; goto_if 1, unk_8eb1000
    ROM:08EB0E8B                 DCB 1
    ROM:08EB0E8C                 DCD unk_8EB1000
    ROM:08EB0E90                 DCB 0x6B           ; releaseall
    ROM:08EB0E91                 DCB 0x2F           ; playse SE_SUPER_EFFECTIVE
    ROM:08EB0E92                 DCW 0xE
    ROM:08EB0E94                 DCB 0x30           ; waitse
    ROM:08EB0E95                 DCB 0x97           ; fadescreen FADE_TO_BLACK
    ROM:08EB0E96                 DCB 1
    ROM:08EB0E97                 DCB 0x25           ; callspecial faint (0xc8)
    ROM:08EB0E98                 DCW 0xC8
    ROM:08EB0E9A                 DCB 2              ; end
```

The scripts opens the questionnaire window, then calls special function with id 0x89. If that function sets `VAR8007` to `0x1337`, we continue script execution at address `0x8eb1000`, otherwise the iconic “it’s super effective” sound effect is played, the screen blacks out, and the game over screen is displayed.

Let’s continue analysis of the happy path at `0x8eb1000`:

```
    ROM:08EB1000 byte_8EB1000    DCB 0x5A           ; faceplayer
    ROM:08EB1001                 DCB 0xB6           ; setwildbattle SPECIES_MEW, 100, ITEM_MASTER_BALL
    ROM:08EB1002                 DCW 0x97
    ROM:08EB1004                 DCB 0x64
    ROM:08EB1005                 DCW 1
    ROM:08EB1007                 DCB 0x30           ; waitse
    ROM:08EB1008                 DCB 0xA1           ; playmoncry SPECIES_MEW, CRY_MODE_ENCOUNTER
    ROM:08EB1009                 DCW 0x97
    ROM:08EB100B                 DCW 2
    ROM:08EB100D                 DCB 0xC5           ; waitmoncry
    ROM:08EB100E                 DCB 0x28           ; delay 111
    ROM:08EB100F                 DCW 0x6F
    ROM:08EB1011                 DCB 0x29           ; setflag FLAG_SYS_SPECIAL_WILD_BATTLE
    ROM:08EB1012                 DCW 0x807
    ROM:08EB1014                 DCB 0x25           ; callspecial StartLegendaryBattle
    ROM:08EB1015                 DCW 0x138
    ROM:08EB1017                 DCB 0x27           ; waitstate
    ROM:08EB1018                 DCB 0x2A           ; clearflag FLAG_SYS_SPECIAL_WILD_BATTLE
    ROM:08EB1019                 DCW 0x807
    ROM:08EB101B                 DCB 0x29           ; setflag 0x306
    ROM:08EB101C                 DCW 0x306
    ROM:08EB101E                 DCB 0x26           ; specialvar VAR_RESULT, GetBattleOutcome
    ROM:08EB101F                 DCW 0x800D
    ROM:08EB1021                 DCW 0xB4
    ROM:08EB1023                 DCB 0x21           ; compare VAR_RESULT, B_OUTCOME_CAUGHT
    ROM:08EB1024                 DCW 0x800D
    ROM:08EB1026                 DCW 7
    ROM:08EB1028                 DCB 6              ; goto_if VAR_RESULT, 1, 0x8eb1040
    ROM:08EB1029                 DCB 1
    ROM:08EB102A                 DCD unk_8EB1040
    ROM:08EB102E                 DCB 5              ; goto EventScript_RemoveStaticMon
    ROM:08EB102F                 DCD EventScript_RemoveStaticMon
```

This starts a battle against a wild Mew. If the player catches it, script execution continues at `0x8eb1040`:

```
    ROM:08EB1040 byte_8EB1040    DCB 0x67           ; message 0x8eb1058
    ROM:08EB1041                 DCD unk_8EB1058
    ROM:08EB1045                 DCB 0x31           ; playfanfare MUS_OBTAIN_KEY_ITEM
    ROM:08EB1046                 DCW 0x103
    ROM:08EB1048                 DCB 0x32           ; waitfanfare
    ROM:08EB1049                 DCB 0x66           ; waitmessage
    ROM:08EB104A                 DCB 0x6D           ; waitbuttonpress
    ROM:08EB104B                 DCB 0x68           ; closemessage
    ROM:08EB104C                 DCB 5              ; goto EventScript_RemoveStaticMon
    ROM:08EB104D                 DCD EventScript_RemoveStaticMon
```

Nice! This prints the message stored at address `0x8eb1058` and plays a fanfare. So, just a matter of deciphering the message, surely it will contain the flag, right?

```
    ROM:08EB1058 msg_flag        DCB 0xCE, 0xDC, 0xDD, 0xE7, 0, 0xD7, 0xD5, 0xE2, 0xE2
    ROM:08EB1058                                         ; DATA XREF: ROM:08EB1041↑o
    ROM:08EB1061                 DCB 0xE3, 0xE8, 0, 0xD6, 0xD9, 0, 0xE1, 0xED, 0, 0xD8
    ROM:08EB106B                 DCB 0xD9, 0xE7, 0xE8, 0xDD, 0xE2, 0xED, 0xAD, 0xFE, 0xC8
    ROM:08EB1074                 DCB 0xE3, 0xEB, 0, 0xE8, 0xDC, 0xD9, 0, 0xE7, 0xD9, 0xE6
    ROM:08EB107E                 DCB 0xDD, 0xE3, 0xE9, 0xE7, 0, 0xE8, 0xD9, 0xE7, 0xE8
    ROM:08EB1087                 DCB 0xDD, 0xE2, 0xDB, 0, 0xD6, 0xD9, 0xDB, 0xDD, 0xE2
    ROM:08EB1090                 DCB 0xE7, 0xAD
```

The game uses a special charset, the translation can be found in [`include/characters.h`](https://github.com/pret/pokefirered/blob/master/include/characters.h):

```
    // [ ... snip ... ]
    #define CHAR_A                 0xBB
    #define CHAR_B                 0xBC
    #define CHAR_C                 0xBD
    #define CHAR_D                 0xBE
    #define CHAR_E                 0xBF
    #define CHAR_F                 0xC0
    #define CHAR_G                 0xC1
    #define CHAR_H                 0xC2
    #define CHAR_I                 0xC3
    #define CHAR_J                 0xC4
    #define CHAR_K                 0xC5
    #define CHAR_L                 0xC6
    #define CHAR_M                 0xC7
    #define CHAR_N                 0xC8
    #define CHAR_O                 0xC9
    #define CHAR_P                 0xCA
    #define CHAR_Q                 0xCB
    #define CHAR_R                 0xCC
    #define CHAR_S                 0xCD
    #define CHAR_T                 0xCE
    #define CHAR_U                 0xCF
    #define CHAR_V                 0xD0
    #define CHAR_W                 0xD1
    #define CHAR_X                 0xD2
    #define CHAR_Y                 0xD3
    #define CHAR_Z                 0xD4
    #define CHAR_a                 0xD5
    #define CHAR_b                 0xD6
    #define CHAR_c                 0xD7
    #define CHAR_d                 0xD8
    #define CHAR_e                 0xD9
    #define CHAR_f                 0xDA
    #define CHAR_g                 0xDB
    #define CHAR_h                 0xDC
    #define CHAR_i                 0xDD
    #define CHAR_j                 0xDE
    #define CHAR_k                 0xDF
    #define CHAR_l                 0xE0
    #define CHAR_m                 0xE1
    #define CHAR_n                 0xE2
    #define CHAR_o                 0xE3
    #define CHAR_p                 0xE4
    #define CHAR_q                 0xE5
    #define CHAR_r                 0xE6
    #define CHAR_s                 0xE7
    #define CHAR_t                 0xE8
    #define CHAR_u                 0xE9
    #define CHAR_v                 0xEA
    #define CHAR_w                 0xEB
    #define CHAR_x                 0xEC
    #define CHAR_y                 0xED
    #define CHAR_z                 0xEE
    // [ ... snip ... ]
```

Quickly writing a python script for translation

```
    CHARS = {
        ' ': 0x00, 'À': 0x01, 'Á': 0x02, 'Â': 0x03, 'Ç': 0x04, 'È': 0x05, 'É': 0x06,
        'Ê': 0x07, 'Ë': 0x08, 'Ì': 0x09, 'Î': 0x0B, 'Ï': 0x0C, 'Ò': 0x0D, 'Ó': 0x0E,
        'Ô': 0x0F, 'Œ': 0x10, 'Ù': 0x11, 'Ú': 0x12, 'Û': 0x13, 'Ñ': 0x14, 'ß': 0x15,
        'à': 0x16, 'á': 0x17, 'ç': 0x19, 'è': 0x1A, 'é': 0x1B, 'ê': 0x1C, 'ë': 0x1D,
        'ì': 0x1E, 'î': 0x20, 'ï': 0x21, 'ò': 0x22, 'ó': 0x23, 'ô': 0x24, 'œ': 0x25,
        'ù': 0x26, 'ú': 0x27, 'û': 0x28, 'ñ': 0x29, 'º': 0x2A, 'ª': 0x2B, '&': 0x2D,
        '+': 0x2E, '=': 0x35, ';': 0x36, '¿': 0x51, '¡': 0x52, 'Í': 0x5A, '%': 0x5B,
        '(': 0x5C, ')': 0x5D, 'â': 0x68, 'í': 0x6F, '<': 0x85, '>': 0x86, '0': 0xA1,
        '1': 0xA2, '2': 0xA3, '3': 0xA4, '4': 0xA5, '5': 0xA6, '6': 0xA7, '7': 0xA8,
        '8': 0xA9, '9': 0xAA, '!': 0xAB, '?': 0xAC, '.': 0xAD, '-': 0xAE, '…': 0xB0,
        '“': 0xB1, '”': 0xB2, '‘': 0xB3, '\\': 0xB4, '♂': 0xB5, '♀': 0xB6, '¥': 0xB7,
        ',': 0xB8, '×': 0xB9, '/': 0xBA, 'A': 0xBB, 'B': 0xBC, 'C': 0xBD, 'D': 0xBE,
        'E': 0xBF, 'F': 0xC0, 'G': 0xC1, 'H': 0xC2, 'I': 0xC3, 'J': 0xC4, 'K': 0xC5,
        'L': 0xC6, 'M': 0xC7, 'N': 0xC8, 'O': 0xC9, 'P': 0xCA, 'Q': 0xCB, 'R': 0xCC,
        'S': 0xCD, 'T': 0xCE, 'U': 0xCF, 'V': 0xD0, 'W': 0xD1, 'X': 0xD2, 'Y': 0xD3,
        'Z': 0xD4, 'a': 0xD5, 'b': 0xD6, 'c': 0xD7, 'd': 0xD8, 'e': 0xD9, 'f': 0xDA,
        'g': 0xDB, 'h': 0xDC, 'i': 0xDD, 'j': 0xDE, 'k': 0xDF, 'l': 0xE0, 'm': 0xE1,
        'n': 0xE2, 'o': 0xE3, 'p': 0xE4, 'q': 0xE5, 'r': 0xE6, 's': 0xE7, 't': 0xE8,
        'u': 0xE9, 'v': 0xEA, 'w': 0xEB, 'x': 0xEC, 'y': 0xED, 'z': 0xEE, '▶': 0xEF,
        ':': 0xF0, 'Ä': 0xF1, 'Ö': 0xF2, 'Ü': 0xF3, 'ä': 0xF4, 'ö': 0xF5, 'ü': 0xF6,
        '\n': 0xFE
    }
    
    def bytes2msg(bs):
        return "".join([ [ k for k in CHARS.keys() if CHARS[k] == b ][0] for b in bs ])
    
    msg_flag = bytes([ 0xCE, 0xDC, 0xDD, 0xE7, 0x00, 0xD7, 0xD5, 0xE2, 0xE2, 0xE3,
      0xE8, 0x00, 0xD6, 0xD9, 0x00, 0xE1, 0xED, 0x00, 0xD8, 0xD9,
      0xE7, 0xE8, 0xDD, 0xE2, 0xED, 0xAD, 0xFE, 0xC8, 0xE3, 0xEB,
      0x00, 0xE8, 0xDC, 0xD9, 0x00, 0xE7, 0xD9, 0xE6, 0xDD, 0xE3,
      0xE9, 0xE7, 0x00, 0xE8, 0xD9, 0xE7, 0xE8, 0xDD, 0xE2, 0xDB,
      0x00, 0xD6, 0xD9, 0xDB, 0xDD, 0xE2, 0xE7, 0xAD
      ])
    
    print(bytes2msg(msg_flag))
```

yields the following:

```
    This cannot be my destiny.
    Now the serious testing begins.
```

This doesn’t look like a flag at all!

### Finding Mew’s Password

Looks like we have to dig deeper. We skipped the password prompt altogether, so it kind of makes sense that getting the flag is not that easy. Recall the important part in the first script:

```
    ROM:08EB0E80                 DCB 0x25           ; callspecial ??? (0x89)
    ROM:08EB0E81                 DCD 0x89
    ROM:08EB0E85                 DCB 0x21           ; compare VAR8007, 0x1337
    ROM:08EB0E86                 DCW 0x8007
    ROM:08EB0E88                 DCW 0x1337
    ROM:08EB0E8A                 DCB 6              ; goto_if 1, unk_8eb1000
    ROM:08EB0E8B                 DCB 1
    ROM:08EB0E8C                 DCD unk_8EB1000
```

`callspecial` really just interprets its argument as an index into a big function pointer table and transfers control:

```
    int ScrCmd_special()
    {
      _DWORD *v0; // r1
    
      v0 = (_UNKNOWN **)((char *)&gSpecials + ((4 * ScriptReadHalfword()) & 0x3FFFF));
      if ( v0 >= &gStdScripts )
        ((void (__fastcall *)(const char *, int, const char *, int))AGBAssert)(
          "C:/WORK/POKeFRLG/Src/pm_lgfr_ose/source/scrcmd.c",
          241,
          "0",
          1);
      else
        call_via_r0(*v0);
      return 0;
    }
```

Doing the math, we find `gSpecials + 4 * 0x89 = 0x0815FFD8`. Rings a bell? Sure it does. In the original patch sequence, we had

```
    0x0815fdb4 gSpecials
    0x0815ffd8 0xa9 -> 0x88
    0x0815ffd9 0xad -> 0x88
    0x0815ffda 0x0c -> 0xeb
    0x0815ffdb 0x08 == 0x08
```

meaning that particular special event `0x89` is redirected to location `0x08eb8888`. The function inserted at this address looks as follows:

```
    int special_0x89()
    {
      int result; // r0
      __int16 v1; // r3
    
      result = *(unsigned __int16 *)(gSaveBlock1Ptr + 0x3458);
      if ( result == 0x121E )
      {
        result = *(unsigned __int16 *)(gSaveBlock1Ptr + 0x345A);
        if ( result == 0x1603 )
        {
          result = *(unsigned __int16 *)(gSaveBlock1Ptr + 0x345C);
          if ( result == 0xA02 )
          {
            result = *(unsigned __int16 *)(gSaveBlock1Ptr + 0x345E);
            v1 = 0x1337;
            if ( result != 0x1E1B )
              v1 = 0;
          }
          else
          {
            v1 = 0;
          }
        }
        else
        {
          v1 = 0;
        }
      }
      else
      {
        v1 = 0;
      }
      *gSpecialVar_0x8007 = v1;
      return result;
    }
```

That looks quite promising: Check four locations against constants, and if they all match, assign `0x1337` to the location holding `VAR8007` (remember how the first stage script checks this variable being `0x1337` to determine whether to start the Mew battle? (see `0x08eb0e85`)). So, if we manage to figure out the meaning of those checks we should be good to go, right?

Assuming those four locations hold the responses we picked in the questionnaire, we can look up `0x121e`, `0x1603`, `0x0a02`, `0x1e1b` in [`include/easy_chat.h`](https://github.com/pret/pokefirered/blob/master/include/easy_chat.h) and get `EC_WORD_NEVER`, `EC_WORD_GIVES`, `EC_WORD_YOU`, `EC_WORD_UP`. Unsurprisingly, using `NEVER GIVES YOU UP` as password does not trigger the Mew battle and we still don’t get a flag.

### Finding Mew’s Real Password

Clearly, some shenanigans are at work. The code that the patch adds to the game sets a return value of `0x1337`, still some component in the emulator seems to intercept the function and set the value back to zero. (To confirm this suspicion we could run the ROM in a different emulator and find that the rickroll passes the check there.)

A stupid search for instructions using `0x1337` as an immediate turns up exactly one match in the emulator binary at `0x1407e8869`:

```
    .text:00000001407E8862                 mov     rax, cs:off_1411F6180
    .text:00000001407E8869                 mov     word ptr [rax+0Ch], 1337h
```

`0x1411f6180` holds a pointer to the register file, so the write of constant `0x1337` would happen to the emulated `R3` (`0x0c / 4 = 3`). Decompiling this function in the emulator, we figure out that we’re in `CPULoop`, and that there’s an awful lot of vector instructions gated by an `if ( armNextPc_ == 0x8EB88B0 )`. Checking this virtual address in the ROM, we get confirmation that the emulator indeed patches the return value of the password check function:

```
    ROM:08EB88B0                 STRH            R3, [R1]
    ROM:08EB88B4                 BX              LR
```

We also find a code path in the emulator that can set the return value to zero (`0x1407E82C7`). This is very likely the reason why `NEVER GIVES YOU UP` isn’t accepted as a password, despite the game logic validating it as correct. Looks like we have to deal with the vector instructions and figure out what the input for the real password check in the emulator should be:

```
        if ( armNextPc_ == 0x8EB88B0 )
        {
          v222 = 0x8EB88B0;
          v11 = _mm_loadu_si128((const __m128i *)&xmmword_141076B30);
```

---

*Truncated at 1200 lines. Full text: <https://hxp.io/blog/119/hxp-38C3-CTF-yasashiimon/>*
