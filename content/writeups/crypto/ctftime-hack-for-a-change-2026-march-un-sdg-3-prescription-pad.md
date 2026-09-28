---
title: "Prescription Pad - Hack for a Change 2026 March: UN SDG 3"
category: "crypto"
subcategory: "static-analysis"
type: "writeup"
tags: ["crypto", "xor", "ghidra", "custom-vm", "prescription", "pad", "static-analysis", "hack-for-a-change-2026-march-u", "hack-for-a-change-2026-march-un-sd", "2026", "ctf-writeup"]
summary: "We are given a stripped Linux x8664 ELF binary called \"ghost\"."
source:
  name: "CTFtime writeup #40689"
  url: "https://ctftime.org/writeup/40689"
ctf:
  name: "Hack for a Change 2026 March: UN SDG 3"
  year: 2026
  challenge: "Prescription Pad"
---

## Metadata

- **CTF:** Hack for a Change 2026 March: UN SDG 3
- **Task:** Prescription Pad
- **Author team:** Hack for a Change
- **CTFtime:** <https://ctftime.org/writeup/40689>

---
# Prescription Pad Writeup

## 1. Challenge Overview

We are given a stripped Linux x86_64 ELF binary called "ghost". It accepts a passphrase argument and prints "Correct!" or "Wrong." However, the decompiler output reveals something very different — instead of direct cryptographic operations, the binary contains a virtual machine interpreter that executes embedded bytecode.

## 2. Identifying the VM Architecture

Opening the binary in Ghidra, the main execution function contains a large while loop with a switch statement on a single byte value. This is the classic pattern of a bytecode interpreter. By analyzing each case in the switch, we map out the instruction set:

| Opcode | Name | Operands | Description |   
|--------|-----------|----------|--------------------------------------|   
| 0x10 | PUSH | imm8 | Push immediate byte onto stack |   
| 0x11 | POP | - | Discard top of stack |   
| 0x12 | DUP | - | Duplicate top of stack |   
| 0x20 | ADD | - | Pop a,b; push (a+b) & 0xFF |   
| 0x21 | SUB | - | Pop a,b; push (b-a) & 0xFF |   
| 0x22 | XOR | - | Pop a,b; push a^b |   
| 0x23 | MUL | - | Pop a,b; push (a*b) & 0xFF |   
| 0x24 | ROL | - | Pop a,n; rotate a left by n bits |   
| 0x25 | AND | - | Pop a,b; push a&b |   
| 0x30 | LOAD | imm8 | Push mem[imm8] |   
| 0x31 | STORE | imm8 | Pop top, store to mem[imm8] |   
| 0x40 | READCHAR | imm8 | Push input[imm8] |   
| 0x50 | CMP | - | Pop a,b; set ZF if a==b |   
| 0x60 | JZ | imm16 | Jump if ZF set |   
| 0x61 | JNZ | imm16 | Jump if ZF not set |   
| 0x62 | JMP | imm16 | Unconditional jump |  
| 0x71 | PRINTOK | - | Print 'Correct!' and halt |   
| 0x72 | PRINTFAIL | - | Print 'Wrong.' and halt |

The VM has a 256-byte stack, 256-byte memory, a program counter, and a zero flag (ZF). Input comes from the user's command-line argument, accessed via READCHAR.

## 3. Extracting the Bytecode

The bytecode is stored in a 1024-byte buffer in the .data section. In Ghidra, the main function passes this buffer and its length (stored as a nearby integer) to the interpreter function. We extract both by examining the data section — the bytecode starts with 0x40 (READCHAR) and ends with 0x71 0x72 (PRINTOK PRINTFAIL) followed by zero padding.

## 4. Disassembling the Bytecode

Writing a simple disassembler using our opcode table, we decode the bytecode. The program structure is:

1\. A length check: READCHAR flag_len, PUSH 0, CMP, JNZ fail — verifies the input isn't too long. Then READCHAR flag_len-1, PUSH 0, CMP, JZ fail — verifies it isn't too short.

2\. Accumulator initialization: PUSH 0x5A, STORE 0 — sets mem[0] = 0x5A for use by transform type 3.

3\. Per-character checks: For each flag position i, a sequence of operations transforms input[i] and compares the result against an embedded constant. If the comparison fails, JNZ jumps to the PRINTFAIL label. Five different transform types are used, cycling with i % 5.

## 5. The Five Transform Types

### Transform 0 (i % 5 == 0): XOR + ADD

``` READCHAR i   
PUSH xor_key #(i * 0x37 + 0x13) & 0xFF   
XOR PUSH add_key #(i * 0x0B + 0x07) & 0xFF   
ADD   
PUSH   
expected CMP / JNZ fail   
```

### Transform 1 (i % 5 == 1): MUL + XOR

``` READCHAR i  
PUSH mul_key #((i * 0x1D + 0x03) | 1) & 0xFF  
MUL  
PUSH xor_key #(i * 0x43 + 0x29) & 0xFF  
XOR  
PUSH expected  
CMP / JNZ fail  
```

### Transform 2 (i % 5 == 2): ROL + XOR

```READCHAR i  
PUSH rot_amount #(i % 7) + 1  
ROL  
PUSH xor_key #(i * 0x5B + 0x71) & 0xFF  
XOR  
PUSH expected  
CMP / JNZ fail  
```

### Transform 3 (i % 5 == 3): Accumulator XOR (Stateful)

This is the trickiest transform. It uses mem[0] as a cascading accumulator that updates after each type-3 check:

```READCHAR i  
LOAD 0 #push accumulator from mem[0]  
XOR #input[i] ^ accumulator  
PUSH expected  
CMP / JNZ fail  
LOAD 0 #update accumulator  
READCHAR i  
ADD #acc = (acc + input[i]) & 0xFF  
STORE 0 #save back to mem[0]  
```

The accumulator starts at 0x5A and changes with each correct character. This means type-3 checks are order-dependent — you must solve earlier characters correctly before later type-3 checks produce the right accumulator state.

### Transform 4 (i % 5 == 4): Split Nibble AND + XOR

This transform checks the high and low nibbles of the input byte separately, producing two CMP/JNZ checks per character:

#### High nibble check

```READCHAR i / PUSH 0xF0 / AND / PUSH xor_key / XOR  
PUSH expected / CMP / JNZ fail  
```

#### Low nibble check

```READCHAR i / PUSH 0x0F / AND / PUSH low_xor / XOR  
PUSH low_expected / CMP / JNZ fail  
```

## 6. Solve Approach: Side-Channel Brute Force

While we could algebraically invert each transform type, there is an elegant shortcut. The VM checks characters sequentially — a wrong character at position i causes an immediate JNZ to the fail label. This means correct characters produce more passed CMP instructions before the program terminates.

By reimplementing the VM interpreter in Python and counting how many CMP instructions set ZF = 1, we can brute-force one character at a time:

```python  
def count_passed_checks(bytecode, input_bytes):  
# Run VM, count CMPs where a == b  
...  
return passed

flag = bytearray(b'A' * flag_len)  
for pos in range(flag_len):  
best_char, best_checks = 0, 0  
for ch in range(0x20, 0x7f): # printable ASCII  
flag[pos] = ch  
checks = count_passed_checks(bytecode, bytes(flag))  
if checks > best_checks:  
best_checks = checks  
best_char = ch  
flag[pos] = best_char  
```  
Each correct character increases the passed check count. With ~95 printable ASCII characters and ~37 flag positions, this requires only ~3,500 VM executions — essentially instant.

## 7. Why the Side-Channel Works

The critical design choice is that all JNZ fail jumps go to the same fail label at the end of the bytecode. Each character check is a separate CMP followed by JNZ: if the CMP fails (wrong byte), the JNZ fires and execution jumps to PRINTFAIL, skipping all remaining checks. A correct byte passes the CMP (ZF = 1), the JNZ doesn't fire, and execution continues to the next character.

This means the number of passed CMPs directly correlates with how many characters are correct from left to right. By maximizing this count for each position sequentially, we recover the flag one character at a time.

Note: transform type 3 (accumulator) and type 4 (double check) produce different numbers of CMPs per character, so the count increase isn't always +1. But the principle holds: more passed checks = more correct characters.

## 8. Alternative Approach: Algebraic Inversion

For a more elegant (but harder) solution, each transform can be inverted directly by extracting the keys and expected values from the bytecode, then solving for the input byte. This requires correctly handling all 5 transform types, including the stateful accumulator for type 3. The brute-force approach avoids this complexity entirely.
