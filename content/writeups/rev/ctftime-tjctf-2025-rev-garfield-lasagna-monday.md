---
title: "rev/garfield-lasagna-monday - TJCTF 2025"
category: "rev"
subcategory: "wasm"
type: "writeup"
tags: ["wasm", "rev", "garfield-lasagna-monday", "tjctf", "tjctf-2025", "2025", "ctf-writeup"]
summary: "1\\. Try to input random word:"
source:
  name: "CTFtime writeup #40308"
  url: "https://ctftime.org/writeup/40308"
ctf:
  name: "TJCTF 2025"
  year: 2025
  challenge: "rev/garfield-lasagna-monday"
---

## Metadata

- **CTF:** TJCTF 2025
- **Task:** rev/garfield-lasagna-monday
- **Author team:** Dark_Matter
- **CTFtime:** <https://ctftime.org/writeup/40308>

---
1\. **Try to input random word**:  
\- ADJECTIVE: "test"  
\- NOUN: "test"  
\- VERB (PRESENT TENSE): "test"  
\- ADJECTIVE: "test"  
\- ADJECTIVE: "test"

2\. **Using DevTools to check network traffic request/response**:  
\- After submit, there a request which is web assembly, we can view source code in response: [challenge.wasm](<https://garfield-lasagna-monday.tjc.tf/static/challenge.wasm>)

```  
(module  
(table $__indirect_function_table (;0;) (export "__indirect_function_table") 2 2 funcref)  
(memory $memory (;0;) (export "memory") 256 256)  
(global $global0 (mut i32) (i32.const 5243952))  
(elem $elem0 (i32.const 1) funcref (ref.func $_initialize))  
(func $_initialize (;0;) (export "_initialize")  
nop  
)  
(func $check (;1;) (export "check") (param $var0 i32) (result i32)  
(local $var1 i32)  
block $label0  
local.get $var0  
i32.load8_u  
i32.const 98  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=1  
i32.const 108  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=2  
i32.const 117  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=3  
i32.const 101  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=4  
i32.const 124  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=5  
i32.const 116  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=6  
i32.const 117  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=7  
i32.const 120  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=8  
i32.const 101  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=9  
i32.const 100  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=10  
i32.const 111  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=11  
i32.const 124  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=12  
i32.const 100  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=13  
i32.const 97  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=14  
i32.const 110  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=15  
i32.const 99  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=16  
i32.const 101  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=17  
i32.const 124  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=18  
i32.const 99  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=19  
i32.const 104  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=20  
i32.const 97  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=21  
i32.const 111  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=22  
i32.const 115  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=23  
i32.const 124  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=24  
i32.const 112  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=25  
i32.const 97  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=26  
i32.const 110  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=27  
i32.const 99  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=28  
i32.const 97  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=29  
i32.const 107  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=30  
i32.const 101  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=31  
i32.const 115  
[i32.ne](http://i32.ne)  
br_if $label0  
local.get $var0  
i32.load8_u offset=32  
i32.eqz  
local.set $var1  
end $label0  
local.get $var1  
)  
(func $get_flag (;2;) (export "get_flag") (result i32)  
i32.const 1040  
i64.const 9038006696380691298  
i64.store  
i32.const 1032  
i64.const 7596551555448135522  
i64.store  
i32.const 1024  
i64.const 3708568498132445812  
i64.store  
i32.const 1048  
i32.const 0  
i32.store8  
i32.const 1024  
)  
(func $stackSave (;3;) (export "stackSave") (result i32)  
global.get $global0  
)  
(func $stackRestore (;4;) (export "stackRestore") (param $var0 i32)  
local.get $var0  
global.set $global0  
)  
(func $stackAlloc (;5;) (export "stackAlloc") (param $var0 i32) (result i32)  
global.get $global0  
local.get $var0  
i32.sub  
i32.const -16  
i32.and  
local.tee $var0  
global.set $global0  
local.get $var0  
)  
(func $__errno_location (;6;) (export "__errno_location") (result i32)  
i32.const 1056  
)  
)  
```

By looking at the check function verifies that the input string matches a specific sequence of characters. Here's what it checks for:

\- Position 0: 'b' (98)  
\- Position 1: 'l' (108)  
\- Position 2: 'u' (117)  
\- Position 3: 'e' (101)  
\- Position 4: '|' (124)  
\- Position 5: 't' (116)  
\- Position 6: 'u' (117)  
\- Position 7: 'x' (120)  
\- Position 8: 'e' (101)  
\- Position 9: 'd' (100)  
\- Position 10: 'o' (111)  
\- Position 11: '|' (124)  
\- Position 12: 'd' (100)  
\- Position 13: 'a' (97)  
\- Position 14: 'n' (110)  
\- Position 15: 'c' (99)  
\- Position 16: 'e' (101)  
\- Position 17: '|' (124)  
\- Position 18: 'c' (99)  
\- Position 19: 'h' (104)  
\- Position 20: 'a' (97)  
\- Position 21: 'o' (111)  
\- Position 22: 's' (115)  
\- Position 23: '|' (124)  
\- Position 24: 'p' (112)  
\- Position 25: 'a' (97)  
\- Position 26: 'n' (110)  
\- Position 27: 'c' (99)  
\- Position 28: 'a' (97)  
\- Position 29: 'k' (107)  
\- Position 30: 'e' (101)  
\- Position 31: 's' (115)  
\- Position 32: null terminator (0)

So the expected string is: `blue|tuxedo|dance|chaos|pancakes`

3\. **Completing the Challenge**:  
\- ADJECTIVE: "blue"  
\- NOUN: "tuxedo"  
\- VERB (PRESENT TENSE): "dance"  
\- ADJECTIVE: "chaos"  
\- ADJECTIVE: "pancakes"

4\. **Submit**:

**Flag**: `tjctf{w3b_m4d_libsw4sm}`
