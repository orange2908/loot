---
title: "TSGDBinary - TSG CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "gdb", "eval", "exec", "tsgdbinary", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "First of all, we need to deobfuscate the tsgdbinary.py to check what it does during the operation."
source:
  name: "CTFtime writeup #39706"
  url: "https://ctftime.org/writeup/39706"
original_source: "https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "TSGDBinary"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** TSGDBinary
- **Author team:** blue-lotus
- **CTFtime tags:** gdb
- **CTFtime:** <https://ctftime.org/writeup/39706>
- **Original writeup:** <https://yasarli.com/posts/tsg-ctf-2024-reverse-writeup/>

---
First of all, we need to deobfuscate the `[tsgdbinary.py](http://tsgdbinary.py)` to check what it does during the operation.

```python  
import gdb  
import sys  
import os  
import types

def run_gdb_cmd(cmd):  
global gdb_history  
gdb.execute(cmd, to_string=True)  
gdb_history = gdb.parameter("history filename")  
hs = gdb.parameter("history save")  
if hs and gdb_history:  
with open(gdb_history, "a") as file:  
file.write(cmd + "\n")

def set_reg_byte(i):  
gdb.parse_and_eval("*(unsigned char *)$" + i + " = $al")  
return

def set_reg_int64(i):  
gdb.parse_and_eval("*(unsigned long long *)$" + i + " = $rax")  
return

def set_ing64(i, m):  
gdb.parse_and_eval("$" + i + " = *(unsigned long long *)$" + m)  
return

def set_byte(i, m):  
gdb.parse_and_eval("$" + i + " = *(unsigned char *)$" + m)  
return

def set_reg(i, m):  
gdb.parse_and_eval("$" + i + " = " + hex(m))  
return

def event_breakpoint_connect(u):  
gdb.events.breakpoint_created.connect(u)  
return

def event_breakpoint_disconnect(u):  
gdb.events.breakpoint_created.disconnect(u)  
return

def event_stop_connect(u):  
gdb.events.stop.connect(u)  
return

def event_stop_disconnect(u):  
gdb.events.stop.disconnect(u)  
return

def output_file(pi, v):  
with open(tmp_file, "wb") as f:  
for b in pi:  
f.write(bytes([ord(b) ^ v]))  
return

def read_memory(s, l):  
return gdb.inferiors()[0].read_memory(s, l)

def get_pc():  
return gdb.selected_frame().pc()

def read_reg(o):  
return gdb.selected_frame().read_register(o)

def set_breakpoint(a):  
try:  
gdb.Breakpoint(f"*{a}").silent = True  
return  
except RuntimeError as e:  
return

def disable_output():  
sys.stdout = open(os.devnull, "w")  
sys.stderr = open(os.devnull, "w")  
return

def enable_output():  
sys.stderr.close()  
sys.stderr = sys.__stderr__  
sys.stdout.close()  
sys.stdout = sys.__stdout__  
return

def change_last_breakpoint1(e):  
global bp_lock  
if bp_lock:  
return  
bp_lock = True  
bps = gdb.breakpoints()  
if not bps:  
return  
bp = bps[-1]  
if bp.location.startswith("*"):  
o = int(bp.location[1:])  
n = o - 0x7200  
bp.delete()  
set_breakpoint(n)  
bp_lock = False  
return

def change_last_breakpoint2(e):  
global bp_lock  
if bp_lock:  
return  
bp_lock = True  
bps = gdb.breakpoints()  
if not bps:  
return  
bp = bps[-1]  
if bp.location.startswith("*"):  
o = int(bp.location[1:])  
n = o + 0x30  
bp.delete()  
set_breakpoint(n)  
bp_lock = False  
return

def remove_first_breakpoint(e):  
bps = gdb.breakpoints()  
if bps:  
bps[0].delete()  
return

def gdb_exec(p):  
run_gdb_cmd("source " + p)  
return

def gdb_continue(n):  
gdb.execute("c")

def print_breakpoints():  
bps = gdb.breakpoints()  
print([hex(int(bp.location[1:])) for bp in bps])

gdb.execute("shell rm ./kk")  
gdb.execute("set history filename ./kk")  
gdb.execute("set history save on")

gdb_history = "./kk"  
tmp_file = "./pkcool"

bp_lock = False  
pos = [0, 34, 31, 32, 47, 42]  
lweknt = 0x89FC76AE  
base = 0x401000  
mnt = 0xF8D6A8C3  
base1 = 0x6547EA867000  
base2 = 0x72433A3C000  
kqwee = base1 + 0xD12  
pwsu = base1 + 0xFA0  
xend = pwsu + 0x30

rdx = "rdx"  
rcx = "rcx"  
rax = "rax"  
rdi = "rdi"  
rip = "rip"  
rsp = "rsp"  
rsi = "rsi"

set_breakpoint(base + 0x7F6)  
set_breakpoint(base + 0x8BC)  
gdb.execute("run")

run_gdb_cmd("set pagination off")  
run_gdb_cmd("info b")  
run_gdb_cmd("show")  
run_gdb_cmd("info b")  
event_stop_connect(remove_first_breakpoint)  
bps = gdb.breakpoints()  
print([hex(int(bp.location[1:])) for bp in bps])  
run_gdb_cmd("c")  
event_breakpoint_connect(change_last_breakpoint2)  
set_breakpoint(base + 0x3E4)

ou = read_memory(base + 0x3080, 71)  
print(b"".join(ou[:0x40]))  
output_file(ou, 0xD7)  
gdb_exec(tmp_file)  
# call mmap((void *)0x6547ea867000, 0x1000, 7, 0x32, -1, 0)

# get_script()  
ou1 = read_memory(base + 0x30E0, 305)  
output_file(ou1, 0x3C)  
print(open(tmp_file, "r").read())  
gdb_exec(tmp_file)  
# call mmap((void *)0x72433a3c000, 0x400, 6, 0x32, -1, 0)  
# set $src = 0x7fffffffe460  
# set $dst = 0x72433a3c000  
# set $size = 4  
# set $count = 0x30 / $size  
# set $i = 0  
# while ($i < $count)  
# set $value = *(int *)($src + $i * $size)  
# set *(int *)($dst + $i * $size) = $value  
# set $i = $i + 1  
# end

set_breakpoint(base + 0x3FE)  
# disable_output()  
# etg()  
ou1 = read_memory(base + 0x3220, 270)  
print(b"".join(ou1[:0x40]))  
for i in range(0, 0x30):  
set_reg(rcx, base2 + i)  
set_byte(rdi, rcx)  
set_reg(rip, 0x401414)  
set_reg(rsi, int.from_bytes(ou[i], byteorder="little"))  
if i == 0:  
gdb_continue(4)  
gdb_continue(4)  
set_reg_byte(rcx)  
set_breakpoint(0x40142E - 0x30)

print(b"".join(ou[:0x40]))  
for i in range(0, 0x30):  
set_reg(rcx, base2 + i)  
set_byte(rdi, rcx)  
set_reg(rip, 0x401414)  
set_reg(rsi, int.from_bytes(ou[i + 0x10], byteorder="little"))  
gdb_continue(4)  
set_reg_byte(rcx)  
set_breakpoint(0x40142E - 0x30)

event_breakpoint_disconnect(change_last_breakpoint2)  
event_breakpoint_connect(change_last_breakpoint1)  
event_stop_disconnect(remove_first_breakpoint)

k = 0  
for i in range(0, 6):  
set_reg(rdx, 0x1000)  
set_reg(rsi, base + 0x3340 + 0x1000 * i)  
set_reg(rdi, base1)  
set_reg(rip, base + 0x4D6)  
set_breakpoint(base + 0x7741)  
gdb_continue(4)  
set_reg(rax, base + 0x5A5)  
set_breakpoint(base + 0x77A5)  
set_reg(rip, base1 + pos[i])  
set_reg(rcx, base2 + k)  
set_ing64(rsi, rcx)  
set_reg_int64(rsp)  
gdb_continue(4)  
bps = gdb.breakpoints()  
for bp in bps:  
bp.enabled = False  
set_breakpoint(base + 0x77C1)  
set_reg(rsi, read_reg(rax))  
set_reg(rdi, 0x89FC76AEF8D6A8C3)  
set_reg(rcx, xend + k)  
gdb_continue(4)  
set_reg_int64(rcx)  
k += 8

enable_output()  
set_reg(rdx, 0x30)  
set_reg(rsi, pwsu)  
set_reg(rdi, xend)  
set_reg(rip, base + 0x8CF)  
gdb_continue(4)  
# gdb.execute("shell rm ./kk")  
# gdb.execute("set history save off")  
```

The program will break before calling the `memcmp`. The flag input will be modified by the debugger and then the program will jump to `0x404340`. The code at `0x404340` in binary is encrypted, we need to decrypt it first.

```python  
code = idc.get_bytes(0x404340, 0x6000)

tmp = [0] * 0x1000  
file = open("tmp", "wb")  
for i in range(0, 6):  
tmp = [tmp[j] ^ code[i * 0x1000 + j] for j in range(0x1000)]  
file.write(bytes(tmp))

pos = [0, 34, 31, 32, 47, 42]  
print([hex(i) for i in pos])  
# ['0x0', '0x22', '0x1f', '0x20', '0x2f', '0x2a']  
```

The code at `0x404340` is sevaral mapping functions. We can find the original value manually and then decrypt the flag.

```python  
import struct

flag_enc = list(  
struct.unpack(  
"<" + "Q" * 6,  
b"B\xd3\x1f1d\xfe\xae\xa2\x02\xad\x05H\x1c\xac\x96\xd5\xe6bK#\xb5\xd0\xf7\xa7\xcaV\x19Y\x08`:\xacu}\xc4\x05\n\x8e\xb8\x07Oy=\xef\xadsy8",  
)  
)  
for i in range(6):  
flag_enc[i] = (flag_enc[i] - 0x89FC76AEF8D6A8C3) & 0xFFFFFFFFFFFFFFFF  
print([hex(i)[2:].upper() for i in flag_enc])  
# ['18B287B538492A7F', '4B9A356D4F2F043F', '1DFB5A062A74BA23', '223DE9596042AE07', '7DBC175B0CEDD4B2', 'AE7CFCFEF666D08C']

flag = [  
0x66221E42571B1B1D,  
0x2063383B75652F77,  
0x6B655A6961635674,  
0x641733226F50717C,  
0x624F786E344F6E7A,  
0x1C566D342C774434,  
]  
ou = b"\xb4\xb6\xbb\xbb\xf7\xba\xba\xb6\xa7\xff\xff\xa1\xb8\xbe\xb3\xf7\xfd\xfe\xe7\xaf\xe1\xe2\xe3\xe0\xb2\xb6\xef\xe1\xe0\xe7\xe7\xe7\xfb\xf7\xe7\xaf\xe6\xe7\xe7\xe7\xfb\xf7\xe0\xfb\xf7\xe7\xaf\xe4\xe5\xfb\xf7\xfa\xe6\xfb\xf7\xe7\xfe\xdd\xf6\xa5\xba\xf7\xf9\xf8"  
flag = struct.pack("<" + "Q" * 6, *flag)

flag = [flag[i] ^ ou[i + 0x10] for i in range(0x30)]  
flag = [flag[i] ^ ou[i] for i in range(0x30)]  
print(bytes(flag))  
# TSGCTF{0bfu5ca70r_can_al50_u53_gdb_and_b1nary}  
```
