---
title: "Batman Investigation I - Like Father Like Son - bi0sCTF 2024"
category: "forensics"
subcategory: "memory"
type: "writeup"
tags: ["forensics", "azr43lkn1ght", "volatility", "memory-forensics", "batman", "investigation", "like", "father", "son", "memory", "bi0sctf", "bi0sctf-2024", "2024", "ctf-writeup"]
summary: "Full solution of Batman Investigation II - Gotham Underground Corruption from bi0sctf 2024"
source:
  name: "CTFtime writeup #38976"
  url: "https://ctftime.org/writeup/38976"
original_source: "https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/"
ctf:
  name: "bi0sCTF 2024"
  year: 2024
  challenge: "Batman Investigation I - Like Father Like Son"
---

## Metadata

- **CTF:** bi0sCTF 2024
- **Task:** Batman Investigation I - Like Father Like Son
- **Author team:** bi0s
- **CTFtime tags:** azr43lkn1ght
- **CTFtime:** <https://ctftime.org/writeup/38976>
- **Original writeup:** <https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/>

---
# Batman Investigation I - Like Father Like Son - bi0sCTF 2024

[ __Azr43lKn1ght](https://twitter.com/Azr43lKn1ght)

__2024-03-05

[ __Forensics](https://blog.bi0s.in/categories/Forensics/)

__ __

* * *

Full solution of Batman Investigation II - Gotham Underground Corruption from bi0sctf 2024

**tl;dr**

  * Challenge 1 of Batman Investigation series
  * Memory Forensics - WinDBG Dump Debugging - Malware Analysis - Incident Response - Threat Hunting


**Challenge Points** : 998  
**No. of solves** : 3  
**Challenge Author** : [Azr43lKn1ght](https://twitter.com/Azr43lKn1ght)

### Challenge Description

Damian Wayne stored a secret in his old pc, but Dr. Simon Hurt who got this information, planned a contingency against Damian by the help of Starlab’s techies, poor Damaian was so eager to view the encrypted secret file that Raven sent him long back but Simon knows this piece of information as well as the decryption process, will he win this situation like a Wayne? will Damaian’s Redemption be successful!?

File Password : vOCorthoAGESeNsivEli

### Handout

  * [Primary Link](https://drive.google.com/file/d/1Ewusc9amOY6GbWTWqPut45EyL7wGBweO/view?usp=sharing)
  * [Mirror Link](https://mega.nz/file/giFxmCJR#YFJICgO-0hVKalHCImRam49ErvNHsG-JY38pEVLFKxE)


`Flag format: bi0sCTF{...}`

### Solution

first let’s start with profiling of the memory dump.

```
    1  
```

| 

```
    vol.py -f Damian.mem imageinfo  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
```  
  
| 

```
    Volatility Foundation Volatility Framework 2.6.1  
    INFO    : volatility.debug    : Determining profile based on KDBG search...  
              Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418  
                         AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)  
                         AS Layer2 : FileAddressSpace (/mnt/e/writeup/bat1/Damian.mem)  
                          PAE type : No PAE  
                               DTB : 0x187000L  
                              KDBG : 0xf8000280f0a0L  
              Number of Processors : 6  
         Image Type (Service Pack) : 1  
                    KPCR for CPU 0 : 0xfffff80002810d00L  
                    KPCR for CPU 1 : 0xfffff880009ea000L  
                    KPCR for CPU 2 : 0xfffff880030a8000L  
                    KPCR for CPU 3 : 0xfffff8800311d000L  
                    KPCR for CPU 4 : 0xfffff88003192000L  
                    KPCR for CPU 5 : 0xfffff880031c7000L  
                 KUSER_SHARED_DATA : 0xfffff78000000000L  
               Image date and time : 2023-05-06 16:45:20 UTC+0000  
         Image local date and time : 2023-05-06 22:15:20 +0530  
```  
  
---|---  
  
now let’s get the list of processes running on the system.

```
    1  
    2  
```

| 

```
    vol.py -f Damian.mem --profile Win7SP1x64 pslist  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
```  
  
| 

```
    Volatility Foundation Volatility Framework 2.6.1  
    Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit  
    ------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------  
    0xfffffa80036e2040 System                    4      0     98      469 ------      0 2023-05-06 16:43:35 UTC+0000  
    0xfffffa8004961300 smss.exe                272      4      2       34 ------      0 2023-05-06 16:43:35 UTC+0000  
    0xfffffa80062e8a20 csrss.exe               352    332     10      353      0      0 2023-05-06 16:43:38 UTC+0000  
    0xfffffa80047ca060 wininit.exe             404    332      4       84      0      0 2023-05-06 16:43:39 UTC+0000  
    0xfffffa80047c8360 csrss.exe               412    396     10      290      1      0 2023-05-06 16:43:39 UTC+0000  
    0xfffffa800643a740 services.exe            464    404     14      196      0      0 2023-05-06 16:43:39 UTC+0000  
    0xfffffa8006444060 winlogon.exe            488    396      6      121      1      0 2023-05-06 16:43:39 UTC+0000  
    0xfffffa800498f260 lsass.exe               516    404     11      581      0      0 2023-05-06 16:43:40 UTC+0000  
    0xfffffa800644d5b0 lsm.exe                 524    404     10      147      0      0 2023-05-06 16:43:40 UTC+0000  
    0xfffffa800632a660 svchost.exe             628    464     13      372      0      0 2023-05-06 16:43:40 UTC+0000  
    0xfffffa80064d2b30 VBoxService.ex          692    464     13      123      0      0 2023-05-06 16:43:40 UTC+0000  
    0xfffffa800644bb30 svchost.exe             760    464      8      255      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa800651ab30 svchost.exe             840    464     20      392      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa800654a7c0 svchost.exe             896    464     21      476      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa8006552940 svchost.exe             924    464     33      875      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa8006575b30 audiodg.exe            1000    840      8      136      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa8004871060 svchost.exe             296    464     13      290      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa80065cfb30 svchost.exe             348    464     18      387      0      0 2023-05-06 16:43:41 UTC+0000  
    0xfffffa8006651a30 spoolsv.exe            1140    464     15      315      0      0 2023-05-06 16:43:42 UTC+0000  
    0xfffffa800656ab30 svchost.exe            1180    464     21      332      0      0 2023-05-06 16:43:42 UTC+0000  
    0xfffffa80066dbb30 taskhost.exe           1312    464     10      155      1      0 2023-05-06 16:43:43 UTC+0000  
    0xfffffa8006742b30 dwm.exe                1448    896      6      103      1      0 2023-05-06 16:43:43 UTC+0000  
    0xfffffa8006783060 explorer.exe           1532   1416     40     1002      1      0 2023-05-06 16:43:43 UTC+0000  
    0xfffffa800676d490 VBoxTray.exe           2044   1532     15      149      1      0 2023-05-06 16:43:44 UTC+0000  
    0xfffffa80066e3060 SearchIndexer.          300    464     14      644      0      0 2023-05-06 16:43:51 UTC+0000  
    0xfffffa8006305b30 SearchProtocol         1756    300      9      382      0      0 2023-05-06 16:43:51 UTC+0000  
    0xfffffa8006907b30 SearchFilterHo         1580    300      7      143      0      0 2023-05-06 16:43:51 UTC+0000  
    0xfffffa80062f5300 iexplore.exe           2668   1532     22      477      1      1 2023-05-06 16:44:41 UTC+0000  
    0xfffffa80038a2b30 iexplore.exe           2752   2668     21      434      1      1 2023-05-06 16:44:41 UTC+0000  
    0xfffffa8006434b30 iexplore.exe           2892   2668     20      388      1      1 2023-05-06 16:44:47 UTC+0000  
    0xfffffa8003967b30 scvhost.exe            1924   1532      5       55      1      0 2023-05-06 16:44:54 UTC+0000  
    0xfffffa800393db30 conhost.exe            2292    412      3       51      1      0 2023-05-06 16:44:54 UTC+0000  
    0xfffffa800398f660 notepad.exe            2320   1924      2       57      1      0 2023-05-06 16:44:54 UTC+0000  
    0xfffffa800699e750 RamCapture64.e          596   1532      3       77      1      0 2023-05-06 16:45:18 UTC+0000  
    0xfffffa8003985060 conhost.exe            1900    412      2       51      1      0 2023-05-06 16:45:18 UTC+0000  
    0xfffffa800664f1b0 svchost.exe            2168    464      5        0 ------      0 2023-05-06 16:45:49 UTC+0000  
```  
  
---|---  
  
so here if, we don’t find any process suspicious if we don’t notice so closely, but still we have notepad running.

let’s see what spawned the process notepad.exe of pid 2320 using pstree

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
```

| 

```
    Volatility Foundation Volatility Framework 2.6.1  
    Name                                                  Pid   PPid   Thds   Hnds Time  
    -------------------------------------------------- ------ ------ ------ ------ ----  
     0xfffffa80047ca060:wininit.exe                       404    332      4     84 2023-05-06 16:43:39 UTC+0000  
    . 0xfffffa800644d5b0:lsm.exe                          524    404     10    147 2023-05-06 16:43:40 UTC+0000  
    . 0xfffffa800498f260:lsass.exe                        516    404     11    581 2023-05-06 16:43:40 UTC+0000  
    . 0xfffffa800643a740:services.exe                     464    404     14    196 2023-05-06 16:43:39 UTC+0000  
    .. 0xfffffa800654a7c0:svchost.exe                     896    464     21    476 2023-05-06 16:43:41 UTC+0000  
    ... 0xfffffa8006742b30:dwm.exe                       1448    896      6    103 2023-05-06 16:43:43 UTC+0000  
    .. 0xfffffa8006552940:svchost.exe                     924    464     33    875 2023-05-06 16:43:41 UTC+0000  
    .. 0xfffffa80066dbb30:taskhost.exe                   1312    464     10    155 2023-05-06 16:43:43 UTC+0000  
    .. 0xfffffa800656ab30:svchost.exe                    1180    464     21    332 2023-05-06 16:43:42 UTC+0000  
    .. 0xfffffa80066e3060:SearchIndexer.                  300    464     14    644 2023-05-06 16:43:51 UTC+0000  
    ... 0xfffffa8006907b30:SearchFilterHo                1580    300      7    143 2023-05-06 16:43:51 UTC+0000  
    ... 0xfffffa8006305b30:SearchProtocol                1756    300      9    382 2023-05-06 16:43:51 UTC+0000  
    .. 0xfffffa80064d2b30:VBoxService.ex                  692    464     13    123 2023-05-06 16:43:40 UTC+0000  
    .. 0xfffffa800632a660:svchost.exe                     628    464     13    372 2023-05-06 16:43:40 UTC+0000  
    .. 0xfffffa8004871060:svchost.exe                     296    464     13    290 2023-05-06 16:43:41 UTC+0000  
    .. 0xfffffa800651ab30:svchost.exe                     840    464     20    392 2023-05-06 16:43:41 UTC+0000  
    ... 0xfffffa8006575b30:audiodg.exe                   1000    840      8    136 2023-05-06 16:43:41 UTC+0000  
    .. 0xfffffa800664f1b0:svchost.exe                    2168    464      5      0 2023-05-06 16:45:49 UTC+0000  
    .. 0xfffffa80065cfb30:svchost.exe                     348    464     18    387 2023-05-06 16:43:41 UTC+0000  
    .. 0xfffffa8006651a30:spoolsv.exe                    1140    464     15    315 2023-05-06 16:43:42 UTC+0000  
    .. 0xfffffa800644bb30:svchost.exe                     760    464      8    255 2023-05-06 16:43:41 UTC+0000  
     0xfffffa80062e8a20:csrss.exe                         352    332     10    353 2023-05-06 16:43:38 UTC+0000  
     0xfffffa80036e2040:System                              4      0     98    469 2023-05-06 16:43:35 UTC+0000  
    . 0xfffffa8004961300:smss.exe                         272      4      2     34 2023-05-06 16:43:35 UTC+0000  
     0xfffffa80047c8360:csrss.exe                         412    396     10    290 2023-05-06 16:43:39 UTC+0000  
    . 0xfffffa8003985060:conhost.exe                     1900    412      2     51 2023-05-06 16:45:18 UTC+0000  
    . 0xfffffa800393db30:conhost.exe                     2292    412      3     51 2023-05-06 16:44:54 UTC+0000  
     0xfffffa8006444060:winlogon.exe                      488    396      6    121 2023-05-06 16:43:39 UTC+0000  
     0xfffffa8006783060:explorer.exe                     1532   1416     40   1002 2023-05-06 16:43:43 UTC+0000  
    . 0xfffffa8003967b30:scvhost.exe                     1924   1532      5     55 2023-05-06 16:44:54 UTC+0000  
    .. 0xfffffa800398f660:notepad.exe                    2320   1924      2     57 2023-05-06 16:44:54 UTC+0000  
    . 0xfffffa800699e750:RamCapture64.e                   596   1532      3     77 2023-05-06 16:45:18 UTC+0000  
    . 0xfffffa800676d490:VBoxTray.exe                    2044   1532     15    149 2023-05-06 16:43:44 UTC+0000  
    . 0xfffffa80062f5300:iexplore.exe                    2668   1532     22    477 2023-05-06 16:44:41 UTC+0000  
    .. 0xfffffa80038a2b30:iexplore.exe                   2752   2668     21    434 2023-05-06 16:44:41 UTC+0000  
    .. 0xfffffa8006434b30:iexplore.exe                   2892   2668     20    388 2023-05-06 16:44:47 UTC+0000  
```  
  
---|---  
  
so here we can see that the process scvhost.exe of pid 1924 spawned the process notepad.exe of pid 2320.

where we notice it is not the usual svchost.exe but scvhost.exe which is a bit suspicious.

so we look into its commadline.

```
    1  
    2  
    3  
    4  
    5  
```

| 

```
    vol.py -f Damian.mem --profile Win7SP1x64 cmdline -p 1924  
    Volatility Foundation Volatility Framework 2.6.1  
    ************************************************************************  
    scvhost.exe pid:   1924  
    Command line : "C:\Users\EdwardNygma7\Downloads\windows-patch-update\scvhost.exe"  
```  
  
---|---  
  
so as suspected we can see that the process is running from a suspicious location.

now let’s look if there are any more suspiction before getting into the process.

```
    1  
```

| 

```
    vol.py -f Damian.mem --profile Win7SP1x64 malfind  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
```  
  
| 

```
    [snip]  
    Process: explorer.exe Pid: 1532 Address: 0x4180000  
    Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE  
    Flags: CommitCharge: 16, MemCommit: 1, PrivateMemory: 1, Protection: 6  
      
    0x0000000004180000  41 ba 80 00 00 00 48 b8 38 a1 ee fd fe 07 00 00   A.....H.8.......  
    0x0000000004180010  48 ff 20 90 41 ba 81 00 00 00 48 b8 38 a1 ee fd   H...A.....H.8...  
    0x0000000004180020  fe 07 00 00 48 ff 20 90 41 ba 82 00 00 00 48 b8   ....H...A.....H.  
    0x0000000004180030  38 a1 ee fd fe 07 00 00 48 ff 20 90 41 ba 83 00   8.......H...A...  
      
    0x0000000004180000 41               INC ECX  
    0x0000000004180001 ba80000000       MOV EDX, 0x80  
    0x0000000004180006 48               DEC EAX  
    0x0000000004180007 b838a1eefd       MOV EAX, 0xfdeea138  
    0x000000000418000c fe07             INC BYTE [EDI]  
    0x000000000418000e 0000             ADD [EAX], AL  
    0x0000000004180010 48               DEC EAX  
    0x0000000004180011 ff20             JMP DWORD [EAX]  
    0x0000000004180013 90               NOP  
    0x0000000004180014 41               INC ECX  
    0x0000000004180015 ba81000000       MOV EDX, 0x81  
    0x000000000418001a 48               DEC EAX  
    0x000000000418001b b838a1eefd       MOV EAX, 0xfdeea138  
    0x0000000004180020 fe07             INC BYTE [EDI]  
    0x0000000004180022 0000             ADD [EAX], AL  
    0x0000000004180024 48               DEC EAX  
    0x0000000004180025 ff20             JMP DWORD [EAX]  
    0x0000000004180027 90               NOP  
    0x0000000004180028 41               INC ECX  
    0x0000000004180029 ba82000000       MOV EDX, 0x82  
    0x000000000418002e 48               DEC EAX  
    0x000000000418002f b838a1eefd       MOV EAX, 0xfdeea138  
    0x0000000004180034 fe07             INC BYTE [EDI]  
    0x0000000004180036 0000             ADD [EAX], AL  
    0x0000000004180038 48               DEC EAX  
    0x0000000004180039 ff20             JMP DWORD [EAX]  
    0x000000000418003b 90               NOP  
    0x000000000418003c 41               INC ECX  
    0x000000000418003d ba               DB 0xba  
    0x000000000418003e 83               DB 0x83  
    0x000000000418003f 00               DB 0x0  
    [snip]  
```  
  
---|---  
  
this is the only thing that looked suspicious as it spawned our malicious process.

this looks self modifying as well there seems to be a control flow change as well, but after few analysis there doesn’t seem to be any malciious activity.

let’s get into analysis of the process scvhost.exe’s binary

we can see that the binary is packed with UPX packer.

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-1.png)

so let’s unpack it

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-2.png)

Looking at the strings of the binary gives us some suspicious output, like

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-3.png)

so we will better start analysing it statically with ida.

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-4.png)

This initial bit seems straightforward, it’s checking the privilege with which the current process was launched. If it was launched as admin, then it proceeds, else it executes `runas svchost.exe`, which is standard to elevate privileges.

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-5.png)

here we can see that PEB is being meddled with unlinking the current process from the list using SeDebugPrivilege just like how prolaco malware does.  
in simpole words we can see that this is taking off the link to the current process from the previous node in the process list, and is making it point to the next process in the list. (processes in Windows are stored in the form of a linked list. So a process can be “hidden” by simply unlinking the “next” pointer from the previous process in the list and making it point to the one after the process we wish to hide).

So this function is simply to unlink the process from the process list. 

Next, inside both blocks of the if-else condition, lies this function

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-6.png)

This function is simply to hide the process from the task-manager list 

Next, we have this function 

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-7.png)

What this function does is, it sets the “priority-class” of the current process to “low”, effectively rendering it as ignored by the system unless and until it has no other jobs to perform. Coincidentally, this also does a good job at hiding the current task. 

These if else condition blocks are based on the response given by the user after the UAC (User Access Control) prompt is generated after `runas svchost.exe` is executed. 

Next up we have a plethora of anti-debug checks, which can be easily found by just visiting the function calls from here 

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-8.png)

so we have to either patch it or bypass it if we have to debug it.

The next function simply creates a `Notepad.exe` process 

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-9.png)

Now let us analyse this block

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-10.png)

`K32EnumProcess` is a Windows API to enumerate through all running processes on the system, and it retrieves an iterable with the PIDs of each such process. 

Keeping this knowledge in mind, we can make a good hunch saying that this is enumerating through the PID list of current running processes to try and find the PID of the `Notepad.exe` process that was just created prior. This is backed by the fact that it is iterating from 0 to the highest PID there is, and storing those in a variable and making a comparison against `Notepad.exe`. Hence, moving on. 

Next, it gets the handle to the environment variable `AZRAEL`  
After that, it XOR encrypts the content that the environment variable points to with the key `0x33`, and stores that in an array. 

let’s get the value of the environment variable AZRAEL

```
    1  
```

| 

```
    vol.py -f Damian.mem --profile Win7SP1x64 envars | grep -i AZRAEL  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
```  
  
| 

```
    Volatility Foundation Volatility Framework 2.6.1  
        1312 taskhost.exe         0x00000000002a1320 azrael                         batmanknightfall  
        1448 dwm.exe              0x00000000002c1320 azrael                         batmanknightfall  
        1532 explorer.exe         0x0000000002860a60 azrael                         batmanknightfall  
        2044 VBoxTray.exe         0x0000000000391320 azrael                         batmanknightfall  
        2668 iexplore.exe         0x0000000000131320 azrael                         batmanknightfall  
        2752 iexplore.exe         0x0000000000081320 azrael                         batmanknightfall  
        2892 iexplore.exe         0x0000000000541320 azrael                         batmanknightfall  
        1924 scvhost.exe          0x0000000000321320 azrael                         batmanknightfall  
        2320 notepad.exe          0x00000000001b1320 azrael                         batmanknightfall  
         596 RamCapture64.e       0x0000000000211320 azrael                         batmanknightfall  
```  
  
---|---  
  
now let’s xor the key with 0x33 and we get:

`QRG^R]X]ZT[GUR__`

After this, it opens a file in “read bytes” mode, called `confidential.bin`, and writes it in “write bytes” mode to another file called `windowsupdate.bin`. 

trying to dump as well as retreive both the files end in a failure as well mft has no data as well which might be because of aes encryption charset issue eventhough the file is not more than 1024 bytes long. 

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
```

| 

```
    MFT entry found at offset 0x8c2d6400  
    Attribute: In Use & File  
    Record Number: 1445  
    Link count: 2  
      
      
    $STANDARD_INFORMATION  
    Creation                       Modified                       MFT Altered                    Access Date                    Type  
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ----  
    2023-04-20 13:21:59 UTC+0000 2023-05-06 16:44:54 UTC+0000   2023-05-06 16:44:54 UTC+0000   2023-04-20 13:21:59 UTC+0000   Archive  
      
    $FILE_NAME  
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path  
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------  
    2023-04-20 13:21:59 UTC+0000 2023-04-20 13:21:59 UTC+0000   2023-04-20 13:21:59 UTC+0000   2023-04-20 13:21:59 UTC+0000   Windows\WINDOW~1.BIN  
      
    $FILE_NAME  
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path  
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------  
    2023-04-20 13:21:59 UTC+0000 2023-04-20 13:21:59 UTC+0000   2023-04-20 13:21:59 UTC+0000   2023-04-20 13:21:59 UTC+0000   Windows\windowsupdate.bin  
      
    $DATA  
      
      
    ***************************************************************************  
    ***********************************************************************  
```  
  
---|---  
  
Next up, it takes the encrypted environment variable that we have, then performs an AES decryption using that as the key. We know that it is AES-ECB by looking at standard AES operations being performed in the binary, such as `sub_bytes` and `substitution`. 

Also another dead giveaway is that it is being performed upon multiples of 16 bytes each 

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-11.png)

This AES decrypted data is then taken and put through another encryption scheme, namely 

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-12.png)

This seems like a pretty simple encryption, since we already have all the runtime values of the keys and values being used here (key depends on the value that we set the `AZRAEL` environment variable to)  
A decryption algorithm for the above encryption would look as follows: 

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
```

| 

```
    int a=1;  
    for (int i = 0; i < size; i++)   
    {  
        plaintext[i] = plaintext[i] ^ env_var[i % encsize];  
        plaintext[i] = plaintext[i] - ((i + a) % 10);  
        plaintext[i] = plaintext[i] ^ env_var[i % encsize];  
        plaintext[i] = plaintext[i] - ((i + a) % 10);  
        a++;  
    }  
```  
  
---|---  
  
This next block we can see

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-13.png)

VirtualAllocEx, WriteProcessMemory, GetModuleHandleA(“Kernel32”) are all very very common indicators of a DLL injection being undergone, and in our case, the DLL being injected is Msvrct.dll.

After injecting the dll, the malware seems to be going on a spree of deleting a bunch of windows registry keys clearing forensic evidences, trying to cover up all evidences of its actions. It even deletes confidential.bin, and then deletes any evidences of itself having deleted it.

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-14.png)

This is trying to delete a subkey named `Notepad.exe` under the key opened right before this. The registry keys for this handle are deleted both under the 64-bit and 32-bit mode - as some applications might have separate entries open for both architecture modes. 

Furthermore, specific files from the Windows file system are targeted and removed based on their relation to user activity logs (in this case our malware), history, or cache files. 

as well we can see that the encrypted strings not unallocated or flushed.

so we have two ways to get the flag here.

  1. as we know the encrypted content from teh file ois decrypted and then goes through the encryption algorithm of xor and shifts, so we can give the flag format into it , which gives us “`q2sWRN”. then we can dump all the vads/heaps of the process and grep from them/ do a search for it or we can get them from the vads listing easily by using Memprocfs


```
    1  
```

| 

```
    vol.py -f Damian.mem --profile Win7SP1x64 vaddump -p 1924 -D vads/  
```  
  
---|---

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
    10  
    11  
    12  
    13  
    14  
    15  
    16  
    17  
    18  
    19  
    20  
    21  
    22  
    23  
    24  
    25  
    26  
    27  
    28  
    29  
    30  
    31  
    32  
    33  
    34  
    35  
    36  
    37  
    38  
    39  
    40  
    41  
    42  
    43  
    44  
    45  
    46  
    47  
    48  
    49  
    50  
    51  
```  
  
| 

```
    Volatility Foundation Volatility Framework 2.6.1  
    Pid        Process              Start              End                Result  
    ---------- -------------------- ------------------ ------------------ ------  
          1924 scvhost.exe          0x000000007ffe0000 0x000000007ffeffff vads/scvhost.exe.11ff67b30.0x000000007ffe0000-0x000000007ffeffff.dmp  
          1924 scvhost.exe          0x0000000000110000 0x000000000030ffff vads/scvhost.exe.11ff67b30.0x0000000000110000-0x000000000030ffff.dmp  
          1924 scvhost.exe          0x0000000000040000 0x0000000000040fff vads/scvhost.exe.11ff67b30.0x0000000000040000-0x0000000000040fff.dmp  
          1924 scvhost.exe          0x0000000000020000 0x000000000002ffff vads/scvhost.exe.11ff67b30.0x0000000000020000-0x000000000002ffff.dmp  
          1924 scvhost.exe          0x0000000000010000 0x000000000001ffff vads/scvhost.exe.11ff67b30.0x0000000000010000-0x000000000001ffff.dmp  
          1924 scvhost.exe          0x0000000000030000 0x0000000000033fff vads/scvhost.exe.11ff67b30.0x0000000000030000-0x0000000000033fff.dmp  
          1924 scvhost.exe          0x0000000000060000 0x00000000000c6fff vads/scvhost.exe.11ff67b30.0x0000000000060000-0x00000000000c6fff.dmp  
          1924 scvhost.exe          0x0000000000050000 0x0000000000050fff vads/scvhost.exe.11ff67b30.0x0000000000050000-0x0000000000050fff.dmp  
          1924 scvhost.exe          0x00000000000e0000 0x00000000000e0fff vads/scvhost.exe.11ff67b30.0x00000000000e0000-0x00000000000e0fff.dmp  
          1924 scvhost.exe          0x00000000000d0000 0x00000000000d0fff vads/scvhost.exe.11ff67b30.0x00000000000d0000-0x00000000000d0fff.dmp  
          1924 scvhost.exe          0x0000000077020000 0x0000000077119fff vads/scvhost.exe.11ff67b30.0x0000000077020000-0x0000000077119fff.dmp  
          1924 scvhost.exe          0x00000000004a0000 0x000000000059ffff vads/scvhost.exe.11ff67b30.0x00000000004a0000-0x000000000059ffff.dmp  
          1924 scvhost.exe          0x0000000000490000 0x000000000049ffff vads/scvhost.exe.11ff67b30.0x0000000000490000-0x000000000049ffff.dmp  
          1924 scvhost.exe          0x0000000000320000 0x000000000041ffff vads/scvhost.exe.11ff67b30.0x0000000000320000-0x000000000041ffff.dmp  
          1924 scvhost.exe          0x0000000001d20000 0x0000000001f1ffff vads/scvhost.exe.11ff67b30.0x0000000001d20000-0x0000000001f1ffff.dmp  
          1924 scvhost.exe          0x0000000000730000 0x00000000008b0fff vads/scvhost.exe.11ff67b30.0x0000000000730000-0x00000000008b0fff.dmp  
          1924 scvhost.exe          0x00000000005a0000 0x0000000000727fff vads/scvhost.exe.11ff67b30.0x00000000005a0000-0x0000000000727fff.dmp  
          1924 scvhost.exe          0x00000000008c0000 0x0000000001cbffff vads/scvhost.exe.11ff67b30.0x00000000008c0000-0x0000000001cbffff.dmp  
          1924 scvhost.exe          0x0000000002470000 0x000000000266ffff vads/scvhost.exe.11ff67b30.0x0000000002470000-0x000000000266ffff.dmp  
          1924 scvhost.exe          0x00000000020b0000 0x00000000022affff vads/scvhost.exe.11ff67b30.0x00000000020b0000-0x00000000022affff.dmp  
          1924 scvhost.exe          0x00000000026b0000 0x00000000028affff vads/scvhost.exe.11ff67b30.0x00000000026b0000-0x00000000028affff.dmp  
          1924 scvhost.exe          0x0000000077240000 0x00000000773e8fff vads/scvhost.exe.11ff67b30.0x0000000077240000-0x00000000773e8fff.dmp  
          1924 scvhost.exe          0x0000000077120000 0x000000007723efff vads/scvhost.exe.11ff67b30.0x0000000077120000-0x000000007723efff.dmp  
          1924 scvhost.exe          0x000000007f0e0000 0x000000007ffdffff vads/scvhost.exe.11ff67b30.0x000000007f0e0000-0x000000007ffdffff.dmp  
          1924 scvhost.exe          0x000000007efe0000 0x000000007f0dffff vads/scvhost.exe.11ff67b30.0x000000007efe0000-0x000000007f0dffff.dmp  
          1924 scvhost.exe          0x000007fefefe0000 0x000007feff0bafff vads/scvhost.exe.11ff67b30.0x000007fefefe0000-0x000007feff0bafff.dmp  
          1924 scvhost.exe          0x000007fefd570000 0x000007fefd58efff vads/scvhost.exe.11ff67b30.0x000007fefd570000-0x000007fefd58efff.dmp  
          1924 scvhost.exe          0x000007fefd020000 0x000007fefd076fff vads/scvhost.exe.11ff67b30.0x000007fefd020000-0x000007fefd076fff.dmp  
          1924 scvhost.exe          0x000000013f130000 0x000000013f22afff vads/scvhost.exe.11ff67b30.0x000000013f130000-0x000000013f22afff.dmp  
          1924 scvhost.exe          0x000007fefd4f0000 0x000007fefd55afff vads/scvhost.exe.11ff67b30.0x000007fefd4f0000-0x000007fefd55afff.dmp  
          1924 scvhost.exe          0x000007fefd0c0000 0x000007fefd0cefff vads/scvhost.exe.11ff67b30.0x000007fefd0c0000-0x000007fefd0cefff.dmp  
          1924 scvhost.exe          0x000007fefd560000 0x000007fefd56dfff vads/scvhost.exe.11ff67b30.0x000007fefd560000-0x000007fefd56dfff.dmp  
          1924 scvhost.exe          0x000007fefe0c0000 0x000007fefe1ecfff vads/scvhost.exe.11ff67b30.0x000007fefe0c0000-0x000007fefe1ecfff.dmp  
          1924 scvhost.exe          0x000007fefd590000 0x000007fefd5f6fff vads/scvhost.exe.11ff67b30.0x000007fefd590000-0x000007fefd5f6fff.dmp  
          1924 scvhost.exe          0x000007fefdfa0000 0x000007fefe068fff vads/scvhost.exe.11ff67b30.0x000007fefdfa0000-0x000007fefe068fff.dmp  
          1924 scvhost.exe          0x000007fefe250000 0x000007fefefd7fff vads/scvhost.exe.11ff67b30.0x000007fefe250000-0x000007fefefd7fff.dmp  
          1924 scvhost.exe          0x000007fffffb0000 0x000007fffffd2fff vads/scvhost.exe.11ff67b30.0x000007fffffb0000-0x000007fffffd2fff.dmp  
          1924 scvhost.exe          0x000007feff430000 0x000007feff4a0fff vads/scvhost.exe.11ff67b30.0x000007feff430000-0x000007feff4a0fff.dmp  
          1924 scvhost.exe          0x000007feff280000 0x000007feff31efff vads/scvhost.exe.11ff67b30.0x000007feff280000-0x000007feff31efff.dmp  
          1924 scvhost.exe          0x000007feff250000 0x000007feff27dfff vads/scvhost.exe.11ff67b30.0x000007feff250000-0x000007feff27dfff.dmp  
          1924 scvhost.exe          0x000007feff320000 0x000007feff428fff vads/scvhost.exe.11ff67b30.0x000007feff320000-0x000007feff428fff.dmp  
          1924 scvhost.exe          0x000007feff560000 0x000007feff560fff vads/scvhost.exe.11ff67b30.0x000007feff560000-0x000007feff560fff.dmp  
          1924 scvhost.exe          0x000007fffffd9000 0x000007fffffdafff vads/scvhost.exe.11ff67b30.0x000007fffffd9000-0x000007fffffdafff.dmp  
          1924 scvhost.exe          0x000007fffffd7000 0x000007fffffd8fff vads/scvhost.exe.11ff67b30.0x000007fffffd7000-0x000007fffffd8fff.dmp  
          1924 scvhost.exe          0x000007fffffd5000 0x000007fffffd6fff vads/scvhost.exe.11ff67b30.0x000007fffffd5000-0x000007fffffd6fff.dmp  
          1924 scvhost.exe          0x000007fffffdd000 0x000007fffffdefff vads/scvhost.exe.11ff67b30.0x000007fffffdd000-0x000007fffffdefff.dmp  
          1924 scvhost.exe          0x000007fffffdb000 0x000007fffffdcfff vads/scvhost.exe.11ff67b30.0x000007fffffdb000-0x000007fffffdcfff.dmp  
          1924 scvhost.exe          0x000007fffffdf000 0x000007fffffdffff vads/scvhost.exe.11ff67b30.0x000007fffffdf000-0x000007fffffdffff.dmp  
```  
  
---|---  
  
![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-18.png)

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-15.png)

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-16.png)

![alt text](https://blog.bi0s.in/2024/03/05/Forensics/BatmanInvestigationI-LikeFatherLikeSon-bi0sCTF2024/image-17.png)

```
    1  
```

| 

```
    `q2sWRN-ne~5a:v"L}7	uc4tVaT@7Xo#wg2w5w0w!q4LfirLz5{3D1Vaxj2Jc0EaKtF5faD15  
```  
  
---|---  
  
  2. we can patch the binary to bypass the anti-debugging checks and then debug it to find distance from some known address to the encrypted string heap address with a pointer in the stack where as of now we know the key or setting up a decoy key in our debug environment and finding the distance between the key and the pointer to the encrypted string and with that we can get the address of key and then the encrypted memory, list all the mapped memory and get the encrypyted 60 bytes using this way.


by either of the method, we get the encrypted string

```
    1  
    2  
```

| 

```
    `q2sWRN-ne~5a:v"L}7	uc4tVaT@7Xo#wg2w5w0w!q4LfirLz5{3D1Vaxj2Jc0EaKtF5faD15  
```  
  
---|---  
  
so writing a reverse script for it

```
    1  
    2  
    3  
    4  
    5  
    6  
    7  
    8  
    9  
```

| 

```
        ada=1;  
    for (int i = 0; i < size; i++)   
        {  
     plaintext[i]=plaintext[i]^env_var[i%encsize];  
     plaintext[i] = plaintext[i] - ((i+ada)%10);  
      plaintext[i]=plaintext[i]^env_var[i%encsize];  
     plaintext[i] = plaintext[i] - ((i+ada)%10);  
     ada++;  
         }  
```  
  
---|---  
  
we get the flag

### flag

```
    1  
```

| 

```
    bi0sCTF{M4lw4r3_4n4ly51s_4nd_DF1R_1s_4w3s0m3_4nd_4ppr3c14t3d_th4t_y0u_s0lv3d_<33}  
```  
  
---|---  
  
## Closing Note

Thank you to everyone who tried the challenge and congratulations to the 3 teams who solved it: idek, kalmarunionen and C4T BuT S4D. We thank you for playing the CTF and would love to hear some feedback about the challenge.  
If you have any queries regarding the challenge, feel free to hit me up over twitter/discord.

**Contact** : Azr43lKn1ght | [twitter](https://twitter.com/Azr43lKn1ght) | [Linkedin](https://www.linkedin.com/in/azr43lkn1ght?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app) | [github](https://github.com/Azr43lKn1ght)

* * *

__2026-08-31

[__bi0sCTF](https://blog.bi0s.in/tags/bi0sCTF/)

[__Memory Forensics](https://blog.bi0s.in/tags/Memory-Forensics/)

[__Incident Response](https://blog.bi0s.in/tags/Incident-Response/)

[__Malware Analysis](https://blog.bi0s.in/tags/Malware-Analysis/)

[__WinDBG Dump Debugging](https://blog.bi0s.in/tags/WinDBG-Dump-Debugging/)

[__Threat Hunting](https://blog.bi0s.in/tags/Threat-Hunting/)

###### __Previous

####  [ Image Gallery - bi0sCTF 2024 ](https://blog.bi0s.in/2024/03/06/Web/ImageGallery1-bi0sCTF2024/ "Image Gallery - bi0sCTF 2024")

######  [__bi0sCTF2024](https://blog.bi0s.in/tags/bi0sCTF2024/)

###### Next  __

####  [ baeBPF - bi0sCTF 2024 ](https://blog.bi0s.in/2024/03/03/RE/baeBPF-bi0sCTF2024/ "baeBPF - bi0sCTF 2024")

######  [__bi0sCTF](https://blog.bi0s.in/tags/bi0sCTF/) [__eBPF](https://blog.bi0s.in/tags/eBPF/)
