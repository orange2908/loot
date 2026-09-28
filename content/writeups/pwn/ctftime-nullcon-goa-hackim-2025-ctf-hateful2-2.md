---
title: "hateful2 - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "tcache", "unsorted-bin", "use-after-free", "safe-linking", "tcache-poisoning", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Starting off i patched the binary"
source:
  name: "CTFtime writeup #39911"
  url: "https://ctftime.org/writeup/39911"
original_source: "https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#hateful-2"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful2
- **Author team:** QnQSec
- **CTFtime:** <https://ctftime.org/writeup/39911>
- **Original writeup:** <https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#hateful-2>

---
![image](<https://github.com/user-attachments/assets/d4def1c1-b27d-4006-baa8-302f903bed17>)

Starting off i patched the binary  
![image](<https://github.com/user-attachments/assets/a30b10a4-cac6-4079-a6ed-24473dac87b5>)

We can see that all protections are enabled

Running the binary shows this menu like option  
![image](<https://github.com/user-attachments/assets/d527d1c6-2db5-4387-92cd-e1c2f5f7957f>)

We can assume this is probably going to be a heap exploitation

I loaded it up in IDA and here's the main function  
![image](<https://github.com/user-attachments/assets/34ec67ef-b066-4e54-a546-f5c6d433ee55>)

The binary isn't striped so there's no need for reversing much here

I'll walkthrough the important details of what each function does

`about_us`:  
![image](<https://github.com/user-attachments/assets/b63ecdad-e040-430c-811b-f7ae344366ea>)

\- This function essentially leaks a stack address, so let's keep that in mind

`add_message`:  
![image](<https://github.com/user-attachments/assets/cd8bf061-2ff7-4d79-a219-2ce7ae8a3f31>)

\- We can only make up to 16 allocations  
\- We control the size of the memory to be allocated

`edit_message`:  
![image](<https://github.com/user-attachments/assets/105d9a65-b317-4ee8-ad52-7bfa13a70ee9>)

\- This is used to edit the content of the memory stored in the global allocations variable at the specified index

`view_message`:  
![image](<https://github.com/user-attachments/assets/b1fdb0aa-45d8-4734-a66f-bcfd72a0e862>)

\- Prints the content of the memory at the specified index of the allocations variable

`remove_message`:  
![image](<https://github.com/user-attachments/assets/a323ec54-e7d2-47e6-96f9-90a8c6daccc7>)

\- Used for memory deallocation  
\- It doesn't set the memory freed to null so a UAF is possible

Based on what we've gathered so far, this is just a standard heap exploitation and the vulnerability is a UAF

Which we will leverage that to get code execution

We are working with glibc 2.36  
![image](<https://github.com/user-attachments/assets/53d3d4c3-b67d-4272-8573-380679b1800a>)

So that version has safe linking enabled and no hooks, but because we have a stack leak we can write over main return addres our ropchain

Since this uses the tcache bin we will leverage a UAF to perform tcache poisoning but for that we need to get a heap leak in order to break the safe linking mechanism

Our step is as follow:  
\- Leak libc & heap  
\- Corrupt tcache->next to get overlapping chunk to the stack address  
\- Write ropchain on stack  
\- Leave program to trigger ropchain

For getting a libc leak we can easily take advantage of the fact that we control the size of the memory to be allocated

Just simply allocate a chunk that's greater than the size the tcache bin can hold `1032 bytes` then on freeing it, the chunk will be placed in the unsorted bin

And since the unsorted bin fd/bk will be pointing to the main_arena struct (during it's first use) we can read that and essentially get a libc leak

To get a heap leak, we just free a chunk that will be placed in the tcache bin, that way it's fd will point to a heap address

One other thing we need to handle is tcache misaligned chunk check, the stack return address of the main function isn't alligned so we just subtract it by 8 to make it alligned 

And with that we're set to go

Here's my [exploit](<https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/Hateful%202/solve.py>)  
![image](<https://github.com/user-attachments/assets/e730d2aa-374b-4479-a52c-837c390189e0>)

Running it works remotely  
![image](<https://github.com/user-attachments/assets/489b27c2-5d35-4f73-b687-305cf49e0337>)

```  
Flag: ENO{W3_4R3_50RRY_4G41N_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}  
```
