---
title: "format-string - corCTF 2024"
category: "pwn"
subcategory: "format-string"
type: "writeup"
tags: ["pwn", "formatstring", "format-string", "shellcode", "checksec", "scanf", "floating-point", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #39399"
  url: "https://ctftime.org/writeup/39399"
original_source: "https://sashactf.gitbook.io/pwn-notes/ctf-writeups/cor-ctf-2024/format-string"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "format-string"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** format-string
- **Author team:** Sashastone
- **CTFtime tags:** formatstring
- **CTFtime:** <https://ctftime.org/writeup/39399>
- **Original writeup:** <https://sashactf.gitbook.io/pwn-notes/ctf-writeups/cor-ctf-2024/format-string>

---
For the complete documentation index, see [llms.txt](https://sashactf.gitbook.io/pwn-notes/llms.txt). This page is also available as [Markdown](https://sashactf.gitbook.io/pwn-notes/ctf-writeups/corctf-2024/format-string.md).

## Introduction

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FLctB5JhDP1KOiHBsYHCD%252Fimage.png%3Falt%3Dmedia%26token%3D8a5791f5-3a5e-4c9b-a1ad-c1735d0592fa&width=768&dpr=3&quality=100&sign=e0b0aeab7d02c0d32db1b6345b9c5a5e&sv=3)

`format-string` was the easy pwn challenge from this CTF, which I unfortunately only managed to solve 1 hour after the CTF concluded due to my focus on another pwn challenge `corchat_v3`. While the description claims you'll learn nothing, I would argue that the mechanisms which allow this challenge to be solvable at all are interesting, even if they're quite lucky.

## Reversing

Running `pwn checksec` reveals we have maximum protections (minus `FORTIFY`).

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FoyE1gcaUUGiI8ZZY3DRY%252Fimage.png%3Falt%3Dmedia%26token%3Dc33e5fa9-98bd-41bb-a9b9-3d966c032595&width=768&dpr=3&quality=100&sign=772ea9e133a603ccb290279c2040b56d&sv=3)

We're also given the source code and, given the name of the challenge, it's very obvious to spot that the problem here is ~~using C~~ a `printf` vuln in the aptly-named `do_printf`.

### do_printf

It uses `scanf("%3s", buf)` to read in the format string, meaning we only have a maximum of 3 characters (plus a null byte) to construct a format string. This is barely enough to do anything meaningful, and immediately rules out anything like `%n` overwrites or `%[num]$p` leaks.

### do_call

We also have `do_call`, which prompts us for the memory address of a function to call with `/bin/sh`. The obvious idea here is to use `system`, and we get our shell, but for that we'd need a libc leak.

So the plan would seem obvious:

  1. Use `do_printf` to leak libc

  2. Use `do_call` to get a shell


## Leaking libc

So with the size restriction of 3 characters, what do we have available?

  * We only have enough room for 1 format string

  * Any of the regular specifiers of the form: `%[specifier]` (here's a [list of specifiers](https://cplusplus.com/reference/cstdio/printf/))

  * We can pad specifiers: `%[0-9][specifier]`

  * We can use variable width specifiers: `%*[specifier]`


The description tells us that it's a common specifier, so let's try `%p`:

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FBpFsH60bSqcmmjNJap65%252Fimage.png%3Falt%3Dmedia%26token%3Dabe47cdf-21e7-45f4-ad8d-a940e0a64c67&width=768&dpr=3&quality=100&sign=348fcd5e39a75336318b94ab48fe265a&sv=3)

Before `printf("%p")`

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FNFa2BjzuyzcINIEoSEnH%252Fimage.png%3Falt%3Dmedia%26token%3D55d428b9-fa76-4b60-87f5-5912d6c92212&width=768&dpr=3&quality=100&sign=dfdebc4103779ae90e143cc310eccfb0&sv=3)

After `printf("%p")`

`%p` (and most specifiers that we can use) will access the first argument (besides the format string), so it looks at `rsi`. In our case, it just so happens that `rsi` is set to some stack address after the first `printf("Here: ")`, which also interestingly points to the string `Here: ` ~~(I'm sure that won't be significant later)~~.

So we can get a stack leak at the very least, but this doesn't help much. `NX` is enabled, so we can't jump to the stack, but even if we could, we'd struggle to write any shellcode due to the small buffer size.

Many of the remaining specifiers aren't very useful either, as most of them would be different ways of printing integers, so they'd only print that stack address back to us, but just in different forms. `%s` doesn't seem that useful at first either, as it would just print `Here: ` back to us.

### Floating point?

One idea I had however was floating point specifiers like `%f`. The reason these are interesting is because they would access different arguments, as in, they wouldn't use `rsi`. To see this, let's have a closer look at [printf](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/printf.c#L27):

Not much to see here, except for the use of variadic arguments using `va_list`. You'll probably be familiar with the fact that `va_list` allows for an unlimited number arguments. It stores the argument registers, plus a pointer to the stack arguments. But it doesn't just store the general purpose (gp) registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`), it can also store the floating point (fp) registers (`xmm0-7`):

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252F6MDRZOhUqBEfFOJrlHcO%252Fimage.png%3Falt%3Dmedia%26token%3D5926cb7e-ede6-4cc7-97f0-6a69dd214ae6&width=768&dpr=3&quality=100&sign=89d75142f4683c97a44bc4e0723f96f4&sv=3)

Here we see that the fp registers can be saved to `[rsp+0x50]` if `al != 0`, because in a call to a variadic function, `al` contains the number of fp registers used as arguments, so if any fp registers are used, we should save them.

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FLMd6fpZzACDz1pZXZmMP%252Fimage.png%3Falt%3Dmedia%26token%3D408f3615-d4fd-4f47-bae9-771e88139dc6&width=768&dpr=3&quality=100&sign=e223c482ba2e1e4af099fec50a2613f3&sv=3)

Since the program doesn't use floating point arguments, it sets `al` to `0` both times, which means that section of memory is left uninitialised, and if we're lucky, could have a libc address.

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FL8Rvl0cFD7c8W3oHD3pS%252Fimage.png%3Falt%3Dmedia%26token%3D0a0637c3-21a4-4b61-875d-36feee523c8c&width=768&dpr=3&quality=100&sign=e1bd868495d7b0ef241dcc6dde95dcf9&sv=3)

First fp argument

And it seems like we may have been lucky? If we can use a floating point specifier which can cover the full 16 bytes, we may be able to leak it as a floating point number, then convert it back. Unfortunately there is no such specifier.

`%f` is a `float` (32 bits) and `%lf` is a `double` (64 bits), which aren't enough to cover it. While there is `%Lf`, which is for a `long double`, on x86 this only covers 80 bits, not 128. Also it seems that these `long double` arguments are passed using the stack, and so it won't be accessing `[rsp+0x50]` anyway, it'll instead use the stack arguments (which overlap with the `do_printf` buffer), which are useless for us:

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FusGKS10XuJEccluSur5i%252Fimage.png%3Falt%3Dmedia%26token%3Dcb1547ca-fbfd-4f2f-955d-efdf7dd25b62&width=768&dpr=3&quality=100&sign=71e8efbf2db98a65917a6df98ef8bf13&sv=3)

Stack arguments

### %s

It turns out that the description wasn't lying when it said it was a widely used specifier (shocker). But doesn't `%s` just leak the string `Here: `?

Well, my teammate [ir0nstone](https://x.com/ir0nstone) found something interesting that happens when you do `%p` then `%s`:

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252F64GJtLrTb8l81gBqTDf2%252Fimage.png%3Falt%3Dmedia%26token%3D20edd22e-adc5-4f3b-9a7f-9a1be62a786e&width=768&dpr=3&quality=100&sign=6347180bf1507cefb95e3adf01689398&sv=3)

`%p` then `%s`

The 2nd `%s` now contains the tail end of the `%p` output, which is quite interesting. It implies that `rsi` points to some internal stack buffer that the output gets copied to.

So what if now you do `%s` followed by some character. In theory, this could append the character to the buffer, as it would output the current buffer + an extra character, which must be copied to this buffer.

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252F1ZsRn2R1r2ZGzDjzWNGU%252Fimage.png%3Falt%3Dmedia%26token%3D91258cff-37bd-43dd-9a41-5066f8e31abf&width=768&dpr=3&quality=100&sign=8f6ed70d0ba5402d3b8bda1499569eff&sv=3)

Appending characters

And sure enough this works! Now if this is just some stack buffer, there could be uninitialised stack data inside it, which we could pad up to and print back to us. We can verify this with the following script:

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FnnS9kKzyUmZoxMAezifm%252Fimage.png%3Falt%3Dmedia%26token%3D1898a561-541a-46e1-b93e-7576915e9ded&width=768&dpr=3&quality=100&sign=d13fe8f09556ad0426dd762bf9490fc2&sv=3)

Finding stack data

### Hang on, what?

This is some weird behaviour, and seems quite lucky for us (which it is). Understandably I had questions.

#### The buffer

First of all, what is this stack buffer? And also why is there a buffer at all, isn't `stdout` supposed to be unbuffered?

To answer these, let's look further into `printf`. We saw that it calls [vfprintf](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/vfprintf-internal.c#L1288), so lets start there.

It starts off by doing some sanity checks, but then checks if the file is unbuffered, and if it is, it will call [buffered_vfprintf](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/vfprintf-internal.c#L2343):

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FXl28m8ftibSsxT4OYiYM%252Fimage.png%3Falt%3Dmedia%26token%3D7fee9175-8ac7-4f52-b4c1-e04b4327e15a&width=768&dpr=3&quality=100&sign=5bcdb08bff872b124c0bc7082e482e91&sv=3)

[vfprintf](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/vfprintf-internal.c#L1343)

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252Fk5vsZKQPT0wdNJTGMBv8%252Fimage.png%3Falt%3Dmedia%26token%3D9f8c4577-a433-4c02-aede-56220792d128&width=768&dpr=3&quality=100&sign=194c2f370844b9105b636824b6f9cf9c&sv=3)

`buffered_vfprintf`

It seems that when the file is unbuffered, it creates a "helper file" on the stack that uses a _stack buffer_ , and then it prints to the "helper file". This seems like such a hack (cos it is), but thankfully it helps us out, because `CHAR_T buf[BUFSIZ]` is where the output goes before it's written out.

#### Why in rsi?

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FWIbggLFdUp9eQ8TcAngJ%252Fimage.png%3Falt%3Dmedia%26token%3Da16e5c34-0025-40e4-9a33-2af4324a9aca&width=768&dpr=3&quality=100&sign=e2099ee0a4e1205d01f47041ff30dbbb&sv=3)

<https://elixir.bootlin.com/glibc/glibc-2.31/source/stdio-common/vfprintf-internal.c#L2395>

After it gets printed to the "helper file", the output sits in the stack buffer, and now needs to be written out to stdout. It does this by calling [_IO_sputn](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L1197), which goes on to call the `write` syscall in [_IO_new_file_write](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L1173).

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252Fg31ZkafUhpE2yAJgpFzi%252Fimage.png%3Falt%3Dmedia%26token%3D040fe659-5c69-497f-9d16-d0fa3a2ef091&width=768&dpr=3&quality=100&sign=d5dbc951c8d7d834067af7380534066c&sv=3)

Invoking `write` syscall

This is where `rsi` would be set to the buffer, and from this point the `rsi` register remains untouched. The main reason for this is the fact that no function calls (with 2+ arguments) take place after this, so it never gets clobbered.

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FA7D6k1JgDY1UMESQIZcG%252Fimage.png%3Falt%3Dmedia%26token%3D52a00ac1-9de4-4acd-a2fe-a7322da4d5d4&width=768&dpr=3&quality=100&sign=099774286aecec19dceed52ca6b8f289&sv=3)

[new_do_write](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L449)

![](https://sashactf.gitbook.io/pwn-notes/~gitbook/image?url=https%3A%2F%2F281452579-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FO4GaVx6h6D06xlxKSULj%252Fuploads%252FuL2hRsYJPoIuNCsgYAfc%252Fimage.png%3Falt%3Dmedia%26token%3De65c3b3d-f5d3-4b31-bdec-041b6b5dcf9b&width=768&dpr=3&quality=100&sign=c32750722423510688a3abff6a12ac92&sv=3)

[_IO_new_file_xsputn](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L1255)

However there is still an element of "luck", because `rdi` is clobbered by `_IO_funlockfile` (see [here](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets#io_stdfile_0_lock-in-rdi)), and `rdx` gets clobbered as a scratch register.

### ld leak to libc leak

In my solution I used the first address I found (the one found by the script) for my leak. Unfortunately this address was an ld address (`_dl_process_pt_note+539`), not libc. However, due to how the libraries are mapped, for each system the offsets between the libraries are deterministic, so we can convert this into a libc leak.

The offset for my system was `0x1f4000`, but remotely I had to fiddle a bit to find that it was `0x1f6000` (not the cleanest way to do it, but oh well).

## Solution

Armed with a libc leak, we can now call `do_call` and get RCE.

## Alternative Solution

The above is my solution, but there was another approach that was shared on the discord after the event finished, which involved the variable width specifier: `%*x`.

The variable width specifier allows the user to specify the width for an argument as an argument:

This can be useful in some printf exploits using `%n`, as you can use the lower 32 bits of an address as a width, and print a variable number of bytes depending on that address (here's an [example](https://violenttestpen.github.io/ctf/pwn/2021/06/06/zh3r0-ctf-2021/)).

In our case however, it would use `rsi` as a width and, since thats an address, it will print **a lot** of bytes (most of which are spaces). This is useful because this amount of printing will fill up the buffer, and then when another function is called (like `scanf`), it will clobber the stack buffer with its stack usage, leaving behind addresses. Now the buffer has spaces padding up to some address, which in our case happens to be `_IO_2_1_stdin_`, which we can print.

Below is my implementation of this solution (I opted to find a process with a low width, so that the exploit would run quicker remotely).

[PreviouscorCTF 2024](https://sashactf.gitbook.io/pwn-notes/ctf-writeups/corctf-2024)[Nextcorchat v3](https://sashactf.gitbook.io/pwn-notes/ctf-writeups/corctf-2024/corchat-v3)

Last updated 2 years ago
