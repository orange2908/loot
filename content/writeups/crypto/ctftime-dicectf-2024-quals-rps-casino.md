---
title: "rps-casino - DiceCTF 2024 Quals"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "xor", "lcg", "prng", "z3", "rps-casino", "dicectf-2024-quals", "2024", "ctf-writeup"]
summary: "lolipop included in Writeups"
source:
  name: "CTFtime writeup #38991"
  url: "https://ctftime.org/writeup/38991"
original_source: "https://tsumiiiiiiii.github.io/dice24_rps_casino/"
ctf:
  name: "DiceCTF 2024 Quals"
  year: 2024
  challenge: "rps-casino"
---

## Metadata

- **CTF:** DiceCTF 2024 Quals
- **Task:** rps-casino
- **Author team:** IUT GENESIS
- **CTFtime:** <https://ctftime.org/writeup/38991>
- **Original writeup:** <https://tsumiiiiiiii.github.io/dice24_rps_casino/>

---
# DiceCTF 2024 - rps casino

[ __lolipop](https://tsumiiiiiiii.github.io "Author") included in [__Writeups](https://tsumiiiiiiii.github.io/categories/writeups/)

 __ 2024-02-19  __1773 words __9 minutes

Writeup for the rps-casino Cryptography challenge.

This problem costed me a good 20 hours because of some stupid `z3` gimmick. I think if not for that, could have solved this problem in 2 hours at max, which would have let me to dedicate more time for a 3rd crypto solve smh 😫.

This is the program script:

```
    #!/usr/local/bin/python
    
    import os
    from Crypto.Util.number import bytes_to_long
    
    def LFSR():
      state = bytes_to_long(os.urandom(8))
      while 1:
        yield state & 0xf
        for i in range(4):
          bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1
          state = (state >> 1) | (bit << 63)
    
    rng = LFSR()
    n = 56
    
    print(f"Let's play rock-paper-scissors! We'll give you {n} free games, but after that you'll have to beat me 50 times in a row to win. Good luck!")
    
    rps = ["rock", "paper", "scissors", "rock"]
    nums = []
    
    for i in range(n):
      choice = next(rng) % 3
      inp = input("Choose rock, paper, or scissors: ")
      if inp not in rps:
        print("Invalid choice")
    
        exit(0)
    
      if inp == rps[choice]:
        print("Tie!")
    
      elif rps.index(inp, 1) - 1 == choice:
        print("You win!")
      else:
        print("You lose!")
    
    for i in range(50):
      choice = next(rng) % 3
      inp = input("Choose rock, paper, or scissors: ")
      if inp not in rps:
        print("Invalid choice")
        break
        
      if rps.index(inp, 1) - 1 != choice:
        print("Better luck next time!")
        break
    
      else:
        print("You win!")
    
    else:
      print(open("flag.txt").read())
```

The problem flow is as follows:

  * We have to play 56 rounds of `rock-paper-scissors` against the server. Whatever the result is in those rounds, it does not matter.
  * Then we have to play 50 rounds more and win all of them. If we are successful, `flag` will be printed.
  * In both these steps, the computer’s move is generated through a function called `LFSR`.


## Understanding `LFSR`

`Linear Feedback Shift Register` or in short `LFSR` are random number generators where the output bits depend on some linear combinations of the previous bits. ![https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/dice24/lfsr_pic.svg?raw=true](https://tsumiiiiiiii.github.io/svg/loading.min.svg) Let us try to understand how an LCG works with the help of the above figure.

  * The bits $s_0s_1…s_7 \ \ \forall s_i \in \\{0, 1\\}$ represent the $seed$ or the `initial state` of the LFSR. If $seed$ is somehow compromised, the whole secrecy of the LFSR is lost.
  * Since there are 8 initial bits, this is a $8 \ bit$ LFSR.
  * As previously mentioned, the next bits ($s_8s_{9}…s_n…$) depend on some linear combination of the previous bits.
  * $XOR$ is the linear operation here(actually $xor$ is not linear in terms of traditional math, but under some specific circumstances, it does become linear which we will see in a bit). $s_8 = s_6 \ \oplus \ s_5 \ \oplus s_4 \ \oplus s_0$
  * Notice how $s_8$ depends only $s_6, s_5, s_4, s_0$ and not all of the state bits? Those bits on whom the next state depends are called **taps**. Taps are a key element of any LFSR. Choosing mathematically secured taps is very important to ensure the security of LFSRs. Let us generalize the taps for the above LFSR: $s_{n} = s_{n-2} \ \oplus \ s_{n-3} \ \oplus s_{n-4} \ \oplus s_{n-8} \ \ \ \forall n > 7$.
  * There is a better representation of taps, which helps us model LFSR mathematically in a very convenient manner. Remember how I said xor is linear under specific circumstances? It is linear under addition mod 2. That is, xor is denoted simply as $b_0 \oplus b_1 = (b_0+b_1) \mod 2$, where $b_i \in \\{0, 1\\}$. We can thus represent the above tap equation with $s_{n} = s_{n-2} + s_{n-3} + s_{n-4} + s_{n-8} \mod 2$. Under $\mathbb{Z}/\mathbb{Z}2$ this is known as the **Feedback polynomial** which for the given LFSR is $1+x^4+x^5+x^6+x^8$.


### LFSR as a matrix

Suppose we want to find $s_{99784}$ for the above LFSR. Do we need to run the simulation $99784$ times to get that?

No. There is a very neat approach to this due to the matrix representation of LFSR. Consider this matrix:

$$ \underbrace{ \begin{pmatrix} s_{k} \\\ s_{k+1} \\\ s_{k+2} \\\ \vdots \\\ s_{k+n-1} \end{pmatrix} }_{\text{next \ states}} = \ \underbrace{ \begin{pmatrix} 0 & 1 & 0 & \cdots & 0 \\\ 0 & 0 & 1 & \cdots & \vdots \\\ \vdots & \vdots & \vdots & \ddots & 1 \\\ c_0 & c_1 & c_2 & \cdots & c_{n-1} \\\ \end{pmatrix} }_{\text{companion \ matrix} \ (T)} \cdot \underbrace{ \begin{pmatrix} s_{k - 1} \\\ s_{k} \\\ s_{k+1} \\\ \vdots \\\ s_{k+n-2} \end{pmatrix} }_{\text{previous \ states}} = \ \underbrace{ \begin{pmatrix} 0 & 1 & 0 & \cdots & 0 \\\ 0 & 0 & 1 & \cdots & \vdots \\\ \vdots & \vdots & \vdots & \ddots & 1 \\\ c_0 & c_1 & c_2 & \cdots & c_{n-1} \\\ \end{pmatrix} ^ k }_{\text{raised \ to \ power} \ k} \cdot \underbrace{ \begin{pmatrix} s_{0} \\\ s_{1} \\\ s_{2} \\\ \vdots \\\ s_{n-1} \end{pmatrix} }_{\text{initial \ states}} $$

This is the generalized representation of a $n \ bit$ LFSR where $a_k, a_{k+1}, a_{k+2}, …$ are state bits. The square matrix is known as `companion matrix`. This is equivalent to a `transition matrix` and is fixed for a particular LFSR. The $c_0, c_1, c_2, …, c_{n-1}$ in the companion matrix represents the tap bits.

What would these matrices look like for the given LFSR?

$$ \begin{pmatrix} s_{k} \\\ s_{k+1} \\\ s_{k+2} \\\ \vdots \\\ s_{k+7} \end{pmatrix} = \ \begin{pmatrix} 0 & 1 & 0 & \cdots & 0 \\\ 0 & 0 & 1 & \cdots & \vdots \\\ \vdots & \vdots & \vdots & \ddots & 1 \\\ c_0 & c_1 & c_2 & \cdots & c_{7} \\\ \end{pmatrix} \cdot \begin{pmatrix} s_{k - 1} \\\ s_{k} \\\ s_{k+1} \\\ \vdots \\\ s_{k+6} \end{pmatrix} = \ \begin{pmatrix} 0 & 1 & 0 & \cdots & 0 \\\ 0 & 0 & 1 & \cdots & \vdots \\\ \vdots & \vdots & \vdots & \ddots & 1 \\\ c_0 & c_1 & c_2 & \cdots & c_{n-1} \\\ \end{pmatrix} ^ k \cdot \begin{pmatrix} s_{0} \\\ s_{1} \\\ s_{2} \\\ \vdots \\\ s_{7} \end{pmatrix} $$

$$ \begin{pmatrix} c_0 & c_1 & c_2 & c_3 & c_4 & c_5 & c_6 & c_7 \end{pmatrix} = \ \begin{pmatrix} 0 & 1 & 1 & 1 & 0 & 0 & 0 & 1 \end{pmatrix} $$

The problem of finding $s_{99784}$ becomes trivial now.

$$ \begin{pmatrix} s_{99784} \\\ s_{99785} \\\ s_{99786} \\\ \vdots \\\ s_{99791} \end{pmatrix} = \ T ^ {99784} \cdot \begin{pmatrix} s_{0} \\\ s_{1} \\\ s_{2} \\\ \vdots \\\ s_{7} \end{pmatrix} $$

## Tackling the given problem

Given is a 64-bit LFSR with 3 tap positions. Every time a game is played, **4 states of the LFSR is combined and returned** which is later used after modulo by 3. Simply put, the 4 lower bits of the LFSR are used modulo 3 as the opponent’s move.

$$ \begin{aligned} move \ &= \ (state \ \ \& \ \ 15) \ \ &mod \ \ 3 \\\ &= ((s_3 \ll 3) + (s_2 \ll 2) + (s_1 \ll 1) + s_0 ) \ \ &mod \ \ 3 \\\ &= (s_3\cdot8 + s_2\cdot4 + s_1\cdot2 + s_0) \ \ &mod \ \ 3 \end{aligned} $$

This entire operation steps can be represented using matrix operations as follows:

$$ \begin{aligned} \begin{pmatrix} move_k \\\ move_{k+1} \\\ move_{k+2} \\\ move_{k+3} \\\ 0 \\\ \vdots \\\ 0 \end{pmatrix} & = \begin{pmatrix} s_k+s_{k+1}\cdot2+s_{k+2}\cdot4+s_{k+3}\cdot8 \\\ s_{k+4}+s_{k+5}\cdot2+s_{k+6}\cdot4+s_{k+7}\cdot8 \\\ s_{k+8}+s_{k+9}\cdot2+s_{k+10}\cdot4+s_{k+11}\cdot8 \\\ s_{k+12}+s_{k+13}\cdot2+s_{k+14}\cdot4+s_{k+15}\cdot8 \\\ 0 \\\ \vdots \\\ 0 \end{pmatrix} \\\ & = \underbrace{ \begin{pmatrix} 1 & 2 & 4 & 8 & 0 & 0 & 0 & 0 & \cdots & 0 \\\ 0 & 0 & 0 & 0 & 1 & 2 & 4 & 8 & \cdots & 0 \\\ \vdots & \vdots & \vdots & \vdots & \vdots & \vdots & \vdots & \vdots & \ddots & 0 \\\ 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & \cdots & 0 \\\ \end{pmatrix} }_{\text{first \ 4 \ rows \ contain \ the \ block} \ (1 \ 2 \ 4 \ 8\ ) \ \text{at \ different \ positions}} \cdot T^k \cdot \begin{pmatrix} s_{0} \\\ s_{1} \\\ s_{2} \\\ \vdots \\\ s_{63} \end{pmatrix} \ mod \ \ 3 \end{aligned} $$

All operations previously were on $\mathbb{Z}/\mathbb{Z}2$. It now shifts to $\mathbb{Z}/\mathbb{Z}16$ and then to $\mathbb{Z}/\mathbb{Z}3$. This last conversion is what complicates everything.

### Initial approach (didn’t work)

My first thought was to convert this to a graph problem. We can do a `dfs` where nodes represent the moves and edges represent the transition operations from one move to another. We can prune the branches based on modulo values we received from the initial 56 games.

The problem with this approach was that it gave too many valid $seeds$. I could not figure out a way to eliminate them and keep a single seed.

### Correct approach

Every move in the game can be represented as a constraint. We can represent the moves of the first 56 games as constraints and use a constraint solver which would give valid configurations to satisfy our constraints. A very popular constraint solver is `z3`. We can represent the `state` as a `bit-vector` of 64 bits and add all the constraints.

$$ \begin{aligned} \begin{rcases} s_1 &\equiv 1 \mod 3 \\\ s_2 &\equiv 2 \mod 3 \\\ s_3 &\equiv 0 \mod 3 \\\ \vdots \\\ s_{56} &\equiv 1 \mod 3 \end{rcases} \text{these \ are \ constraints} \end{aligned} $$

In my solution, I represented each bit as a variable. But navigating `z3` is … a bit _sophisticated_. I had to go through a lot of trial and error to make it work.

```
    bits = [ BitVec('f_%s' % i, 4) for i in range(n - 1, -1, -1) ]
    
    S = Solver()
    for i in range(n):
      S.add(ULT(bits[i], 2))
      S.add(UGE(bits[i], 0))
    
    for i in range(n - 8):
      assert len(bits) == n
      relevant = bits[-4:]
      assert(len(relevant) == 4)
      num = (relevant[0] << 3) + (relevant[1]  << 2) + (relevant[2]  << 1) + relevant[3]
      diff = num - vals[i]
      rem = URem(diff, 3)
      S.add(rem == 0)
      for j in range(4):
        first = bits[-1] + bits[-2] + bits[-4] + bits[-5]
        bits = [first & 1] + bits[:-1]
        
    print(S.check())
```

__Note __

For some reason that I haven’t figured out yet,`BitVec('f_%s' % i, 1)` did not work. But somehow `BitVec('f_%s' % i, 4)` worked properly.

Once we have the $seed$, we can win the next 50 games easily and claim the flag.

```
    rng = LFSR(seed)
    
    for _ in range(56):
      _ = next(rng)
      
    moves = ["rock", "paper", "scissors"]
    
    for _ in range(50):
      move = next(rng) % 3
      win = moves[(move + 1) % 3]
      recvuntil(sock, b': ')
      sendline(sock, win.encode())
    
    print(recvline(sock))
```

> **dice{wow_u_must_be_extremely_lucky_91ff5a34}**

Updated on 2024-02-19

[Read Markdown](https://tsumiiiiiiii.github.io/dice24_rps_casino/index.md)

[ __](javascript:void\(0\); "Share on Twitter")[__](javascript:void\(0\); "Share on Facebook")[__](javascript:void\(0\); "Share on Reddit")

__[Crypto](https://tsumiiiiiiii.github.io/tags/crypto/), [DiceCTF](https://tsumiiiiiiii.github.io/tags/dicectf/), [LFSR](https://tsumiiiiiiii.github.io/tags/lfsr/), [LCG](https://tsumiiiiiiii.github.io/tags/lcg/), [English](https://tsumiiiiiiii.github.io/tags/english/)[Back](javascript:void\(0\);) | [Home](https://tsumiiiiiiii.github.io/)

[ __DiceCTF 2024 - Winter](https://tsumiiiiiiii.github.io/dice24_winter/ "DiceCTF 2024 - Winter") [LA CTF 2024 crypto writeups __](https://tsumiiiiiiii.github.io/lacrypto/ "LA CTF 2024 crypto writeups")
