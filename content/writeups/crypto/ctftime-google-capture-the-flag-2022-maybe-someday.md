---
title: "Maybe Someday - Google Capture The Flag 2022"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "prng", "proof-of-work", "paillier", "maybe", "someday", "google-capture-the-flag", "google-capture-the-flag-2022", "2022", "ctf-writeup"]
summary: "2022-07-20 :: #ctf #google-ctf #challenge-writing #crypto #paillier"
source:
  name: "CTFtime writeup #39219"
  url: "https://ctftime.org/writeup/39219"
original_source: "https://mystiz.hk/posts/2022/2022-07-20-google-ctf-maybe-someday/"
ctf:
  name: "Google Capture The Flag 2022"
  year: 2022
  challenge: "Maybe Someday"
---

## Metadata

- **CTF:** Google Capture The Flag 2022
- **Task:** Maybe Someday
- **Author team:** Google CTF
- **CTFtime:** <https://ctftime.org/writeup/39219>
- **Original writeup:** <https://mystiz.hk/posts/2022/2022-07-20-google-ctf-maybe-someday/>

---
# Google CTF 2022: Maybe Someday

2022-07-20 :: [#ctf](https://mystiz.hk/tags/ctf/) [#google-ctf](https://mystiz.hk/tags/google-ctf/) [#challenge-writing](https://mystiz.hk/tags/challenge-writing/) [#crypto](https://mystiz.hk/tags/crypto/) [#paillier](https://mystiz.hk/tags/paillier/)

This is the third year I had a writeup on Google CTF (see my writeup in [2020](https://mystiz.hk/posts/2020/2020-08-25-google-ctf-oracle/) and [2021](https://mystiz.hk/posts/2021/2021-07-24-google-ctf/)). Yet this time it is _the_ official writeup for a challenge - as the challenge author! There are eventually 35 solvers (out of 382 teams) for the challenge.

## Challenge Summary⌗

> Leave me your ciphertexts. I will talk to you later.
> 
> `nc HOST PORT`
> 
> Attachments: [chall.py](https://github.com/samueltangz/ctf-archive-created/blob/master/20220702-google-ctf/maybe-someday/public/chall.py)

We are given a public key of Paillier cryptosystem $(n, g)$, and is asked to complete 16 rounds of challenge $\mathcal{C}$. In each round of $\mathcal{C}$:

  1. The server generates a random $s$, which of two bytes long.
  2. The server $m_0 := \text{SHA512}(s)$.
  3. The server encrypts a PKCSv1.5-padded $m_0$ with the public key $(n, g)$ and sends its ciphertext $c_0$ to the player.
  4. The player sends $c_1, c_2, ..., c_{20}$ to the server.
  5. The server checks and tells the player if each of the corresponding $m_i$'s is PKCSv1.5-compliant.
  6. The player sends $\hat{m_0}$ to the server. If $\hat{m_0} = m_0$, the player wins this round.


The objective for the player is to win 16 rounds of $\mathcal{C}$ for the flag.

## Solution⌗

📖 **Alternative Writeups.** My writeup is known to be unnecessarily lengthy. Instead, you may be interested to read the writeups compiled by our players: [Writeup](https://furutsuki.hatenablog.com/entry/2022/07/04/104524) by @theoremoon, [writeup](https://blog.y011d4.com/20220704-google-ctf-writeup) by @y011d4, [writeup](https://project-euphoria.dev/problems/google-ctf-2022-maybe-someday/) by @Xornet_Euphoria, [writeup](https://jsur.in/posts/2022-07-05-google-ctf-2022-maybe-someday-writeup) by @josep68_, [writeup](https://willwam.me/posts/2022-07-05-googlectf-maybesomeday) by @willwam845. 

### Background: Homomorphic property of Paillier cryptosystem⌗

A ciphertext $c := \mathcal{E}(m)$ is defined by $c := g^m \cdot r^n\ \text{mod}\ n^2$, for a random number $r \in [0, n)$.

  1. $\mathcal{E}(m_1 + m_2) = \mathcal{E}(m_1) \cdot \mathcal{E}(m_2)$
  2. $\mathcal{E}(m_1 \cdot m_2) = \mathcal{E}(m_1)^{m_2} = \mathcal{E}(m_2)^{m_1}$


Their proofs are pretty straight forward:

  1. $\mathcal{E}(m_1) \cdot \mathcal{E}(m_2) = (g^{m_1} \cdot {r_1}^n) \cdot (g^{m_2} \cdot {r_2}^n) = g^{m_1 + m_2} \cdot (r_1 \cdot r_2)^n = \mathcal{E}(m_1 + m_2)$, and
  2. $\mathcal{E}(m_1)^{m_2} = (g^{m_1} \cdot {r_1}^n)^{m_2} = g^{m_1 \cdot m_2} \cdot ({r_1}^{m_2})^n = \mathcal{E}(m_1 \cdot m_2)$.


### What kind of queries do we have?⌗

In this section, we will discuss some "padding oracles" for Paillier cryptosystem. Suppose that we know the length of the message and denote it by $l$. Denote also the message $m_0$ (composed only of ASCII hexadecimal characters $\mathcal{H} = \\{\texttt{0}, \texttt{1}, ..., \texttt{f}\\}$) by

$$m_0 := \texttt{s}_1\ \texttt{s}_2\ \dots \texttt{s}_l,$$

where $\texttt{s}_1, \texttt{s}_2, ..., \texttt{s}_l \in \mathcal{H}$ represent the $l$ bytes of the message. Finally, denote the padded message $\tilde{m}_0$ by

$$\tilde{m}_0 := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{00}\ \texttt{s}_1\ \texttt{s}_2\ \dots \texttt{s}_l,$$

with $\texttt{p}_1, \texttt{p}_2, ..., \texttt{p}_k \in \\{1, 2, ..., 255\\}$; and $c_0$ be a ciphertext of $\tilde{m}_0$.

**Note.** Not all of the below oracles are useful for this challenge. 

#### Query 1a: Check if $\texttt{s}_1 \leq a$ ($a \in \mathcal{H}$)⌗

**Approach.** Send $\hat{c} := c_0 \cdot \mathcal{E}({256}^l - a \cdot {256}^{l-1})$. The corresponding message $\hat{m}$ has a valid padding _if and only if_ $\texttt{s}_1 < a$. 

The message $\hat{m}$ would be $\hat{m} := \tilde{m}_0 + (256^l - a \cdot {256}^{l-1})$, i.e.,

$$\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \htmlStyle{color: yellow;}{\texttt{01}}\ \htmlStyle{color: yellow;}{(\texttt{s}_1-a)}\ \texttt{s}_2\ \dots \ \texttt{s}_l.$$

The characters in yellow are the modified ones. There are three cases ($\texttt{**}$ below represents a non-null byte; 😀 and 😡 mean that $\hat{m}$ has a valid and an invalid padding respectively):

  1. **[😡]** $\texttt{s}_1 > a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{01}\ \texttt{**} \ \texttt{s}_2\ \dots \ \texttt{s}_l$.
  2. **[😀]** $\texttt{s}_1 = a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{01}\ \texttt{00} \ \texttt{s}_2\ \dots \ \texttt{s}_l$.
  3. **[😀]** $\texttt{s}_1 < a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{00}\ \texttt{**} \ \texttt{s}_2\ \dots \ \texttt{s}_l$.


#### Query 1b: With known $\texttt{s}_{i-1}$, check if $\texttt{s}_i \leq a$⌗

**Approach.** Send $\hat{c} := c_0 \cdot \mathcal{E}({256}^l - (\texttt{s}_i - 1) \cdot {256}^{l-(i-1)} - a \cdot {256}^{l-i})$. The corresponding message $\hat{m}$ has a valid padding _if and only if_ $\texttt{s}_i < a$. 

The message $\hat{m}$ would be $\hat{m} := \tilde{m}_0 + [{256}^l -(\texttt{s}_i - 1) \cdot {256}^{l-(i-1)} - a \cdot {256}^{l-i}]$, i.e.,

$$\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \htmlStyle{color: yellow;}{\texttt{01}} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-2} \ \htmlStyle{color: yellow;}{\texttt{01}} \ \htmlStyle{color: yellow;}{(\texttt{s}_i-a)} \ \texttt{s}_{i+1} \dots \ \texttt{s}_l.$$

There are three cases:

  1. **[😡]** $\texttt{s}_i > a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{01} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-2} \ \texttt{01} \ \texttt{**} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.
  2. **[😀]** $\texttt{s}_i = a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{01} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-2} \ \texttt{01} \ \texttt{00} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.
  3. **[😀]** $\texttt{s}_i < a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots\ \texttt{p}_k\ \texttt{01} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-2} \ \texttt{00} \ \texttt{**} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.


#### Query 2a: Check if $s_i = a$⌗

**Approach.** Send $\hat{c} := c_0 \cdot \mathcal{E}(2 \cdot {256}^l - a \cdot {256}^{l-i})$. The corresponding message $\hat{m}$ has a valid padding _if and only if_ $\texttt{s}_i = a$. 

The message $\hat{m}$ would be $\hat{m} := \tilde{m}_0 + [2 \cdot {256}^l - a \cdot {256}^{l-i}]$, i.e.,

$$\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots \ \texttt{p}_k\ \htmlStyle{color: yellow;}{\texttt{02}} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-1} \ \htmlStyle{color: yellow;}{(\texttt{s}_i-a)} \ \texttt{s}_{i+1} \dots \ \texttt{s}_l.$$

There are three cases:

  1. **[😡]** $\texttt{s}_i > a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots \ \texttt{p}_k\ \texttt{02} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-1} \ \texttt{**} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.
  2. **[😀]** $\texttt{s}_i = a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots \ \texttt{p}_k\ \texttt{02} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i-1} \ \texttt{00} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.
  3. **[😡]** $\texttt{s}_i < a$: $\hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots \ \texttt{p}_k\ \texttt{02} \ \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{**} \ \texttt{**} \ \texttt{s}_{i+1} \ \dots \ \texttt{s}_l$.


#### Query 2b: Check if $s_{i_1} = a_1$ or $s_{i_2} = a_2$ or ... or $s_{i_k} = a_k$ [*]⌗

**[*]** Terms and conditions apply. Here $i_1 < i_2 < ... < i_k$ and $i_r - i_{r-1} > 1$. The second condition (i.e., $i_r - i_{r-1} > 1$) is used to avoid handling carry. 

This is an extension of query 2a. We can send

$$\hat{c} := c_0 \cdot \mathcal{E}\left(2 \cdot {256}^l - \sum_{j=1}^k a_j \cdot {256}^{l-i_j}\right),$$

which corresponds to the message

$$\begin{aligned} \hat{m} := \texttt{00}\ \texttt{02}\ \texttt{p}_1\ \texttt{p}_2\ \dots \ \texttt{p}_k\ \htmlStyle{color: yellow;}{\texttt{02}} \ & \texttt{s}_1 \ \texttt{s}_2 \ \dots \ \texttt{s}_{i_1-1} \ \htmlStyle{color: yellow;}{(\texttt{s}_{i_1}-a_1)} \ \texttt{s}_{i_1+1} \ \dots \\\ & \texttt{s}_{i_2-1} \ \htmlStyle{color: yellow;}{(\texttt{s}_{i_2}-a_2)} \ \texttt{s}_{i_2+1} \ \dots \ \texttt{s}_{i_k-1} \ \htmlStyle{color: yellow;}{(\texttt{s}_{i_k}-a_k)} \ \texttt{s}_{i_k+1} \ \dots \ \texttt{s}_l. \end{aligned}$$

If any of $s_{i_j} = a_j$, then the byte $s_{i_j} - a_j$ would be zero. This yields a zero byte in $\hat{m}$ and thus it has a valid padding. Otherwise $\hat{m}$ is not PKCSv1.5-compliant.

### "Binary search"⌗

Since $m_0$ has 16 bits of entropy, it is expected to recover it with 16 queries using binary search. To achieve this, we would like to generate queries such that the probabilities of returning 😀 and 😡 are close. Using _query 2b_ and if we assume the 128 hex characters are _independent_ and _uniform_ , the change of getting a 😀 would be $(15/16)^k$ (thus the change getting a 😡 would be $1 - (15/16)^k$). When $k = 11$, the probabilities are respectively 49.17% and 50.83%, which is very close.

Although it seems that we have an "binary search" approach which ideally removes at least 49.17% of the candidates in each query, we actually don't. The queries are not independent to each other.

Fortunately it is not that bad. I can easily generate a set of 20 queries with a success rate of 96.90%. This ends up having 60.46% gaining the flag.

### Exploit script⌗

```
    from pwn import *
    from tqdm import tqdm
    import hashlib
    import itertools
    import random
    
    def recvint(r, n=''):
        r.recvuntil(f'{n} = '.encode())
        return int(r.recvline().decode())
     
    def generate_ids(k):
        while True:
            ids = sorted(random.choices(range(128), k=k))
            if any([ids[i+1] - ids[i] == 1 for i in range(k-1)]): continue
            return ids
     
    def precompute(n, g):
        random.seed(73)
     
        k = 11 # number of terms
     
        queries = []
        for i in range(20):
            # The query we are going to ask is
            #   is "x[ids[0]] == vs[0] OR ... OR x[ids[k-1]] = vs[k-1]"?
            query = [0 for _ in range(128)]
            ids = generate_ids(k)
            vs  = [random.randint(0, 15) for _ in range(k)]
            for j, v in zip(ids, vs):
                query[j] = b'0123456789abcdef'[v]
            queries.append(query)
     
        delta_cs = []
        for query in queries:
            m1 = 2 * 256**128 - sum([q * 256**(127-i) for i, q in enumerate(query)])
            c1 = pow(g, m1, n**2)
            delta_cs.append(c1)
     
        response_map = {}
        for x in tqdm(itertools.product(range(256), repeat=2), total=256**2):
            x = bytes(x)
            y = hashlib.sha512(x).hexdigest().encode()
     
            res = []
            for query in queries:
                res.append(any([query[i] == y[i] for i in range(128)]))
     
            response_map[str(res)] = y
        
        print(f'Number of groups detected: {len(response_map)} (the probability of '
              f'computing the answer would be {len(response_map)/65536*100}%).')
     
        return response_map, delta_cs
     
    def forge(c0, delta_cs, n):
        return [c0*c1 % n**2 for c1 in delta_cs]
     
    def solve(response_map, res):
        return response_map[str(res)]
     
    def main():
        r = remote('maybe-someday.2022.ctfcompetition.com', 1337)
        
        r.recvline()
     
        n = recvint(r, 'n')
        g = recvint(r, 'g')
    
        _p = log.progress('Precomputing...')
        response_map, delta_cs = precompute(n, g)
        _p.success()
     
        for _ in tqdm(range(16)):
            c0 = recvint(r, 'c0')
     
            cs = forge(c0, delta_cs, n)
            for c in cs:
                r.sendline(str(c).encode())
            res = [r.recvline().decode().strip() == '😀' for _ in cs]
            answer = solve(response_map, res)
            r.sendline(answer)
     
            assert r.recvline().decode().strip() == '💡'
     
        r.interactive()
        # CTF{p4dd1n9_or4cl3_w1th_h0mom0rph1c_pr0p3r7y_c0m6in3d_in7o_a_w31rd_m47h_puzz1e}
     
     
    if __name__ == '__main__':
        while True:
            try:
                main()
                break
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except:
                pass
```

## Retrospective⌗

### Developing the Challenge⌗

My initial intention is to create an insanely hard crypto challenge which can keep players pulling their hair out during the CTF... Well, as you can tell, I failed. Maybe I will also walk-through how I came up with the challenge.

Remember that there is a commented snippet inside `chall.py`?

```
    # # The secret has 16 bits of entropy.
    # # Hence 16 oracle calls should be sufficient, isn't it?
    # for _ in range(16):
    #     c = int(input())
    #     try:
    #         p.decrypt(c)
    #         print('😀')
    #     except:
    #         print('😡')
```

Well, that is actually the first edition of the challenge. In the beginning, the goal was to recovering the secret (composed of 128 hex characters) and we are given 512 oracle calls. Turns out binary search would work. I would rate it a ⭐ in terms of difficulty.

It got me thinking - what if we change the problem into a non-interactive one? Can we reduce it to 512 oracle calls because there are 512 bits of unknown?

#### Approach 1: Testing character-by-character⌗

It is pretty obvious that we can solve the challenge with $128 \times 16 = 2048$ oracle calls. For $i = 1, 2, ..., 128$, we will ask the below 16 queries:

  * Is $\texttt{s}_i = \texttt{0}$?
  * Is $\texttt{s}_i = \texttt{1}$?
  * ...
  * Is $\texttt{s}_i = \texttt{f}$?


One can slightly optimize to $128 \times 15 = 1920$ oracle calls because $\texttt{s}_i = \texttt{f}$ if

$$\texttt{s}_i \neq \texttt{0} \quad \text{and} \quad \texttt{s}_i \neq \texttt{1} \quad \text{and} \quad \dots \quad \text{and} \quad \texttt{s}_i \neq \texttt{e}.$$

#### Approach 2: "Group in pairs"⌗

We can reduce the number of oracle calls to $64 \times 24 = 1536$ by grouping the unknowns in pairs. For $i = 1, 2, ..., 64$:

  * Is $\texttt{s}_{2i-1} = \texttt{0}$ or $\texttt{s}_{2i} = \texttt{0}$?
  * Is $\texttt{s}_{2i-1} = \texttt{1}$ or $\texttt{s}_{2i} = \texttt{1}$?
  * ...
  * Is $\texttt{s}_{2i-1} = \texttt{f}$ or $\texttt{s}_{2i} = \texttt{f}$?
  * Is $\texttt{s}_{2i-1} = \texttt{0}$ or $\texttt{s}_{2i} = \texttt{1}$?
  * Is $\texttt{s}_{2i-1} = \texttt{2}$ or $\texttt{s}_{2i} = \texttt{3}$?
  * ...
  * Is $\texttt{s}_{2i-1} = \texttt{e}$ or $\texttt{s}_{2i} = \texttt{f}$?


The first 16 queries is to find the characters used (i.e., $\\{\texttt{s}_{2i-1}, \texttt{s}_{2i}\\}$), and the remaining eight is to identify which is which.

I wanted to improve the approach by grouping in 4 (or larger), but I am not smart enough to find a better solution...

#### Approach 3: Random queries those almost cuts the set in half⌗

As discussed above, the query

$$\texttt{s}_{i_1} = a_1 \quad \text{or} \quad \texttt{s}_{i_2} = a_2 \quad \text{or} \quad ... \quad \text{or} \quad \texttt{s}_{i_{11}} = a_{11}$$

returns true (resp. false) at a chance 49.17% (resp. 50.83%). We can theoretically find a set of $\approx 512$ queries to recover the secret. Turns out it is both hard to generate the queries and validate if we can uniquely recover the secret.

**A side note.** Hope I left an interesting enough math puzzle for everyone to research with. I am pretty curious if the original edition of the challenge can be tackled effectively (in around $\approx 512$ queries). 

### Finally, why "Maybe Someday"?⌗

* * *

* * *

[← BalsnCTF 2022 Writeup](https://mystiz.hk/posts/2022/2022-09-05-balsn/) [TSJ CTF 2022 (II): Signature →](https://mystiz.hk/posts/2022/2022-03-02-tsjctf-2/)
