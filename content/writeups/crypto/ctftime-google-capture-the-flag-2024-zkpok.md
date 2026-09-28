---
title: "ZKPOK - Google Capture The Flag 2024"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "gcd", "schnorr", "quadratic-residue", "zkpok", "ecc", "google-capture-the-flag", "google-capture-the-flag-2024", "2024", "ctf-writeup"]
summary: "2024-06-24 :: #ctf #google-ctf #challenge-writing"
source:
  name: "CTFtime writeup #39226"
  url: "https://ctftime.org/writeup/39226"
original_source: "https://mystiz.hk/posts/2024/2024-06-24-google-ctf-2/"
ctf:
  name: "Google Capture The Flag 2024"
  year: 2024
  challenge: "ZKPOK"
---

## Metadata

- **CTF:** Google Capture The Flag 2024
- **Task:** ZKPOK
- **Author team:** Google CTF
- **CTFtime:** <https://ctftime.org/writeup/39226>
- **Original writeup:** <https://mystiz.hk/posts/2024/2024-06-24-google-ctf-2/>

---
# Google CTF 2024 (II): ZKPOK

2024-06-24 :: [#ctf](https://mystiz.hk/tags/ctf/) [#google-ctf](https://mystiz.hk/tags/google-ctf/) [#challenge-writing](https://mystiz.hk/tags/challenge-writing/)

ZKPOK is a challenge I made while learning Zero Knowledge Proofs on [zk-learning.org](https://zk-learning.org/). I was watching the first lecture video, I came across with the interactive proof for quadratic residues at [20:00](https://youtu.be/uchjTIlPzFo?si=nxWgDGVScmMHTn7M&t=1200). This made me ponder - it should be easy to apply Fiat-Shamir transform to make this non-interactive. Let's also use MD5 so that it could be vulnerable. Hours later, this challenge appeared without a proper solve script.

Surprisingly, the challenge ended up having three solves, which makes this the least solved challenge in Google CTF 2024.

## Challenge Summary⌗

> If you know the flag... you know the flag!
> 
> `nc zkpok.2024.ctfcompetition.com 1337`
> 
> Attachments: [zkpok.zip](https://github.com/google/google-ctf/tree/main/2024/quals/crypto-zkpok/attachments)

We are given $n$ and $c$ in `param.py`, where $c$ is the encrypted flag using the Rabin cryptosystem, with modulus being $n$ (i.e., we have $c = m^2 \ \text{mod}\ n$ with flag $m$).

On top of that, the goal is to generate a proof $(s_1, s_2, ..., s_{128}, z_1, z_2, ..., z_{128})$ with

  1. $b_1, b_2, ..., b_{128} = \text{MD5}(s_1, s_2, ..., s_{128})$,
  2. $\text{gcd}(s_i, n) = 1$ for all $i = 1, 2, ..., 128$, and
  3. ${z_i}^2 \equiv s_i \cdot c^{b_i} \ (\text{mod}\ n)$ for all $i = 1, 2, ..., 128$.


## Solution⌗

### What is the proof?⌗

This challenge, in the nutshell, requires the players to provide a valid non-interactive zero-knowledge proof of knowledge of modular square roots.

An interactive proof of modular square roots would look like something below:

Note over Prover: Generates a random r Prover->Verifier: s = r² mod n Verifier->Prover: b (either 0 or 1) Prover->Verifier: z = r·xᵇ mod n Note over Verifier: Checks if z² ≡ s·yᵇ mod n 

In case of $z^2 \equiv s \cdot y^2 \ (\text{mod}\ n)$, the verifier is 50% sure that the prover has the right $x$ such that $y \equiv x^2 \ (\text{mod}\ n)$. The prove will be repeated many times, as a malicious prover would only have a success rate of $1/2^k$ to successfully prove all $k$ rounds.

We will also use Fiat-Shamir transform to convert the interactive proof into a non-interactive one. In short, the verifier delegates the work on generating $b$'s to the prover while making sure that the prover are unable to control $b$ in their favour.

### Yet another MD5 collision challenge⌗

There are many tools, like UniColl and FastColl, that find MD5 collisions with a given prefix. For instance, we can find $s_{1, 0}, s_{2, 0}, ..., s_{128, 0}$ and $s_{1, 1}, s_{1, 2}, ..., s_{1, 128}$ with

$$h = \text{MD5}(s_{1, b_1}, s_{2, b_2}, ..., s_{128, b_{128}})$$

remains unchanged for all $b_1, b_2, ..., b_{128} \in \\{0, 1\\}$ (i.e., $h$ is a constant). In that way, we are able to pick $b_1, b_2, ..., b_{128}$ based on the resulting MD5 digest, $h$.

💭 **ZKPOK vs MD5 hashqines.** The idea behind ZKPOK is also used to generate hashquines, where a picture (or a program) shows the MD5 digest of itself. @spq [tweeted](https://x.com/__spq__/status/838583044260904960) on the first GIF MD5 hashquine, and Rogdham wrote an [article](https://www.rogdham.net/2017/03/12/gif-md5-hashquine.en) explaining its theory. They are very interesting - go read if you haven't! 

### ...and we gonna solve some diophantine equations!⌗

Since we want to answer queries, we would also like to know $z_{i, 0}$ and $z_{i, 1}$ such that

$$z_{i, 0}^2 \equiv s_{i, 0} \ (\text{mod}\ n) \quad \text{and} \quad z_{i, 1}^2 \equiv s_{i, 1} \cdot c \ (\text{mod}\ n) \qquad [\ddagger]$$

Using FastColl, we can find a pair of prefixes for $s_{i, 0}$ and $s_{i, 1}$, namely, $\hat{s_{i, 0}}$ and $\hat{s_{i, 1}}$. Now we want to find a common suffix, $\Delta s_i$. We denote $s_{i, b} := \hat{s_{i, b}} + \Delta s_i$. In this way, what is left to fulfil is the condition $[\ddagger]$. Substituting, we have

$$z_{i, 0}^2 \cdot c - z_{i, 1}^2 \equiv (\hat{s_{i, 0}} - \hat{s_{i, 1}}) \cdot c \ (\text{mod}\ n).$$

Here $z_{i, 0}$ and $z_{i, 1}$ are the only unknowns here. Now we have a congruence in the form of $x^2 + ky^2 \equiv m \ (\text{mod}\ n)$, which is solvable according to Pollard and Schorr's paper1.

😏 **Deja vu?** This paper served also as a reference solution to the _circular_ challenge in TokyoWesterns CTF 2020. What I did is to copy my solve script and it worked for this challenge... 

### Some implementation details⌗

The $s_i$'s I used are of 446 bytes. While hashing, we are also prepending the size of $s_i$ (which is of two bytes). Since MD5 has a block size of 64 bytes, we can split the $s_i$'s into blocks. This enable us to interchangably use $s_{i, 0}$ and $s_{i, 1}$ without altering the digest. The prefix I used is `01 be ff`, which also guaranteeds that the $s_i$ is of 446 bytes. Also, collisions generated by FastColl are of 192 bytes, and we thus have 256 bytes to control (i.e., for $\Delta s_i$'s).

A bottleneck of my script is where we solve for $x^2 + ky^2 \equiv m \ (\text{mod}\ n)$, which took around 20 seconds each time. Fortunately, there are not much possible $(k, m)$s because the preimages FastColl generated has bit differences applied on the same positions, thus we could cache the values of $(k, m)$ and return $(x, y)$ immediately. We find that around 60% of the $(k, m)$'s are repeated, thus the $(x, y)$ computed can be reused.

Finally, my Python script that constructs a proof completes in around 20 minutes. This includes finding collisions with FastColl and solving the diophanine equation. With a valid proof created, we can show it to the verifier and retrieve the flag: `CTF{wh0_w1l1_b3_us1n9_md5_f0r_h4sh1n9_1n_2024}`.

📜 **Final words...** By the way, I didn't continue learning ZKPs since I started working on this challenge. I will be taught the quadratic residue protocol next time I watch the lecture video. 

* * *

  1. J. Pollard, C. Schnorr (1987). "An efficient solution of the congruence $x^2 + k y^2 = m\ (\text{mod}\ n)$"  
<https://dl.acm.org/doi/10.1109/TIT.1987.1057350> ↩︎


* * *

* * *

[← Google CTF 2024 (III): IDEA](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-3/) [Google CTF 2024 (I): Blinders →](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-1/)
