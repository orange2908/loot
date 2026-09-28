---
title: "MHK2 - Google Capture The Flag 2023"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lattice", "sage", "prng", "mhk2", "google-capture-the-flag", "google-capture-the-flag-2023", "2023", "ctf-writeup"]
summary: "2023-06-26 :: #ctf #google-ctf #crypto #knapsack #challenge-writing"
source:
  name: "CTFtime writeup #39217"
  url: "https://ctftime.org/writeup/39217"
original_source: "https://mystiz.hk/posts/2023/2023-06-26-google-ctf-mhk2/"
ctf:
  name: "Google Capture The Flag 2023"
  year: 2023
  challenge: "MHK2"
---

## Metadata

- **CTF:** Google Capture The Flag 2023
- **Task:** MHK2
- **Author team:** Google CTF
- **CTFtime:** <https://ctftime.org/writeup/39217>
- **Original writeup:** <https://mystiz.hk/posts/2023/2023-06-26-google-ctf-mhk2/>

---
# Google CTF 2023: MHK2

2023-06-26 :: [#ctf](https://mystiz.hk/tags/ctf/) [#google-ctf](https://mystiz.hk/tags/google-ctf/) [#crypto](https://mystiz.hk/tags/crypto/) [#knapsack](https://mystiz.hk/tags/knapsack/) [#challenge-writing](https://mystiz.hk/tags/challenge-writing/)

_MHK2_ is one of the challenges I coauthored for Google CTF 2023 and there were 18 teams solving this challenge during the contest time.

## Challenge Summary⌗

> I hid your flag using one of Murakami's knapsacks
> 
> Attachments: [MHK2.sage](https://github.com/google/google-ctf/blob/main/2023/quals/crypto-mhk2/attachments/MHK2.sage), [output.txt](https://github.com/google/google-ctf/blob/main/2023/quals/crypto-mhk2/attachments/output.txt)

This challenge implements the knapsack cryptosystem from Y. Murakami, S. Hamasho and M. Kasahara's paper ["A knapsack public-key cryptosystem using two random sequences"](https://ieeexplore.ieee.org/document/6979893). Below summarizes how a keypair is generated and how a bit is being encrypted:

### Generating a keypair⌗

  * For $i = 1, 2$: 
    * Generate a random sequence $\textbf{s}_i = (s_{i, 1}, s_{i, 2}, ..., s_{i, 256})$ where $0 \leq s_{ij} < 2^{128}$.
    * Compute $p_i = \sum_j s_{ij} + 2$. If $p_i$ is not a prime, generate $\textbf{s}_i$ again.
    * Generate a random number $e_i$ with $(p-1)/2 \leq e_i \leq p-1$.
  * Define $\textbf{s} := (s_1, s_2, ..., s_{256})$ with $s_j = s_{1j} + s_{2j}$.
  * For $i = 1, 2$: 
    * Define $\textbf{a}_i = (a_{i, 1}, a_{i, 2}, ..., a_{i, 256})$ where $a_{ij} = e_i \cdot s_{ij} \ \text{mod}\ p_i$.
    * Define $\textbf{b}_i = (b_{i, 1}, b_{i, 2}, ..., b_{i, 256})$ where $b_{ij} = s_{ij} \ \text{mod} \ 2$.
    * Define $\textbf{b} = (b_1, b_2, ..., b_{256})$ where $b_j = s_j \ \text{mod}\ 2$.
    * Define $t \in \\{1, 2\\}$ and $\textbf{c} = \textbf{b}_t$.


The secret and public keys are respectively given by $(\textbf{s}_1, \textbf{s}_2, \textbf{s}, p_1, p_2, e_1, e_2)$ and $(\textbf{a}_1, \textbf{a}_2, \textbf{b}, \textbf{c})$.

### Encrypting a bit $m$⌗

To encrypt a bit $m \in \\{0, 1\\}$, generate a random sequence $\textbf{r}_i = (r_{i, 1}, r_{i, 2}, ..., r_{i, 256})$ where $r_{ij} \in \\{0, 1\\}$ such that $$\left\\{\begin{aligned} & m \equiv \sum_j b_j r_{1j} \equiv \sum_j b_j r_{2j} \ (\text{mod}\ 2) \\\ & \sum_j c_j r_{1j} = \sum_j c_j r_{2j} \end{aligned}\right.$$

Compute the ciphertext $(C_1, C_2)$ as $C_i = \sum_j a_{ij} \cdot r_{ij}$ for $i = 1, 2$.

**How is it differ from the MHK2 implementation?** In MHK2 cryptosystem, the prime numbers $p_1$ and $p_2$ are randomly generated such that $p_i / 2 < \sum_j s_{ij} < p_i$. This is not our case -- we fix it to $p_i := \sum_j s_{ij} + 2$. 

We are given the public key $(\textbf{a}_1, \textbf{a}_2, \textbf{b}, \textbf{c})$ and the encrypted flag, and the objective is to recover the flag.

## Solution⌗

### An intended solution⌗

From the specification, we have $a_{ij} \equiv e_i \cdot s_{ij} \ (\text{mod}\ p_i)$. If we sum up all $j$'s, we have

$$\sum_j a_{ij} \equiv \sum_j (e_i \cdot s_{ij}) \equiv e_i \sum_j s_{ij} \equiv e_i (p_i - 2) \equiv - 2 e_i \ (\text{mod}\ p_i).$$

Since we have $a_{ij}$, we can retrieve $e_i$ if we have $p_i$. Denote $A_i := \sum_j a_{ij}$, we have

$$2e_i + A_i \equiv 0 \ (\text{mod}\ p_i).$$

Substituting back, we have $2a_{ij} \equiv 2e_i \cdot s_{ij} \equiv -A_i \cdot s_{ij} \ (\text{mod}\ p_i)$. Thus there exists integers $x_{ij}$ such that

$$2a_{ij} + A_i \cdot s_{ij} = p_i \cdot x_{ij},$$

with $x_{ij} = (2a_{ij} + A_i \cdot s_{ij}) / p_i \leq (2 \cdot \text{max}_j(a_{ij}) + A_i \cdot 2^{128}) / \text{max}_j(a_{ij})$. We then have

We then have

$$\begin{aligned} 0 &= (2a_{ij} + A_i \cdot s_{ij}) \cdot x_{i0} - (2a_{i0} + A_i \cdot s_{i0}) \cdot x_{ij} \\\ &= 2a_{ij} \cdot x_{i0} - 2a_{i0} \cdot x_{ij} + A_i \cdot (s_{ij} \cdot x_{i0} - s_{i0} \cdot x_{ij}) \end{aligned}$$

Interestingly, $x_{ij}$ are around 136-bit long, and $s_{ij} \cdot x_{i0} - s_{i0} \cdot x_{ij}$ are around 128-bit long. We can construct a lattice of dimension $511 \times 511$ below:

$$\left[\begin{matrix} 1 & & & & -2a_{i1} & \dots & -2a_{in} \\\ & & & & 2a_{i0} \\\ & & & & & \ddots \\\ & & & & & & 2a_{i0} \\\ & 1 & & & A_i \\\ & & \ddots & & & \ddots \\\ & & & 1 & & & A_i \end{matrix}\right]$$

It is expected to span $\left[\begin{matrix} x_{i0} & s_{i1} \cdot x_{i0} - s_{i0} \cdot x_{i1} & \cdots & s_{in} \cdot x_{i0} - s_{i0} \cdot x_{in} & 0 & \cdots & 0 \end{matrix}\right]$ if we assign appropriate weights.

Notably, there is a short vector being $\left[\begin{matrix}a_{i0} & 0 & \cdots & 0 & 0 & \cdots & 0\end{matrix}\right]$, and it might affect the first entry of the expected matrix:

$$\left[\begin{matrix} x_{i0}\ \text{mod}\ a_{i0} & s_{i1} \cdot x_{i0} - s_{i0} \cdot x_{i1} & \cdots & s_{in} \cdot x_{i0} - s_{i0} \cdot x_{in} & 0 & \cdots & 0 \end{matrix}\right].$$

From $x_{i0} \ \text{mod} \ a_{i0}$, we can retrieve few candidates of $x_{i0}$. Following that, we can obtain $p_i$ and $e_i$. Repeat for $i = 1, 2$ and we can recover the secret key. We can easily decrypt the flag with the secret key.

### An oversight⌗

🚧 **Work in progress.** This part contains the players' unintended solutions and it is under construction. 

* * *

* * *

[← Bauhinia CTF 2023: How to Stop Time](https://mystiz.hk/posts/2023/2023-08-21-b6actf/) [ACSC 2023 Quals (I): Gotion and easySSTI →](https://mystiz.hk/posts/2023/2023-03-29-acsc-1/)
