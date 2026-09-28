---
title: "Blinders - Google Capture The Flag 2024"
category: "crypto"
subcategory: "xss"
type: "writeup"
tags: ["crypto", "xss", "blinders", "google-capture-the-flag", "google-capture-the-flag-2024", "2024", "ctf-writeup"]
summary: "2024-06-24 :: #ctf #google-ctf #challenge-writing"
source:
  name: "CTFtime writeup #39225"
  url: "https://ctftime.org/writeup/39225"
original_source: "https://mystiz.hk/posts/2024/2024-06-24-google-ctf-1/"
ctf:
  name: "Google Capture The Flag 2024"
  year: 2024
  challenge: "Blinders"
---

## Metadata

- **CTF:** Google Capture The Flag 2024
- **Task:** Blinders
- **Author team:** Google CTF
- **CTFtime:** <https://ctftime.org/writeup/39225>
- **Original writeup:** <https://mystiz.hk/posts/2024/2024-06-24-google-ctf-1/>

---
# Google CTF 2024 (I): Blinders

2024-06-24 :: [#ctf](https://mystiz.hk/tags/ctf/) [#google-ctf](https://mystiz.hk/tags/google-ctf/) [#challenge-writing](https://mystiz.hk/tags/challenge-writing/)

This is yet another edition of Google CTF, where I wrote some crypto challenges with my colleagues. I contributed on three challenges this time, namely, _Blinders_ , _ZKPOK_ and _IDEA_. There are respectively 56, 3 and 4 solves (out of 267 teams scoring non-zero flags) during the contest period.

Blinders is one of the challenges I coauthored, which introduces a protocol for private set membership.

## Challenge Summary⌗

> If you are really efficient at guessing which number is missing from {0, 1, ..., 255}, I am more than happy to share you the flag!
> 
> `nc blinders.2024.ctfcompetition.com 1337`
> 
> Attachments: [blinders.zip](https://github.com/google/google-ctf/tree/main/2024/quals/crypto-blinders/attachments)

This challenge introduces a private set membership protocol called _Blinders_ , which the server has the set $S$. The client wants to privately check whether a given $\text{id}$ is a member of the set $S$.

Note over Client: Generates a random key r Note over Client: Computes eid := H(id)·r Client->Server: eid Note over Server: Generates a random key k Note over Server: Computes eid₁ := H(id₁)·k, ...,\n eidₙ := H(idₙ)·k and deid := eid·k Server->Client: eid₁, ..., eidₙ, deid Note over Client: Computes eid' := deid·r⁻¹ Note over Client: Knows that id ∈ S if\neid' := eidᵢ for some i. 

In the challenge, $S = \\{1, 2, ..., 256\\} \setminus \\{x\\}$ for a random value $x \in \\{1, 2, ..., 256\\}$. The goal is to find $x$ given two calls to the private set membership protocol... 16 times.

📝 **Note.** We will use $S = \\{1, 2, ..., 256\\} \setminus \\{x\\}$ instead of $\\{0, 1, ..., 255\\} \setminus \\{x\\}$ defined in the actual challenge for presentation purposes. 

## Solution⌗

### Two bugs of Blinders⌗

We will cover the two bugs of _Blinders_ that could be chained together in our case.

🪲 **The order bug.** $\text{eid}_i$'s not being shuffled. 

Since the $\text{eid}_i$'s are not shuffled, we have

$$\text{eid}_i = \begin{cases} \text{H}(i) \cdot k & \text{if} \ i < x, \\\ \text{H}(i + 1) \cdot k & \text{otherwise}. \end{cases}$$

🐛 **The subset bug.** The client can query, not necessarily effectively, if a chosen set $T$ (of $m$ entries) is a subset of $S$.

The client can send $\text{eid} := \sum_{t \in T} \text{H}(t)$ to the server. Then $T \subseteq S$ iff there exists $i_1, i_2, ..., i_{m}$ such that $\text{eid}_{i_1} + \text{eid}_{i_2} + ... + \text{eid}_{i_m} = \text{deid}$.

Assume that we want to check if $\\{2, 3\\} \subseteq S$. We can send $\text{eid} := \text{H}(2) + \text{H}(3)$ to the server. The server then responds us with $(\text{eid}_1, \text{eid}_2, ..., \text{eid}_n, \text{deid})$. We then can search for $i, j \in \\{1, 2, ..., 256\\}$ such that $\text{eid}_i + \text{eid}_j = \text{deid}$. If such $(i, j)$ exists, we can claim that $\\{2, 3\\} \subseteq S$.

### Recover $x$ with only two calls⌗

We can send $\text{eid} := \text{H}(2) + \text{H}(4) + ... + \text{H}(256)$ and $\text{eid}' := \text{H}(1) + \text{H}(3) + ... + \text{H}(255)$ to the server. Let $(\text{eid}_1, \text{eid}_2, ..., \text{eid}_{255}, \text{deid})$ and $(\text{eid}'_1, \text{eid}'_2, ..., \text{eid}'_{255}, \text{deid}')$ be the corresponding responses from the server.

  1. If $x$ is odd, we have $(\text{eid}_2 + \text{eid}_4 + ... + \text{eid}_{x-1}) + (\text{eid}_x + \text{eid}_{x+2} + ... + \text{eid}_{255}) = \text{deid}$.
  2. If $x$ is even, we have $(\text{eid}'_1 + \text{eid}'_3 + ... + \text{eid}'_{x-1}) + (\text{eid}'_x + \text{eid}'_{x+2} + ... + \text{eid}'_{254}) = \text{deid}'$.


For instance, we can determine if $x = 15$ by checking whether

$$(\text{eid}_2 + \text{eid}_4 + ... +\text{eid}_{14}) + (\text{eid}_{15} + \text{eid}_{17} + ... + \text{eid}_{255}) = \text{deid}.$$

We can likewise learn if $x = 24$ with

$$(\text{eid}'_1 + \text{eid}'_3 + ... + \text{eid}'_{23}) + (\text{eid}'_{24} + \text{eid}'_{26} + ... + \text{eid}'_{254}) = \text{deid}'.$$

Therefore we can recover $x$ with two oracle calls. Repeating the progress 16 times, we have the flag: `CTF{pr1v4t3_s3t_m3mb3rsh1p_qu3r135_m3d4_m0r3_p0w3rfu1}`.

* * *

* * *

[← Google CTF 2024 (II): ZKPOK](https://mystiz.hk/posts/2024/2024-06-24-google-ctf-2/) [Intigriti's XSS Challenge (February 2024) →](https://mystiz.hk/posts/2024/2024-02-23-intigriti-xss/)
