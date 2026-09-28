---
title: "official - [Very Easy] Flag Command 2024"
category: "web"
subcategory: "deserialization"
type: "writeup"
tags: ["web", "deserialization", "official", "web-exploitation", "very-easy-flag-command", "hackthebox"]
summary: "web writeup for \"official\" from [Very Easy] Flag Command - techniques: deserialization, official, web-exploitation, very-easy-flag-command, hackthebox."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/%5BVery%20Easy%5D%20Flag%20Command/official_writeup.md"
ctf:
  name: "[Very Easy] Flag Command"
  year: 2024
  challenge: "official"
---

## Source

- **CTF:** [Very Easy] Flag Command 2024
- **Challenge:** official
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/%5BVery%20Easy%5D%20Flag%20Command/official_writeup.md>

---
![](https://raw.githubusercontent.com/hackthebox/writeup-templates/master/challenge/assets/images/banner.png)



<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 60%;" align=left />    	<font size="10">Flag Command</font>

​	    Prepared By: Xclow3n

​	    Challenge Author(s): Xclow3n

​	    Difficulty: <font color=green>Very Easy</font>

​	    Classification: Official


### Description:

Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

### Objective

Find a secret command in json response and use it to get the flag

## Application Overview

Visiting the home page we are provided with the following page:

![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/[Very%20Easy]%20Flag%20Command/assets/home.png)

We can play the game but none of the option leads us to the flag

## Solution

If we simply look at the developer's tool network tab and reload the page, we can see it makes a web request to the `options` endpoint 

![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/[Very%20Easy]%20Flag%20Command/assets/dev.png)

Looking at the response of this endpoint. There is a secret command whose value is "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack".

![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/[Very%20Easy]%20Flag%20Command/assets/res.png)

If we start the game and enter the secret value we get the flag.

![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/web/[Very%20Easy]%20Flag%20Command/assets/flag.png)
