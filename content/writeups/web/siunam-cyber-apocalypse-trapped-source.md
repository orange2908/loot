---
title: "Trapped-Source - Cyber-Apocalypse 2023"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "trapped-source", "web-exploitation", "cyber-apocalypse", "siunam321", "trapped"]
summary: "Intergalactic Ministry of Spies tested Pandora's movement and intelligence abilities."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/Cyber-Apocalypse-2023/Web/Trapped-Source/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Cyber-Apocalypse-2023/Web/Trapped-Source/README.md"
ctf:
  name: "Cyber-Apocalypse"
  year: 2023
  challenge: "Trapped-Source"
---

## Source

- **CTF:** Cyber-Apocalypse 2023
- **Challenge:** Trapped-Source
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/Cyber-Apocalypse-2023/Web/Trapped-Source/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/Cyber-Apocalypse-2023/Web/Trapped-Source/README.md>

---
# Trapped Source

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Intergalactic Ministry of Spies tested Pandora's movement and intelligence abilities. She found herself locked in a room with no apparent means of escape. Her task was to unlock the door and make her way out. Can you help her in opening the door?

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210317.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210402.png)

In here, we see there's a vault, which is locked.

**Let's view the source page!**
```html
[...]
<script>
    window.CONFIG = window.CONFIG || {
        buildNumber: "v20190816",
        debug: false,
        modelName: "Valencia",
        correctPin: "8291",
    }
</script>
[...]
```

In here, we see the correct pin code is `8291`!!

Let's enter that!

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210544.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210549.png)

We got the flag!

- **Flag: `HTB{V13w_50urc3_c4n_b3_u53ful!!!}`**

## Conclusion

What we've learned:

1. Viewing Source Page
