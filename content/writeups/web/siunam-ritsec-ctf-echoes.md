---
title: "Echoes - RITSEC-CTF 2023"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "burp", "echoes", "rce", "web-exploitation"]
summary: "web writeup for \"Echoes\" from RITSEC-CTF - techniques: command-injection, burp, echoes, rce, web-exploitation."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Echoes/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Web/Echoes/README.md"
ctf:
  name: "RITSEC-CTF"
  year: 2023
  challenge: "Echoes"
---

## Source

- **CTF:** RITSEC-CTF 2023
- **Challenge:** Echoes
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/RITSEC-CTF-2023/Web/Echoes/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/RITSEC-CTF-2023/Web/Echoes/README.md>

---
# Echoes

- 50 Points / 399 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Do you hear that?

[https://echoes-web.challenges.ctf.ritsec.club/](https://echoes-web.challenges.ctf.ritsec.club/)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134054.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134238.png)

As you can see, we can enter some words:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134255.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134303.png)

Burp Suite HTTP history:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134354.png)

When we clicked the "Test word" button, it'll send a POST request to `/check.php`, with parameter `word`.

Then it'll output with our input three times!

Hmm... I wonder how it works...

Well, you guessed! ***`echo` OS command!***

That being said, we can try to test ***OS command injection***!

**To do so, I'll use the new line characeter (`\n` = `%0a`):** (Or you can use `|`)
```bash
a %0a id
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134906.png)

Boom! We have RCE (Remote Code Execution) via OS command injection!

**Let's get the flag!**
```bash
a %0a ls
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401134951.png)

```bash
a %0a cat flag.txt
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401135037.png)

Nice!

- **Flag: `RS{R3S0UND1NG_SUCS3SS!}`**

## Conclusion

What we've learned:

1. OS Command Injection
