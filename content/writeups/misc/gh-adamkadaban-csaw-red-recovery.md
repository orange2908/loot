---
title: "Recovery - CSAW Red 2020"
category: "misc"
subcategory: "network"
type: "writeup"
tags: ["misc", "pcap", "recovery", "network", "miscellaneous", "csaw-red"]
summary: "misc writeup for \"Recovery\" from CSAW Red - techniques: pcap, recovery, network, miscellaneous, csaw-red."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Recovery/README.md"
ctf:
  name: "CSAW Red"
  year: 2020
  challenge: "Recovery"
---

## Source

- **CTF:** CSAW Red 2020
- **Challenge:** Recovery
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Recovery/README.md>

---
> Alice forgot her throwaway email address, but she has a packet capture of her traffic. Can you help her recover it? To get the flag, answer a question about this traffic on the server here: nc [web.red.csaw.io](http://web.red.csaw.io/) 5018

# Strings method

1. run strings on the file & grep the email

    ```bash
    strings recovery.data | grep mail.com
    ```

2. Look for the email with Alice's name

    ```bash
    strings recovery.data | grep mail.com | alice
    ```

    - The email is `alice_test@hotmail.com`
3. Type the email into the nc

    ```markdown
    echo alice_test@hotmail.com | nc web.red.csaw.io 5018
    ```

4. The flag is flag{W1r3sh4rk,TCPfl0w,gr3p,57r1n95--7h3y'r3_4ll_f0r3n51c5_700l5}
