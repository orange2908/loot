---
title: "Cat - CSAW Red 2020"
category: "misc"
subcategory: "network"
type: "writeup"
tags: ["misc", "pcap", "wireshark", "cat", "network", "miscellaneous"]
summary: "misc writeup for \"Cat\" from CSAW Red - techniques: pcap, wireshark, cat, network, miscellaneous."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Cat/README.md"
ctf:
  name: "CSAW Red"
  year: 2020
  challenge: "Cat"
---

## Source

- **CTF:** CSAW Red 2020
- **Challenge:** Cat
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Cat/README.md>

---
# animal_friendships (50pt)

> The druid in your party is a fan of the animal friendship spell. To get the flag, track them down in this packet capture, then report who they befriended here: nc [web.red.csaw.io](http://web.red.csaw.io/) 5017

1. If we download the file, we see it is a .data file. Also, the description states it is a packet capture, therefore we could look at it on Wireshark.
    - Let’s open it up on Wireshark.
2. We see this .jpg, very interesting, let’s explore:

    ![animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_1.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Cat/animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_1.png)

3. We open it up and we get our friend. A SQUIRREL!

    ![animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_2.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Cat/animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_2.png)

4. Now let’s connect to the server and answer the question:

    ![animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_3.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/CSAW%20Red%202020/misc/Cat/animal_friendships%20(50pt)%20318fc57735b949fda8d36ee590f3096f/Untitled_3.png)

5. The flag is flag{m4k1n9_f0r3n51c5_53c0nd_n47ur3}
