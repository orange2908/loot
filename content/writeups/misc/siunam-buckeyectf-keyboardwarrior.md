---
title: "keyboardwarrior - BuckeyeCTF 2022"
category: "misc"
subcategory: "network"
type: "writeup"
tags: ["misc", "pcap", "wireshark", "tshark", "keyboardwarrior", "network"]
difficulty: "medium"
summary: "In this challenge, we can download a file:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior/README.md"
ctf:
  name: "BuckeyeCTF"
  year: 2022
  challenge: "keyboardwarrior"
---

## Source

- **CTF:** BuckeyeCTF 2022
- **Challenge:** keyboardwarrior
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior/README.md>

---
# keyboardwarrior

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

> I found a PCAP of some Bluetooth packets being sent on this guy's computer. He's sending some pretty weird stuff, you should take a look.

> Author: v0rtex

> Difficulty: Medium

## Find the flag

**In this challenge, we can download a file:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106080807.png)

```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior]
└─# file keyboardwarrior.pcap 
keyboardwarrior.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Bluetooth HCI H4 with pseudo-header, capture length 262144)
```

**It's a pcap file, let's open it in WireShark!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106080850.png)

**In WireShark, we can see that there are lots of BlueTooth packets, and the Human Interface Device is interesting to me, as the challenge's description is talking about `sending some pretty weird stuff`.**

**Let's filter that!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081056.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081204.png)

**After fumbling around, I found that the Human Interface Device packets are something weird, as it only has 1 hex value is different.**

**Now, we can use `tshark` (Command line version of WireShark) to find all the weird hex value:**
```
┌──(root🌸siunam)-[~/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior]
└─# tshark -r keyboardwarrior.pcap -Y "btatt.value" -T fields -e btatt.value > weird_value.txt
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081322.png)

**Let's clean that up!**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081413.png)

**Then, I also found that in rgbCTF2020, there is a [writeup](https://github.com/spitfirerxf/rgbCTF2020/tree/master/PI1) caught my attention:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081548.png)

> Keyboard are using certain hexes to send keyboard signal to the host, but it's not in ASCII.

In the writeup, it also include a [keycode dictionary](https://gist.github.com/willwade/30895e766273f606f821568dadebcc1c#file-keyboardhook-py-L42):

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081635.png)

Armed with the above information, we can basically find the flag!

**After some find and replace, you'll get this:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/BuckeyeCTF-2022/images/Pasted%20image%2020221106081851.png)

We found the flag!

> Note: The `-` should be an underscore (`_`). Complete flag: `buckeyectf{4v3r4g3_b13_3nj0y3r}`

# Conclusion

What we've learned:

1. Inspecting BlueTooth Packets
