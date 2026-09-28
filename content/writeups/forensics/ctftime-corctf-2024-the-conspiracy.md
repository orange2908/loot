---
title: "the-conspiracy - corCTF 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "scapy", "eval", "the-conspiracy", "network", "corctf", "corctf-2024", "2024", "ctf-writeup"]
summary: "Hi All, Challenge description is like below:"
source:
  name: "CTFtime writeup #39353"
  url: "https://ctftime.org/writeup/39353"
original_source: "https://medium.com/@embossdotar/ctf-writeup-corctf-2024-the-conspiracy-52e9f95624c7"
ctf:
  name: "corCTF 2024"
  year: 2024
  challenge: "the-conspiracy"
---

## Metadata

- **CTF:** corCTF 2024
- **Task:** the-conspiracy
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39353>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-corctf-2024-the-conspiracy-52e9f95624c7>

---
Hi All, Challenge description is like below:

"forensics/the-conspiracy  
jammy

Our intelligence team created a chat app, and secretly distributed it to the lemonthinker gang. We’ve given you the application source and a capture taken by one of our agents — can you uncover their plans? ", source: corCTF 2024 — the-conspiracy challenge

Challenge contains two files — challenge.pcap and [source.py](http://source.py). We have to be familiar with them!

View of the [source.py](http://source.py) file:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*UFHhn1hnr65xTn-i3XW0_Q.png>)

[source.py](http://source.py) file view, source: corCTF 2024 — the-conspiracy challenge

Let’s take a look at the [pcap file](<https://en.wikipedia.org/wiki/Pcap)!>

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*T92v6hpTfcihdUQ-YioGVg.png>)

Wireshark view — pcap file, source: corCTF 2024 — the-conspiracy challenge

We can see there 59 packets:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*dseGiK2opvSdHp13A5V49Q.png>)

Wireshark view — pcap file (max nr of packets), source: corCTF 2024 — the-conspiracy challenge

Sorted by Protocols:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*aLg6Xcgb0VeRFkYOkii4jw.png>)

Wireshark view — pcap file (sorted by protocols), source: corCTF 2024 — the-conspiracy challenge

To reverse engineer this task and retrieve the flag from the pcap file, we’ll need to do the following steps:

o Analyze the PCAP file: Extract the packets and retrieve the encrypted messages and the keys.  
o Decrypt the messages: Use the keys to decrypt the messages and reconstruct the original text.

Here’s how we can approach this problem:

o Extract Data from PCAP File:  
Use a tool like [Scapy](<https://scapy.net/>) to read the packets from the pcap file.  
Identify the packets containing the encrypted messages and keys.

o Decrypt Messages:

Use the extracted keys to divide the encrypted numbers and retrieve the original ASCII values.  
Convert the ASCII values back to characters to reconstruct the original messages.  
Let’s write the script to perform these steps:

```  
from scapy.all import *  
import ast

#Read the packets from the pcap file  
packets = rdpcap(‘challenge.pcap’) # Replace with path to your pcap file

#Separate packets into messages and keys  
messages_packets = []  
keys_packets = []

for packet in packets:  
if packet.haslayer(Raw):  
try:  
payload = packet[Raw].load.decode(‘utf-8’, errors=’ignore’)  
if payload.startswith(‘[‘):  
#Payload is a list, either message or keys  
if len(messages_packets) <= len(keys_packets):  
messages_packets.append(payload)  
else:  
keys_packets.append(payload)  
except UnicodeDecodeError:  
pass

#Decrypt the messages  
for encrypted_message, key in zip(messages_packets, keys_packets):  
encrypted_message = ast.literal_eval(encrypted_message)  
key = ast.literal_eval(key)  
original_message = ‘’.join(chr(int(enc_msg / k)) for enc_msg, k in zip(encrypted_message, key))  
print(original_message)  
```

This script does the following:

Reads packets from the pcap file.  
Separates packets into those containing encrypted messages and those containing keys.  
Decrypts each message using the corresponding keys.  
Prints the original messages.

By running this script, you will be able to retrieve the original messages, one of which is the flag you’re looking for.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*RbgdTJSFgVetTmxEaY8UBQ.png>)

Flag (decrypted messages), source: corCTF 2024 — the-conspiracy challenge

**Flag: corctf{b@53d_af_f0r_th3_w1n}**

I hope you enjoy!
