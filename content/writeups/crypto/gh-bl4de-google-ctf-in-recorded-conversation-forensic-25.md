---
title: "In Recorded Conversation Forensic 25 - Google CTF 2016"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "pcap", "recorded", "conversation", "forensic"]
summary: "We get pcap (irc.pcap) file with some IRC conversation."
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/In_Recorded_Conversation_Forensic_25/README.md"
ctf:
  name: "Google CTF"
  year: 2016
  challenge: "In Recorded Conversation Forensic 25"
---

## Source

- **CTF:** Google CTF 2016
- **Challenge:** In Recorded Conversation Forensic 25
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/In_Recorded_Conversation_Forensic_25/README.md>

---
# In Recorded Conversation (Forensic, 25pts)

## Problem

Can you find the flag?

## Solution

We get _pcap_ (irc.pcap) file with some IRC conversation.

Quick "Follow the stream" reveals this fragment:

```
:andrewg!~poppopret@agriffiths.c.gctf-2015-admins.google.com.internal PRIVMSG #ctf :CTF{
PING irc.capturetheflag.withgoogle.com
:irc.capturetheflag.withgoogle.com PONG irc.capturetheflag.withgoogle.com :irc.capturetheflag.withgoogle.com
:itsl0wk3y!~poppopret@itsl0wk3y.c.gctf-2015-admins.google.com.internal PRIVMSG #ctf :some_
PRIVMSG #ctf :leaks_
:andrewg!~poppopret@agriffiths.c.gctf-2015-admins.google.com.internal PRIVMSG #ctf :are_
PRIVMSG #ctf :good_
:itsl0wk3y!~poppopret@itsl0wk3y.c.gctf-2015-admins.google.com.internal PRIVMSG #ctf :leaks_
:andrewg!~poppopret@agriffiths.c.gctf-2015-admins.google.com.internal PRIVMSG #ctf :}
PING irc.capturetheflag.withgoogle.com
```

And we can simply collect fragments of the flag:

```
CTF{some_leaks_are_good_leaks_}
