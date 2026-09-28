---
title: "CTF Mind Tricks - 1337UP LIVE CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "spectrogram", "mind", "tricks", "network", "1337up-live-ctf", "ctf-writeup"]
summary: "Players download a PCAP. There's a lot of noise from random HTTPS traffic, so they should filter by SMB and see this WAV file transfer."
source:
  name: "CTFtime writeup #39674"
  url: "https://ctftime.org/writeup/39674"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "CTF Mind Tricks"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** CTF Mind Tricks
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39674>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/>

---
Players download a PCAP. There's a lot of noise from random HTTPS traffic, so they should filter by SMB and see this WAV file transfer.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/smb-filter.png>)

Return to the start of the request, then follow the TCP stream.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/follow-tcp-stream.png>)

You can convert the ASCII to raw and save this as a .MP4 file.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/ascii-to-raw.png>)

Alternatively, just go to `File > Export Objects > SMB`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/export-smb-objects.png>)

You'll find an AI song I generated with [suno](<https://suno.com>).

If you closed the PCAP here though, you missed a step! If you look through the ports (I recommend filtering out HTTP(S) with `!(tcp.port == 80 || tcp.port == 443)`), you'll a suspicious one; `1337`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/port-1337-chat.png>)

```  
I need to send you a message but I can't remember what frequency you said?  
It was 18-21kHz.  
Sending the song via SMB now.  
Oh, how interesting.. Thanks!  
```

So, there's something hidden in some frequency of the audio ? We can isolate these things with `sonic-visualizer` or `Audacity`. I went with the latter.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/audacity-waveform.png>)

Viewing the spectrogram doesn't reveal anything.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/default-spectrogram.png>)

We need to configure the range between `18000hz` to `21000hz`.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/images/high-frequency-spectrogram.png>)

Flag: `INTIGRITI{hidden_in_music_1337}`
