---
title: "Talking Duck - V1t CTF 2025"
category: "stego"
subcategory: "audio"
type: "writeup"
tags: ["stego", "spectrogram", "morse", "talking", "duck", "audio", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "Upon listening to the file, it sounds like the duck is making “short” and “long” quacks."
source:
  name: "CTFtime writeup #40477"
  url: "https://ctftime.org/writeup/40477"
original_source: "https://ctf.dvzr.io/competitions/v1t-ctf-2025/talking-duck/"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Talking Duck"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Talking Duck
- **Author team:** CaptureTheFat
- **CTFtime:** <https://ctftime.org/writeup/40477>
- **Original writeup:** <https://ctf.dvzr.io/competitions/v1t-ctf-2025/talking-duck/>

---
## Attachments

  * [ ⇩ duck_sound.wav ](https://ctf.dvzr.io/assets/files/v1t_ctf_2025/talking_duck/duck_sound.wav)


## Recon

Upon listening to the file, it sounds like the duck is making “short” and “long” quacks. This immediately suggested Morse code to me. To analyze this further, I opened the audio file in Audacity and used the spectrogram view to visually interpret the signal.

![Spectrogram analysis](https://ctf.dvzr.io/assets/files/v1t-ctf-2025/talking-duck/spectrogram.png)

## Flag capture

By translating the pulses into Morse code, we obtain the following sequence:

```
    ...- / .---- / - / -.. / ..- / -.-. / -.- / ... / ----- / ... / ... / ----- / ...
```

Decoding that sequence using any Morse tool reveals the message: `V1TDUCKS0SS0S`.

```
    Flag: V1T{DUCK_S0S_S0S}
```

[← Back to V1t CTF 2025](https://ctf.dvzr.io/competitions/v1t-ctf-2025/)
