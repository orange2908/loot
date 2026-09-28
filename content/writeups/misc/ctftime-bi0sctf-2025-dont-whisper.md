---
title: "dont_whisper - bi0sCTF 2025"
category: "misc"
type: "writeup"
tags: ["audio", "adversarial", "misc", "ml", "dont", "whisper", "bi0sctf", "bi0sctf-2025", "2025", "ctf-writeup"]
summary: "Writeup for dont_whisper from bi0sCTF 2025."
source:
  name: "CTFtime writeup #40309"
  url: "https://ctftime.org/writeup/40309"
original_source: "https://pwn-la-chapelle.eu/posts/bi0s2025_dontwhisper/"
ctf:
  name: "bi0sCTF 2025"
  year: 2025
  challenge: "dont_whisper"
---

## Metadata

- **CTF:** bi0sCTF 2025
- **Task:** dont_whisper
- **Author team:** Pwn-la-Chapelle
- **CTFtime tags:** audio, adversarial, misc, ml
- **CTFtime:** <https://ctftime.org/writeup/40309>
- **Original writeup:** <https://pwn-la-chapelle.eu/posts/bi0s2025_dontwhisper/>

---
> The challenge provides a FastAPI-based service, allowing users to interact with a chatbot via text and audio. Audio uploads are passed through a patched version (it was patched to simplify the exploit, more details in the full writeup) of OpenAI's Whisper ASR (tiny.en v20231117), before getting passed to the Chatbot. Our goal was to find and exploit vulnerabilities within the provided system to read the flag placed at `/chal/flag`.

### tl;dr:  
#### Adversarial audio attack against Whisper tiny.en to inject shell commands.
