---
title: "Wiretap - CTF@CIT 2026"
category: "stego"
subcategory: "audio"
type: "writeup"
tags: ["stego", "spectrogram", "wiretap", "audio", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "The WAV is a fake phone call:"
source:
  name: "CTFtime writeup #40735"
  url: "https://ctftime.org/writeup/40735"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Wiretap"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Wiretap
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40735>

---
# Writeup: Wiretap

## TL;DR

The WAV is a fake phone call:

\- dial tone  
\- DTMF dialing  
\- ringback  
\- modem handshake  
\- Bell 103 data

Demodulating the two Bell 103 channels recovers an HTTP request and an HTTP response.  
The response is a GeoCities-style page with three embedded SVG scanlines that render a hidden banner.  
That banner spells the classic dial-up line:

`g3t_0ff_th3_ph0n3_1m_0n_th3_1ntern3t`

So the flag is:

`CIT{g3t_0ff_th3_ph0n3_1m_0n_th3_1ntern3t}`

## Recon

Basic checks:

```bash  
sha1sum files/beep_beep_boop.wav  
ffprobe -hide_banner files/beep_beep_boop.wav  
```

The SHA1 matches the prompt:

```text  
fb8ef1616ef3e993e81d7f23f9d56b76d51175be  
```

The capture is about 3 minutes 58 seconds long, mono PCM at 44.1 kHz.  
Looking at a spectrogram makes the structure obvious:

\- dial tone at the start  
\- DTMF bursts  
\- ringback tone  
\- a modem/data section after call setup

I saved that spectrogram as `other/spectrogram.png`.

## Solve

The modem section is Bell 103 style FSK.  
I downsampled the recording, isolated the two channels, and used a frequency discriminator plus 300 baud async framing to recover both byte streams.

Recovered low channel:

```http  
GET /SiliconValley/Heights/4721/diary.html HTTP/1.0  
Host: [www.geocities.com](http://www.geocities.com)  
User-Agent: Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)  
```

Recovered high channel:

```http  
HTTP/1.0 200 OK  
Server: Apache/1.3.6 (Unix)  
Content-Type: text/html  
Content-Length: 6519  
Connection: close  
```

The HTML contains a fake 90s GeoCities page with three SVG strips inside the “manual” block.  
Rendering those SVGs produces the hidden pixel banner in `other/manual.png`.

That banner reads:

```text  
g3t_0ff_th3_ph0n3_1m_0n_th3_1ntern3t  
```

Wrap it in the normal flag format:

```text  
CIT{g3t_0ff_th3_ph0n3_1m_0n_th3_1ntern3t}  
```

## Artifacts

\- `scripts/[solve.py](http://solve.py)` verifies the WAV hash, demodulates both Bell 103 channels, and regenerates the decoded artifacts  
\- `other/request.txt` and `other/response.txt` store the recovered HTTP conversation  
\- `other/manual.png` stores the rendered hidden banner from the page  
\- `other/spectrogram.png` stores the audio spectrogram used during analysis

## Flag

`CIT{g3t_0ff_th3_ph0n3_1m_0n_th3_1ntern3t}`
