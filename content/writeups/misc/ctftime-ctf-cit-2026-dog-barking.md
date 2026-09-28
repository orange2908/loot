---
title: "Dog barking - CTF@CIT 2026"
category: "misc"
type: "writeup"
tags: ["misc", "dog", "barking", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "I recorded this audio at the dogpark the other day and I think the dogs were trying to tell me something???"
source:
  name: "CTFtime writeup #40742"
  url: "https://ctftime.org/writeup/40742"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Dog barking"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Dog barking
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40742>

---
# Dog barking — Writeup

\- Category: Misc  
\- Value: 902 pts  
\- Author: by **ronnie**

## Challenge

I recorded this audio at the dogpark the other day and I think the dogs were trying to tell me something???

**FLAG FORMAT:** `CIT{example_flag}`

## Recon

We are given a `.wav` file of dogs barking. Looking closely at the audio (e.g. by extracting the envelope and peak frequencies of each bark), we notice there are exactly three distinct types of barks:

1\. A short, low-pitched bark (~491 Hz, ~120ms long)  
2\. A long, high-pitched bark (~589 Hz, ~180ms long)  
3\. A short, medium-pitched bark (~525 Hz, ~130ms long)

## Solve

If we map the short, low-pitched bark to `0` and the long, high-pitched bark to `1`, and treat the medium-pitched bark as a space character, we get a sequence of 8-bit binary chunks.

Here is a Python script that decodes the audio:

```python  
from [scipy.io](http://scipy.io) import wavfile  
import numpy as np

sample_rate, samples = wavfile.read("../files/challenge.wav")  
if len(samples.shape) > 1:  
samples = samples[:, 0]

chunk_size = sample_rate // 100 # 10ms chunks  
envelope = [np.max(np.abs(samples[i:i+chunk_size])) for i in range(0, len(samples), chunk_size)]  
threshold = np.max(envelope) * 0.15  
is_barking = [1 if e > threshold else 0 for e in envelope]

events = []  
current_state = is_barking[0]  
current_len = 0  
for state in is_barking:  
if state == current_state:  
current_len += 1  
else:  
events.append((current_state, current_len))  
current_state = state  
current_len = 1  
events.append((current_state, current_len))

words = []  
current_pos = 0  
for state, length in events:  
if state == 1:  
bark_samples = samples[current_pos * chunk_size : (current_pos + length) * chunk_size]  
w = np.fft.fft(bark_samples)  
freqs = np.fft.fftfreq(len(w))  
peak_freq = abs(freqs[np.argmax(np.abs(w))]) * sample_rate

if peak_freq < 500:  
words.append("0")  
elif peak_freq > 550:  
words.append("1")  
else:  
words.append(" ")  
current_pos += length

binary = "".join(words)  
flag = "".join(chr(int(b, 2)) for b in binary.split(" "))  
print(flag)  
```

Running this script outputs the flag perfectly.

## Flag

```text  
CIT{b4rking_up_th3_wr0ng_tr33}  
```
