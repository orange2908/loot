---
title: "Audio Stego - Spectrogram, LSB, DTMF, SSTV and Morse"
category: stego
subcategory: audio
type: technique
tags: [audio, wav, spectrogram, sonic-visualiser, audacity, lsb, dtmf, sstv, morse, backmasking, echo-hiding, deepsound, steghide, ffmpeg, goertzel, numpy]
difficulty: medium
summary: "Look at the spectrogram first; then LSB, then tone decoding (DTMF/Morse/SSTV), then echo and channel-difference tricks."
when_to_use:
  - "The challenge file is .wav, .mp3, .flac, .ogg or an extracted audio track"
  - "The audio is noise, beeps, or a screeching tone"
  - "The waveform looks symmetric or one channel looks like the other plus noise"
  - "The file plays for far longer than the audible content"
tools: [audacity, sonic-visualiser, ffmpeg, sox, steghide, stegseek, python3, numpy, scipy, multimon-ng, qsstv, deepsound]
related: [image-triage, video-stego, audio-analyzer, stego-cheatsheet, stego-bruteforce, text-unicode-stego]
---

## TL;DR

Order of operations for any audio file: **spectrogram -> metadata -> LSB -> tone decode ->
channel maths -> tool-specific (steghide/DeepSound)**. A spectrogram costs ten seconds and
solves a large fraction of audio challenges outright because the flag is literally drawn in the
frequency domain.

## Recognise it

| What you hear/see | Likely technique |
| --- | --- |
| White noise, hiss | LSB or spectrogram drawing |
| A sequence of two-tone beeps | DTMF (telephone keypad) |
| Short/long beeps at one pitch | Morse |
| A warbling, buzzing 1-2 kHz sweep repeating every ~2 minutes | SSTV |
| Speech played backwards / gibberish with normal prosody | backmasking, reverse it |
| A clean tone with a faint repeat | echo hiding |
| Two channels that sound identical | subtract them, the difference is the payload |
| Normal music, big file | steghide/DeepSound carrier |

## Attack

### 1. Spectrogram (always first)

```bash
# ffmpeg writes a PNG spectrogram without opening a GUI
ffmpeg -i chal.wav -lavfi showspectrumpic=s=1920x1080:mode=combined:legend=1 spec.png

# per-channel, log frequency scale - better for text drawn low in the spectrum
ffmpeg -i chal.wav -lavfi showspectrumpic=s=2048x1024:mode=separate:scale=log spec_sep.png

# sox equivalent
sox chal.wav -n spectrogram -o spec.png -x 2000 -y 1000

# GUI: Audacity -> select track -> track dropdown -> Spectrogram; or Sonic Visualiser
```

In Audacity, if nothing shows, change **Spectrogram Settings**: window size 2048-8192,
scale Logarithmic, and raise the gain / lower the range.

### 2. Format and metadata

```bash
# sample rate, channels, bit depth, codec, duration
ffprobe -hide_banner -show_streams -show_format chal.wav
soxi chal.wav
mediainfo chal.wav

# ID3 / Vorbis comments / album art
exiftool -a -u -g1 chal.mp3
ffmpeg -i chal.mp3 -an -vcodec copy cover.jpg   # embedded artwork
```

### 3. LSB in samples

Works on uncompressed PCM only (WAV/AIFF/raw). MP3/OGG/FLAC-lossy destroy it; FLAC is lossless
so LSB survives a FLAC round trip if the tool wrote into the decoded samples.

```bash
# convert to a canonical 16-bit PCM wav first
ffmpeg -i chal.mp3 -acodec pcm_s16le -ar 44100 canon.wav
```

Then extract bit 0 of each sample (see the code below, or use the general-purpose
`lsb-extractor` script).

### 4. Tone decoding

```bash
# DTMF, POCSAG, AFSK and more, all at once
multimon-ng -a DTMF -a MORSE_CW -t wav chal.wav

# SSTV: play the file into qsstv with a loopback device, or use a python sstv decoder
# Identify the mode first from the 1900/1200 Hz VIS header (Robot36, Martin M1, Scottie S1...)

# reverse the audio (backmasking)
sox chal.wav reversed.wav reverse
ffmpeg -i chal.wav -af areverse reversed.wav

# slow it down without changing pitch (hidden speech), or change pitch
sox chal.wav slow.wav tempo 0.5
ffmpeg -i chal.wav -af "atempo=0.5" slow.wav

# stereo channel subtraction: the payload is often L - R
ffmpeg -i chal.wav -af "pan=mono|c0=c0-c1" diff.wav
sox chal.wav -c 1 diff.wav remix 1v1,2v-1
```

### 5. Tool carriers

```bash
# steghide supports WAV and AU (not MP3)
steghide info -p '' chal.wav
stegseek chal.wav /usr/share/wordlists/rockyou.txt

# DeepSound carriers are WAV/FLAC; the signature 'DSCF' appears near the start of the data
strings -n 4 chal.wav | grep -i dscf
binwalk chal.wav
```

## Theory

### DTMF

Each key is the sum of one low and one high tone:

|  | 1209 Hz | 1336 Hz | 1477 Hz | 1633 Hz |
| --- | --- | --- | --- | --- |
| **697 Hz** | 1 | 2 | 3 | A |
| **770 Hz** | 4 | 5 | 6 | B |
| **852 Hz** | 7 | 8 | 9 | C |
| **941 Hz** | * | 0 | # | D |

Detecting a single known frequency is exactly what the **Goertzel algorithm** does, in O(N) per
frequency with no FFT:

$$ s[n] = x[n] + 2\cos(\omega)s[n-1] - s[n-2], \quad \omega = \frac{2\pi k}{N} $$
$$ |X_k|^2 = s[N-1]^2 + s[N-2]^2 - 2\cos(\omega)\,s[N-1]s[N-2] $$

### Morse

Morse in audio is on/off keying of one carrier. Compute the envelope (absolute value, low-pass
filtered), threshold it, measure run lengths, and cluster them: the shortest run is a *dit*,
~3x is a *dah*, gaps of 1/3/7 dits separate symbols/letters/words.

### Echo hiding

A bit is encoded as the delay of a faint echo (e.g. 0.8 ms = `0`, 1.2 ms = `1`). Detection uses
the **cepstrum**: `real(ifft(log(|fft(frame)|)))` shows a peak at the echo delay.

### SSTV

Luminance is encoded as frequency (1500 Hz black to 2300 Hz white) scanned line by line, with
1200 Hz sync pulses. A VIS header at the start identifies the mode.

## Code

```python
#!/usr/bin/env python3
"""Audio stego helpers: WAV loading, LSB, Goertzel DTMF, Morse envelope decoding.

Usage:
  python3 audio_stego.py lsb chal.wav
  python3 audio_stego.py dtmf chal.wav
  python3 audio_stego.py morse chal.wav
  python3 audio_stego.py --selftest
"""
from __future__ import annotations

import math
import struct
import sys
import wave

DTMF_LOW = [697, 770, 852, 941]
DTMF_HIGH = [1209, 1336, 1477, 1633]
DTMF_KEYS = [
    ["1", "2", "3", "A"],
    ["4", "5", "6", "B"],
    ["7", "8", "9", "C"],
    ["*", "0", "#", "D"],
]

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-..-.": "/", "-.--.-": ")", "-.--.": "(",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-...-": "=", ".-.-.": "+",
    "-....-": "-", ".----.": "'", "---...": ":", ".--.-.": "@", "..--.-": "_",
}


def read_wav(path: str) -> tuple[list[list[float]], int]:
    """Return (channels as float lists in [-1,1], sample_rate). Handles 8/16/32-bit PCM."""
    with wave.open(path, "rb") as w:
        nch, width, rate, nframes = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(nframes)
    if width == 1:
        vals = [(b - 128) / 128.0 for b in raw]
    elif width == 2:
        ints = struct.unpack("<%dh" % (len(raw) // 2), raw)
        vals = [v / 32768.0 for v in ints]
    elif width == 4:
        ints = struct.unpack("<%di" % (len(raw) // 4), raw)
        vals = [v / 2147483648.0 for v in ints]
    else:
        raise ValueError(f"unsupported sample width {width}")
    channels = [vals[c::nch] for c in range(nch)]
    return channels, rate


def read_wav_ints(path: str) -> tuple[list[int], int, int]:
    """Raw integer samples (interleaved), sample width in bytes, channel count."""
    with wave.open(path, "rb") as w:
        nch, width, nframes = w.getnchannels(), w.getsampwidth(), w.getnframes()
        raw = w.readframes(nframes)
    if width == 2:
        ints = list(struct.unpack("<%dh" % (len(raw) // 2), raw))
    elif width == 1:
        ints = list(raw)
    else:
        ints = list(struct.unpack("<%di" % (len(raw) // 4), raw))
    return ints, width, nch


def lsb_extract(samples: list[int], nbits: int = 1, msb_first: bool = True,
                stride: int = 1, offset: int = 0) -> bytes:
    """Pull `nbits` low bits from every `stride`-th sample and pack them into bytes."""
    bits: list[int] = []
    for s in samples[offset::stride]:
        for b in range(nbits):
            bits.append((s >> b) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        v = 0
        if msb_first:
            for b in chunk:
                v = (v << 1) | b
        else:
            for j, b in enumerate(chunk):
                v |= b << j
        out.append(v)
    return bytes(out)


def goertzel(samples: list[float], rate: int, freq: float) -> float:
    """Magnitude-squared of `freq` in `samples`, normalised by length."""
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + n * freq / rate)
    omega = 2.0 * math.pi * k / n
    coeff = 2.0 * math.cos(omega)
    s1 = s2 = 0.0
    for x in samples:
        s0 = x + coeff * s1 - s2
        s2 = s1
        s1 = s0
    power = s1 * s1 + s2 * s2 - coeff * s1 * s2
    return power / (n * n)


def decode_dtmf(mono: list[float], rate: int, win_ms: int = 25, thresh: float = 1e-5) -> str:
    """Slide a window, take the strongest low and high DTMF tone, collapse repeats."""
    win = max(1, int(rate * win_ms / 1000))
    seq: list[str] = []
    for start in range(0, len(mono) - win, win):
        frame = mono[start:start + win]
        lo = [goertzel(frame, rate, f) for f in DTMF_LOW]
        hi = [goertzel(frame, rate, f) for f in DTMF_HIGH]
        li, hidx = lo.index(max(lo)), hi.index(max(hi))
        if max(lo) > thresh and max(hi) > thresh:
            seq.append(DTMF_KEYS[li][hidx])
        else:
            seq.append(" ")
    out = []
    prev = None
    for ch in seq:
        if ch != prev:
            if ch != " ":
                out.append(ch)
            prev = ch
    return "".join(out)


def envelope(mono: list[float], rate: int, win_ms: int = 5) -> list[float]:
    win = max(1, int(rate * win_ms / 1000))
    env = []
    acc = 0.0
    for i, v in enumerate(mono):
        acc += abs(v)
        if (i + 1) % win == 0:
            env.append(acc / win)
            acc = 0.0
    return env


def decode_morse(mono: list[float], rate: int, win_ms: int = 5) -> str:
    """Threshold the envelope, cluster run lengths, translate."""
    env = envelope(mono, rate, win_ms)
    if not env:
        return ""
    peak = max(env)
    if peak <= 0:
        return ""
    on = [e > peak * 0.3 for e in env]
    runs: list[tuple[bool, int]] = []
    cur = on[0]
    count = 0
    for v in on:
        if v == cur:
            count += 1
        else:
            runs.append((cur, count))
            cur, count = v, 1
    runs.append((cur, count))
    on_runs = [n for state, n in runs if state]
    if not on_runs:
        return ""
    unit = min(on_runs)
    text = []
    symbol = []
    for state, n in runs:
        units = n / unit
        if state:
            symbol.append("." if units < 2 else "-")
        else:
            if units >= 6:
                text.append(MORSE.get("".join(symbol), "?") if symbol else "")
                symbol = []
                text.append(" ")
            elif units >= 2:
                if symbol:
                    text.append(MORSE.get("".join(symbol), "?"))
                    symbol = []
    if symbol:
        text.append(MORSE.get("".join(symbol), "?"))
    return "".join(text).strip()


def tone(freq: float, dur: float, rate: int, amp: float = 0.4) -> list[float]:
    n = int(dur * rate)
    return [amp * math.sin(2 * math.pi * freq * i / rate) for i in range(n)]


def silence(dur: float, rate: int) -> list[float]:
    return [0.0] * int(dur * rate)


def write_wav(path: str, mono: list[float], rate: int) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", max(-32768, min(32767, int(v * 32767)))) for v in mono))


def _selftest() -> None:
    rate = 8000

    # --- DTMF round trip -------------------------------------------------
    digits = "5309"
    sig: list[float] = []
    for d in digits:
        for ri, row in enumerate(DTMF_KEYS):
            if d in row:
                ci = row.index(d)
                lo = tone(DTMF_LOW[ri], 0.12, rate)
                hi = tone(DTMF_HIGH[ci], 0.12, rate)
                sig.extend(a + b for a, b in zip(lo, hi))
        sig.extend(silence(0.08, rate))
    got = decode_dtmf(sig, rate)
    assert got == digits, f"dtmf: got {got!r} want {digits!r}"

    # --- Morse round trip ------------------------------------------------
    unit = 0.06
    morse_src = {v: k for k, v in MORSE.items()}
    msg = "SOS"
    msig: list[float] = []
    for i, ch in enumerate(msg):
        pattern = morse_src[ch]
        for j, sym in enumerate(pattern):
            msig.extend(tone(800, unit * (1 if sym == "." else 3), rate))
            if j != len(pattern) - 1:
                msig.extend(silence(unit, rate))
        if i != len(msg) - 1:
            msig.extend(silence(unit * 3, rate))
    decoded = decode_morse(msig, rate, win_ms=5).replace(" ", "")
    assert decoded == msg, f"morse: got {decoded!r} want {msg!r}"

    # --- LSB round trip --------------------------------------------------
    payload = b"flag{wav_lsb}"
    bits = [(byte >> (7 - i)) & 1 for byte in payload for i in range(8)]
    samples = [((i * 37) % 2000) - 1000 for i in range(4096)]
    for i, b in enumerate(bits):
        samples[i] = (samples[i] & ~1) | b
    out = lsb_extract(samples, nbits=1, msb_first=True)
    assert out.startswith(payload), out[:32]

    # --- Goertzel sanity --------------------------------------------------
    pure = tone(1000, 0.2, rate)
    assert goertzel(pure, rate, 1000) > 100 * goertzel(pure, rate, 1500)

    print(f"selftest ok: dtmf={got} morse={decoded} lsb={out[:13]!r}")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd, path = sys.argv[1], sys.argv[2]
    if cmd == "lsb":
        samples, width, nch = read_wav_ints(path)
        for msb in (True, False):
            for nbits in (1, 2):
                data = lsb_extract(samples, nbits=nbits, msb_first=msb)
                printable = sum(1 for c in data[:512] if 32 <= c < 127)
                print(f"nbits={nbits} msb={msb} printable={printable}/512 head={data[:64]!r}")
    elif cmd == "dtmf":
        chans, rate = read_wav(path)
        print(decode_dtmf(chans[0], rate))
    elif cmd == "morse":
        chans, rate = read_wav(path)
        print(decode_morse(chans[0], rate))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Spectrogram settings matter.** Default Audacity window (1024, linear) hides text drawn above
  10 kHz or below 200 Hz. Try 4096/log and widen the gain range before concluding "nothing".
- **MP3 has no usable sample LSB.** Convert to WAV only to *view*, never expect LSB to survive
  an MP3 encode.
- **`steghide` on WAV requires uncompressed PCM.** It rejects most "wav" files that are really
  containers for compressed codecs.
- **Stereo tricks**: also try `L+R`, `L-R`, and each channel alone. `ffmpeg -af "pan=..."`.
- **Sample-rate lies**: a file tagged 8 kHz but containing 44.1 kHz data plays back
  slow/deep. Force the rate with `sox -r 44100 -e signed -b 16 -c 1 raw.raw out.wav`.
- **DTMF thresholds**: if `decode_dtmf` produces doubled digits, increase the window; if it
  drops digits, decrease it. Real challenge audio often has noise - normalise first.
- **Morse with inconsistent timing** (hand-keyed) breaks the "shortest run = dit" assumption.
  Cluster the run lengths with a 2-means split instead of taking the minimum.
- **SSTV** needs the right mode; feeding the audio to a decoder that assumes Robot36 when it is
  Martin M1 produces a skewed, colour-shifted image - the skew tells you the mode was wrong.
- **DeepSound** files are recognisable by their data section; if `strings` shows `DSCF` you need
  DeepSound itself (Windows) or a reimplementation, plus the password.
- **Check the file length vs the audible content.** Thirty seconds of silence after the music is
  where the payload usually is; zoom in on the waveform amplitude.

## Tools

`audacity`, `sonic-visualiser`, `ffmpeg`/`ffprobe`, `sox`/`soxi`, `multimon-ng`, `qsstv`,
`steghide`, `stegseek`, `binwalk`, `exiftool`, `mediainfo`, Python `wave` + `numpy` + `scipy`.

## References

- ITU-T Q.23 defines the DTMF tone pairs used in the table above.
- ITU-R M.1677-1 defines International Morse Code timing (dit, 3-dit dah, 1/3/7 gaps).
- Goertzel, "An Algorithm for the Evaluation of Finite Trigonometric Series" (1958).
- FFmpeg filter documentation for `showspectrumpic`, `areverse`, `atempo`, `pan`.
