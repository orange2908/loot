---
title: "Script - Audio Analyzer (Spectrogram, Morse, DTMF)"
category: stego
subcategory: audio
type: script
tags: [audio, spectrogram, morse, dtmf, goertzel, envelope, wav, numpy, matplotlib, fft, stft, lsb, decoder, stego, script]
summary: "Renders a spectrogram, decodes Morse from the amplitude envelope and DTMF via the Goertzel algorithm, all from one WAV file."
tools: [python3, numpy, matplotlib, scipy, ffmpeg]
related: [audio-stego, video-stego, stego-cheatsheet, lsb-extractor, image-triage]
---

## What it does

One script, four analyses over a WAV file:

1. **Spectrogram** - STFT magnitude in dB rendered to a PNG (matplotlib if available, otherwise
   a pure-Pillow greyscale render, otherwise an ASCII spectrogram in the terminal).
2. **Morse** - amplitude envelope -> adaptive threshold -> run-length clustering -> text.
3. **DTMF** - Goertzel filter bank on the eight DTMF frequencies, per window.
4. **LSB** - low bits of the PCM samples, with a printable-ratio report.

It degrades gracefully: numpy, scipy and matplotlib are all optional. With none of them
installed you still get Morse, DTMF and LSB (pure stdlib) plus an ASCII spectrogram.

## Usage

```bash
# convert anything to a canonical 16-bit PCM WAV first
ffmpeg -i chal.mp3 -acodec pcm_s16le -ar 44100 chal.wav

pip install numpy matplotlib          # optional but recommended
python3 audio_analyzer.py chal.wav                 # runs everything
python3 audio_analyzer.py chal.wav --spec spec.png
python3 audio_analyzer.py chal.wav --morse
python3 audio_analyzer.py chal.wav --dtmf --win 30
python3 audio_analyzer.py chal.wav --lsb
python3 audio_analyzer.py --selftest
```

## Script

```python
#!/usr/bin/env python3
"""Audio stego analyzer: spectrogram, Morse decoding, DTMF decoding, sample LSB.

Pure stdlib by default; uses numpy/matplotlib when they are installed.
"""
from __future__ import annotations

import argparse
import cmath
import math
import struct
import sys
import wave

try:
    import numpy as np
except ImportError:
    np = None

DTMF_LOW = (697, 770, 852, 941)
DTMF_HIGH = (1209, 1336, 1477, 1633)
DTMF_KEYS = (
    ("1", "2", "3", "A"),
    ("4", "5", "6", "B"),
    ("7", "8", "9", "C"),
    ("*", "0", "#", "D"),
)

MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-....-": "-", "-.--.": "(", "-.--.-": ")", "---...": ":",
    "-...-": "=", ".-.-.": "+", ".--.-.": "@", "..--.-": "_", ".----.": "'",
}
PRINTABLE = set(range(32, 127)) | {9, 10, 13}


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #
def load_wav(path: str) -> tuple[list[list[float]], list[list[int]], int]:
    """Return (float channels in [-1,1], integer channels, sample rate)."""
    with wave.open(path, "rb") as w:
        nch = w.getnchannels()
        width = w.getsampwidth()
        rate = w.getframerate()
        raw = w.readframes(w.getnframes())
    if width == 1:
        ints = [b - 128 for b in raw]
        scale = 128.0
    elif width == 2:
        ints = list(struct.unpack("<%dh" % (len(raw) // 2), raw))
        scale = 32768.0
    elif width == 4:
        ints = list(struct.unpack("<%di" % (len(raw) // 4), raw))
        scale = 2147483648.0
    else:
        raise ValueError(f"unsupported sample width: {width} bytes")
    ich = [ints[c::nch] for c in range(nch)]
    fch = [[v / scale for v in ch] for ch in ich]
    return fch, ich, rate


def write_wav(path: str, mono: list[float], rate: int) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(
            struct.pack("<h", max(-32768, min(32767, int(v * 32767)))) for v in mono))


# --------------------------------------------------------------------------- #
# spectrogram
# --------------------------------------------------------------------------- #
def _dft_mag(frame: list[float]) -> list[float]:
    """Naive DFT magnitude, used only when numpy is unavailable (frames stay small)."""
    n = len(frame)
    out = []
    for k in range(n // 2):
        acc = 0j
        for i, x in enumerate(frame):
            acc += x * cmath.exp(-2j * math.pi * k * i / n)
        out.append(abs(acc))
    return out


def stft(mono: list[float], rate: int, nfft: int = 1024, hop: int = 256) -> list[list[float]]:
    """Magnitude spectrogram: list of frames, each a list of nfft//2 magnitudes."""
    window = [0.5 - 0.5 * math.cos(2 * math.pi * i / (nfft - 1)) for i in range(nfft)]
    frames: list[list[float]] = []
    if np is not None:
        arr = np.asarray(mono, dtype=float)
        win = np.asarray(window)
        for start in range(0, max(0, len(arr) - nfft), hop):
            seg = arr[start:start + nfft] * win
            frames.append(np.abs(np.fft.rfft(seg))[:nfft // 2].tolist())
        return frames
    for start in range(0, max(0, len(mono) - nfft), hop):
        seg = [mono[start + i] * window[i] for i in range(nfft)]
        frames.append(_dft_mag(seg))
    return frames


def save_spectrogram(mono: list[float], rate: int, out: str,
                     nfft: int = 1024, hop: int = 256, fmax: float | None = None) -> str:
    """Render to PNG with matplotlib, else Pillow, else return an ASCII rendering."""
    frames = stft(mono, rate, nfft, hop)
    if not frames:
        return "audio too short for the chosen FFT size"
    db = [[20 * math.log10(v + 1e-12) for v in f] for f in frames]
    lo = min(min(f) for f in db)
    hi = max(max(f) for f in db)
    span = max(1e-9, hi - lo)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        data = [[(v - lo) / span for v in f] for f in db]
        cols = list(map(list, zip(*data)))  # transpose: frequency on the y axis
        plt.figure(figsize=(16, 9))
        plt.imshow(cols, aspect="auto", origin="lower",
                   extent=[0, len(mono) / rate, 0, rate / 2], cmap="magma")
        if fmax:
            plt.ylim(0, fmax)
        plt.xlabel("time (s)")
        plt.ylabel("frequency (Hz)")
        plt.colorbar(label="normalised dB")
        plt.tight_layout()
        plt.savefig(out, dpi=110)
        plt.close()
        return f"wrote {out} (matplotlib)"
    except ImportError:
        pass

    try:
        from PIL import Image

        h = len(db[0])
        w = len(db)
        im = Image.new("L", (w, h))
        px = im.load()
        for x, frame in enumerate(db):
            for y, v in enumerate(frame):
                px[x, h - 1 - y] = int(255 * (v - lo) / span)
        im.save(out)
        return f"wrote {out} (pillow, {w}x{h}, low frequencies at the bottom)"
    except ImportError:
        pass

    return ascii_spectrogram(db, rows=24, cols=100)


def ascii_spectrogram(db: list[list[float]], rows: int = 24, cols: int = 100) -> str:
    ramp = " .:-=+*#%@"
    lo = min(min(f) for f in db)
    hi = max(max(f) for f in db)
    span = max(1e-9, hi - lo)
    nfreq = len(db[0])
    out_lines = []
    for r in range(rows - 1, -1, -1):
        f0 = int(r * nfreq / rows)
        f1 = max(f0 + 1, int((r + 1) * nfreq / rows))
        line = []
        for c in range(cols):
            t0 = int(c * len(db) / cols)
            t1 = max(t0 + 1, int((c + 1) * len(db) / cols))
            block = [db[t][f] for t in range(t0, min(t1, len(db))) for f in range(f0, f1)]
            v = (max(block) - lo) / span if block else 0.0
            line.append(ramp[min(len(ramp) - 1, int(v * len(ramp)))])
        out_lines.append("".join(line))
    return "\n".join(out_lines)


# --------------------------------------------------------------------------- #
# Morse
# --------------------------------------------------------------------------- #
def envelope(mono: list[float], rate: int, win_ms: float = 5.0) -> list[float]:
    win = max(1, int(rate * win_ms / 1000.0))
    out = []
    acc = 0.0
    for i, v in enumerate(mono):
        acc += abs(v)
        if (i + 1) % win == 0:
            out.append(acc / win)
            acc = 0.0
    return out


def runs_from_envelope(env: list[float], rel_threshold: float = 0.3) -> list[tuple[bool, int]]:
    if not env:
        return []
    peak = max(env)
    if peak <= 0:
        return []
    on = [e > peak * rel_threshold for e in env]
    runs: list[tuple[bool, int]] = []
    cur, count = on[0], 0
    for v in on:
        if v == cur:
            count += 1
        else:
            runs.append((cur, count))
            cur, count = v, 1
    runs.append((cur, count))
    return runs


def unit_length(runs: list[tuple[bool, int]]) -> float:
    """Two-means split of the ON run lengths: the dit length is the lower cluster mean."""
    ons = sorted(n for state, n in runs if state)
    if not ons:
        return 1.0
    if len(ons) == 1 or ons[-1] < 2 * ons[0]:
        return float(ons[0])
    lo_c, hi_c = float(ons[0]), float(ons[-1])
    for _ in range(25):
        lo_grp = [n for n in ons if abs(n - lo_c) <= abs(n - hi_c)]
        hi_grp = [n for n in ons if abs(n - lo_c) > abs(n - hi_c)]
        if not lo_grp or not hi_grp:
            break
        lo_c = sum(lo_grp) / len(lo_grp)
        hi_c = sum(hi_grp) / len(hi_grp)
    return lo_c


def decode_morse(mono: list[float], rate: int, win_ms: float = 5.0) -> str:
    runs = runs_from_envelope(envelope(mono, rate, win_ms))
    if not runs:
        return ""
    unit = unit_length(runs)
    if unit <= 0:
        return ""
    text: list[str] = []
    symbol: list[str] = []

    def flush() -> None:
        if symbol:
            text.append(MORSE_TABLE.get("".join(symbol), "?"))
            symbol.clear()

    for i, (state, n) in enumerate(runs):
        units = n / unit
        if state:
            symbol.append("." if units < 2.0 else "-")
        else:
            if i == 0 or i == len(runs) - 1:   # leading/trailing silence
                continue
            if units >= 5.0:
                flush()
                text.append(" ")
            elif units >= 2.0:
                flush()
    flush()
    return "".join(text).strip()


# --------------------------------------------------------------------------- #
# DTMF (Goertzel)
# --------------------------------------------------------------------------- #
def goertzel(frame: list[float], rate: int, freq: float) -> float:
    n = len(frame)
    if n == 0:
        return 0.0
    k = int(0.5 + n * freq / rate)
    omega = 2.0 * math.pi * k / n
    coeff = 2.0 * math.cos(omega)
    s1 = s2 = 0.0
    for x in frame:
        s0 = x + coeff * s1 - s2
        s2, s1 = s1, s0
    return (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (n * n)


def decode_dtmf(mono: list[float], rate: int, win_ms: float = 25.0,
                rel_threshold: float = 0.15) -> str:
    win = max(8, int(rate * win_ms / 1000.0))
    raw: list[str] = []
    powers: list[float] = []
    per_window: list[tuple[str, float]] = []
    for start in range(0, len(mono) - win, win):
        frame = mono[start:start + win]
        lo = [goertzel(frame, rate, f) for f in DTMF_LOW]
        hi = [goertzel(frame, rate, f) for f in DTMF_HIGH]
        li = lo.index(max(lo))
        hidx = hi.index(max(hi))
        strength = min(max(lo), max(hi))
        per_window.append((DTMF_KEYS[li][hidx], strength))
        powers.append(strength)
    if not powers:
        return ""
    cutoff = max(powers) * rel_threshold
    for key, strength in per_window:
        raw.append(key if strength >= cutoff else " ")
    out: list[str] = []
    prev = None
    for ch in raw:
        if ch != prev:
            if ch != " ":
                out.append(ch)
            prev = ch
    return "".join(out)


# --------------------------------------------------------------------------- #
# sample LSB
# --------------------------------------------------------------------------- #
def lsb_bytes(samples: list[int], nbits: int = 1, msb_first: bool = True) -> bytes:
    bits: list[int] = []
    for s in samples:
        for b in range(nbits):
            bits.append((s >> b) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        if msb_first:
            for b in bits[i:i + 8]:
                v = (v << 1) | b
        else:
            for j, b in enumerate(bits[i:i + 8]):
                v |= b << j
        out.append(v)
    return bytes(out)


def lsb_report(ich: list[list[int]], limit: int = 2048) -> list[str]:
    notes = []
    for ci, ch in enumerate(ich):
        for nbits in (1, 2):
            for msb in (True, False):
                data = lsb_bytes(ch[:limit * 8], nbits, msb)[:limit]
                if not data:
                    continue
                ratio = sum(1 for c in data if c in PRINTABLE) / len(data)
                if ratio > 0.8:
                    notes.append(f"channel {ci} nbits={nbits} {'msb' if msb else 'lsb'}: "
                                 f"printable={ratio:.2f} {data[:80]!r}")
    return notes or ["no channel/bit-order combination produced mostly-printable bytes"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="audio stego analyzer")
    ap.add_argument("wav")
    ap.add_argument("--spec", metavar="PNG", default="spectrogram.png")
    ap.add_argument("--nfft", type=int, default=1024)
    ap.add_argument("--hop", type=int, default=256)
    ap.add_argument("--fmax", type=float, default=None)
    ap.add_argument("--win", type=float, default=25.0, help="DTMF window in ms")
    ap.add_argument("--morse-win", type=float, default=5.0, help="Morse envelope window in ms")
    ap.add_argument("--morse", action="store_true")
    ap.add_argument("--dtmf", action="store_true")
    ap.add_argument("--lsb", action="store_true")
    ap.add_argument("--no-spec", action="store_true")
    args = ap.parse_args(argv)

    fch, ich, rate = load_wav(args.wav)
    mono = fch[0] if len(fch) == 1 else [sum(vals) / len(fch) for vals in zip(*fch)]
    print(f"[i] {args.wav}: {len(fch)} channel(s), {rate} Hz, "
          f"{len(mono) / rate:.2f}s, {len(mono)} frames")

    if len(fch) == 2:
        diff = [a - b for a, b in zip(fch[0], fch[1])]
        energy = sum(abs(v) for v in diff) / max(1, len(diff))
        print(f"[i] mean |L-R| = {energy:.6f} "
              f"({'channels differ - analyse L-R separately' if energy > 1e-4 else 'channels are identical'})")

    run_all = not (args.morse or args.dtmf or args.lsb)

    if not args.no_spec and (run_all or True):
        print("[*] spectrogram")
        print("   " + save_spectrogram(mono, rate, args.spec, args.nfft, args.hop, args.fmax))

    if run_all or args.dtmf:
        print("[*] DTMF")
        print("   " + (decode_dtmf(mono, rate, args.win) or "(nothing)"))

    if run_all or args.morse:
        print("[*] Morse")
        print("   " + (decode_morse(mono, rate, args.morse_win) or "(nothing)"))

    if run_all or args.lsb:
        print("[*] sample LSB")
        for line in lsb_report(ich):
            print("   " + line)
    return 0


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #
def _tone(freq: float, dur: float, rate: int, amp: float = 0.4) -> list[float]:
    return [amp * math.sin(2 * math.pi * freq * i / rate) for i in range(int(dur * rate))]


def _silence(dur: float, rate: int) -> list[float]:
    return [0.0] * int(dur * rate)


def _make_dtmf(digits: str, rate: int) -> list[float]:
    sig: list[float] = []
    for d in digits:
        for ri, row in enumerate(DTMF_KEYS):
            if d in row:
                ci = row.index(d)
                lo = _tone(DTMF_LOW[ri], 0.10, rate)
                hi = _tone(DTMF_HIGH[ci], 0.10, rate)
                sig.extend(a + b for a, b in zip(lo, hi))
        sig.extend(_silence(0.06, rate))
    return sig


def _make_morse(msg: str, rate: int, unit: float = 0.05, freq: float = 700.0) -> list[float]:
    rev = {v: k for k, v in MORSE_TABLE.items()}
    sig: list[float] = _silence(unit, rate)
    words = msg.split(" ")
    for wi, word in enumerate(words):
        for ci, ch in enumerate(word):
            pattern = rev[ch]
            for si, sym in enumerate(pattern):
                sig.extend(_tone(freq, unit * (1 if sym == "." else 3), rate))
                if si != len(pattern) - 1:
                    sig.extend(_silence(unit, rate))
            if ci != len(word) - 1:
                sig.extend(_silence(unit * 3, rate))
        if wi != len(words) - 1:
            sig.extend(_silence(unit * 7, rate))
    sig.extend(_silence(unit, rate))
    return sig


def _selftest() -> None:
    import os
    import tempfile

    rate = 8000
    tmp = tempfile.mkdtemp(prefix="audiotest_")

    # --- DTMF -------------------------------------------------------------
    digits = "5309#"
    got = decode_dtmf(_make_dtmf(digits, rate), rate, win_ms=25.0)
    assert got == digits, f"dtmf: got {got!r}, want {digits!r}"

    # --- Morse ------------------------------------------------------------
    msg = "SOS CTF"
    got_morse = decode_morse(_make_morse(msg, rate), rate, win_ms=5.0)
    assert got_morse == msg, f"morse: got {got_morse!r}, want {msg!r}"

    # unit_length must survive a 10% timing jitter (hand-keyed Morse)
    jittered = [(True, 10), (False, 10), (True, 31), (False, 10), (True, 9),
                (False, 29), (True, 11)]
    unit = unit_length(jittered)
    assert 9.0 <= unit <= 11.0, unit

    # --- spectrogram ------------------------------------------------------
    sweep = _tone(440, 0.3, rate) + _tone(1800, 0.3, rate)
    frames = stft(sweep, rate, nfft=256, hop=128)
    assert frames and len(frames[0]) == 128, (len(frames), len(frames[0]) if frames else 0)
    peak_first = max(range(len(frames[1])), key=lambda k: frames[1][k])
    peak_last = max(range(len(frames[-2])), key=lambda k: frames[-2][k])
    assert peak_last > peak_first, (peak_first, peak_last)
    spec_path = os.path.join(tmp, "spec.png")
    msg_out = save_spectrogram(sweep, rate, spec_path, nfft=256, hop=128)
    assert msg_out, msg_out

    # --- Goertzel ---------------------------------------------------------
    pure = _tone(1000, 0.2, rate)
    assert goertzel(pure, rate, 1000) > 100 * goertzel(pure, rate, 1500)

    # --- LSB round trip ---------------------------------------------------
    payload = b"flag{audio_lsb_works}"
    samples = [((i * 53) % 4001) - 2000 for i in range(8 * len(payload))]
    bits = [(b >> (7 - i)) & 1 for b in payload for i in range(8)]
    for i, b in enumerate(bits):
        samples[i] = (samples[i] & ~1) | b
    assert lsb_bytes(samples, 1, True).startswith(payload)
    notes = lsb_report([samples])
    assert any("flag{audio_lsb_works}" in n for n in notes), notes

    # --- WAV round trip ---------------------------------------------------
    wav_path = os.path.join(tmp, "t.wav")
    write_wav(wav_path, _make_dtmf("123", rate), rate)
    fch, ich, r2 = load_wav(wav_path)
    assert r2 == rate and len(fch) == 1 and len(ich[0]) == len(fch[0])
    assert decode_dtmf(fch[0], r2, 25.0) == "123"

    print(f"selftest ok: dtmf={got} morse={got_morse!r} spectrogram={msg_out.split()[0]} "
          f"lsb={payload.decode()}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
    else:
        sys.exit(main())
```

## Interpreting the output

- **Spectrogram**: text drawn in the frequency domain appears as literal glyphs. If the image
  looks like a solid block, re-run with `--fmax 5000` to zoom into the lower band, or change
  `--nfft` (larger = better frequency resolution, worse time resolution).
- **DTMF**: a clean run of digits is the answer. Doubled digits mean the window is too short
  (`--win 40`); missing digits mean it is too long (`--win 15`).
- **Morse**: `?` characters mean a symbol did not map - usually a timing problem. Try
  `--morse-win 2` for fast keying or `--morse-win 15` for slow.
- **LSB**: a printable ratio above 0.9 with readable text is a hit; 0.8-0.9 with gibberish is
  usually a coincidence of quiet audio (many zero samples).

## Extending it

- **SSTV**: the frequency of each sample maps to luminance (1500 Hz black, 2300 Hz white) with
  1200 Hz sync pulses. Add an instantaneous-frequency estimator (`np.angle` of the analytic
  signal, differentiated) and draw a line per sync interval.
- **Echo hiding**: compute the cepstrum of each frame,
  `np.real(np.fft.ifft(np.log(np.abs(np.fft.fft(frame)) + 1e-12)))`, and look for a peak whose
  quefrency alternates between two values across frames - those are your bits.
- **Spectrogram text hiding** (the inverse direction): synthesise a signal whose STFT matches
  an image by summing sinusoids per bright pixel.
- **Binary FSK**: two tones instead of DTMF's pairs; reuse `goertzel` with your two frequencies.

## Gotchas

- `wave` only reads **uncompressed PCM**. Convert first with ffmpeg; a "WAV" holding IMA ADPCM
  or MP3 data will raise `wave.Error`.
- The pure-python DFT fallback is O(n^2) per frame. Without numpy keep `--nfft` at 256 or 512.
- Stereo files are averaged to mono for analysis; if the payload is only in one channel, that
  halves its amplitude. The script prints the mean `|L-R|` so you know whether to split them.
- Morse decoding assumes a single carrier frequency. Two overlapping messages at different
  pitches need band-pass filtering first.
- A spectrogram with nothing in it is still information: it rules out the whole class and sends
  you to LSB or to a tool carrier such as steghide.
