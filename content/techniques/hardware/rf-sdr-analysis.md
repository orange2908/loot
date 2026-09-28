---
title: "RF and SDR - Capturing, Demodulating OOK/ASK/FSK and Replaying"
category: hardware
subcategory: sdr
type: technique
tags: [sdr, rtl-sdr, hackrf, gqrx, urh, inspectrum, rtl-433, iq, ook, ask, fsk, psk, manchester, demodulation, replay-attack, waterfall, gnuradio, sample-rate]
difficulty: medium
summary: "Find a signal in the spectrum, capture IQ, identify the modulation, demodulate to bits, decode the line coding and replay it."
when_to_use:
  - "The challenge gives you a .cu8/.cs16/.wav/.complex IQ capture"
  - "You have an RTL-SDR/HackRF and a device transmitting on an ISM band"
  - "A remote control, sensor or key fob must be understood or replayed"
tools: [rtl_sdr, hackrf, gqrx, urh, inspectrum, rtl_433, gnuradio, python, numpy]
related: [rf-protocols-rfid-ble, logic-analyzer-decoding, protocol-decoders, rf-sdr-cheatsheet]
---

## TL;DR

Capture IQ at a sample rate >= 2x the signal bandwidth, look at it in
`inspectrum` or URH, identify the modulation by shape (amplitude steps = OOK/ASK,
constant amplitude with a frequency shift = FSK), demodulate to a bit stream, find the
symbol rate from the shortest pulse, decode the line coding (usually Manchester or
PWM), and you have the payload. `rtl_433` already knows hundreds of these protocols -
try it first.

## Recognise it

- Files: `.cu8` (unsigned 8-bit IQ, rtl_sdr default), `.cs16`/`.sc16`, `.cf32`/`.complex`
  (float32 IQ), `.wav` (2-channel = I and Q), `.sub` (Flipper Zero), `.sr`.
- Filenames often encode the parameters: `capture_433920000Hz_2048000sps.cu8`.
- A waterfall showing short bursts repeated 3-5 times (a remote pressing once sends
  the frame several times).
- ISM band centre frequencies: 315, 433.92, 868.3, 915 MHz, 2.4 GHz.

## Theory

### IQ basics

An SDR gives you complex samples `I + jQ`. The magnitude `|z| = sqrt(I^2+Q^2)` is the
amplitude envelope; the derivative of the phase `angle(z[n] * conj(z[n-1]))` is the
instantaneous frequency. That is all you need:

- **OOK / ASK** (amplitude): look at `|z|`, threshold it -> bits.
- **FSK / GFSK / MSK** (frequency): look at the phase derivative, threshold it -> bits.
- **PSK** (phase): look at `angle(z)` after carrier recovery; harder, rarer in CTF.

Sample rate must be at least twice the occupied bandwidth (Nyquist), and in practice
8-20x the symbol rate makes edge timing easy.

### Modulation identification by eye

| Waterfall / time-domain look | Modulation |
|---|---|
| Amplitude turns fully on and off, single frequency line | OOK |
| Amplitude varies between two non-zero levels | ASK |
| Two parallel lines in the waterfall, constant amplitude | 2-FSK |
| Four lines | 4-FSK |
| Smeared single line, constant amplitude, phase jumps | PSK |
| Wide, noise-like, constant envelope | spread spectrum / FHSS (Bluetooth, ZigBee) |
| Line hopping across channels | FHSS |

### Line coding (after demodulation)

| Coding | Description | Symbol pattern |
|---|---|---|
| NRZ | bit = level for the whole symbol | `1`=high, `0`=low |
| Manchester (IEEE) | mid-symbol transition | `1`= low->high, `0`= high->low |
| Manchester (Thomas) | inverse of the above | `1`= high->low |
| PWM / PPM | bit encoded as pulse width | `1` = long high + short low, `0` = short high + long low |
| Differential | a transition means 1, no transition means 0 | |

PWM is dominant in cheap 433 MHz remotes (EV1527, PT2262, HT12E). A typical EV1527 frame:
a long sync low, then 24 bits, each `short-high + long-low` (0) or `long-high + short-low` (1).

### Symbol rate

`symbol_rate = sample_rate / samples_in_shortest_pulse`. Measure the shortest pulse in
inspectrum with cursors, or compute it (the script below does).

## Attack

1. Find the frequency: `gqrx`/`SDR++` waterfall, or sweep with `hackrf_sweep`/`rtl_power`.
2. Capture IQ with generous margin (2 Msps at 433.92 MHz is standard).
3. Try `rtl_433 -A` first - if it is a known consumer protocol you are done.
4. Otherwise load into URH: autodetect modulation, set the symbol rate, read the bits.
5. Identify the line coding from the bit pattern (lots of `01`/`10` pairs = Manchester).
6. Decode the payload; look for a rolling code (changes each press) vs fixed code.
7. Replay with HackRF/`rpitx`/Flipper, or synthesise a new frame and transmit.

## Code

### Capture

```bash
# what is out there: a power sweep
rtl_power -f 400M:500M:100k -g 40 -i 10 -e 60 sweep.csv
hackrf_sweep -f 300:1000 -w 1000000 > sweep.txt

# interactive: gqrx / SDR++ / CubicSDR, set 433.900 MHz, 2 Msps, AM demod, watch the waterfall

# capture IQ with rtl-sdr (cu8: unsigned 8-bit interleaved I,Q)
rtl_sdr -f 433920000 -s 2048000 -g 40 -n 20480000 capture.cu8      # 10 seconds
rtl_sdr -f 433920000 -s 2048000 -g 49.6 - | head -c 40000000 > capture.cu8

# hackrf (cs8 interleaved)
hackrf_transfer -r capture.cs8 -f 433920000 -s 8000000 -l 24 -g 32 -a 1
hackrf_transfer -r capture.cs8 -f 868300000 -s 2000000 -l 16 -g 20

# airspy / sdrplay
airspy_rx -r capture.iq -f 433.92 -a 3000000

# record straight to wav (2 channels = I/Q) for tools that want audio
rtl_fm -M raw -f 433.92M -s 250k capture.raw
sox -r 250000 -e signed -b 16 -c 2 capture.raw capture.wav

# known protocols: try this before doing any work yourself
rtl_433 -f 433.92M -s 250k -A                 # -A = analyse mode, prints pulse timings
rtl_433 -f 433.92M -F json -M level
rtl_433 -r capture.cu8 -A                     # offline, on a saved capture
rtl_433 -R 0 -X 'n=custom,m=OOK_PWM,s=350,l=1050,r=10000,g=500,t=50,y=0' -r capture.cu8
```

### Analysing

```bash
# inspectrum: visual IQ inspection with symbol extraction
inspectrum -r 2048000 capture.cu8
#  - set the sample rate, drag a selection over a burst
#  - add an "Amplitude Demod" plot for OOK, "Frequency Demod" for FSK
#  - enable the symbol overlay, set the symbol period from the shortest pulse,
#    then right-click > "Copy bits" to get the bit string

# URH (Universal Radio Hacker): the most complete workflow
urh                                            # GUI
#  Interpretation tab: autodetect modulation, tune "Samples/Symbol" and the centre
#  Analysis tab: set the decoding (Manchester I/II, Differential, NRZ-I), label fields
#  Generator tab: build a modified frame
#  Simulator tab: replay / fuzz

urh_cli -d RTL-SDR -f 433.92e6 -s 2e6 -rx -file capture.complex
urh_cli --help

# gnuradio-companion for custom flowgraphs
gnuradio-companion
# typical chain: File Source -> Throttle -> Complex to Mag^2 -> Threshold -> File Sink
```

### Pure-Python IQ demodulation

```python
#!/usr/bin/env python3
"""iqdemod.py - load an IQ capture, demodulate OOK/ASK or FSK, and print the bits.

Supports .cu8 (rtl_sdr), .cs8, .cs16 and .cf32 IQ files. With no arguments it
synthesises an OOK burst, demodulates it and asserts the payload round-trips.

Usage:
  python3 iqdemod.py capture.cu8 --rate 2048000 --mode ook
  python3 iqdemod.py capture.cf32 --rate 2000000 --mode fsk --symrate 4800
"""
from __future__ import annotations

import argparse
import sys


def load_iq(path: str, fmt: str | None = None):
    import numpy as np

    fmt = fmt or path.rsplit(".", 1)[-1].lower()
    with open(path, "rb") as fh:
        raw = fh.read()
    if fmt in ("cu8", "u8", "bin"):
        a = np.frombuffer(raw, dtype=np.uint8).astype(np.float32)
        a = (a - 127.5) / 127.5
    elif fmt in ("cs8", "s8"):
        a = np.frombuffer(raw, dtype=np.int8).astype(np.float32) / 128.0
    elif fmt in ("cs16", "sc16", "s16"):
        a = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    elif fmt in ("cf32", "complex", "fc32", "f32"):
        a = np.frombuffer(raw, dtype=np.float32)
    else:
        raise ValueError(f"unknown IQ format: {fmt}")
    if len(a) % 2:
        a = a[:-1]
    return a[0::2] + 1j * a[1::2]


def envelope(iq, smooth: int = 16):
    import numpy as np

    mag = np.abs(iq)
    if smooth > 1:
        kernel = np.ones(smooth) / smooth
        mag = np.convolve(mag, kernel, mode="same")
    return mag


def inst_freq(iq, smooth: int = 16):
    import numpy as np

    d = iq[1:] * np.conj(iq[:-1])
    f = np.angle(d)
    if smooth > 1:
        f = np.convolve(f, np.ones(smooth) / smooth, mode="same")
    return f


def threshold_runs(signal, level: float) -> list[tuple[int, int]]:
    """Return [(value, run_length), ...] for the thresholded signal."""
    bits = (signal > level).astype(int)
    runs = []
    cur = bits[0]
    n = 1
    for b in bits[1:]:
        if b == cur:
            n += 1
        else:
            runs.append((int(cur), n))
            cur = b
            n = 1
    runs.append((int(cur), n))
    return runs


def estimate_symbol_len(runs: list[tuple[int, int]], min_len: int = 4) -> int:
    """Shortest meaningful run = one symbol period (robust to a few glitches)."""
    lens = sorted(n for _v, n in runs if n >= min_len)
    if not lens:
        return 1
    # use a low percentile rather than the strict minimum, to ignore noise spikes
    return max(1, lens[max(0, len(lens) // 20)])


def runs_to_bits(runs: list[tuple[int, int]], symbol_len: int,
                 min_len: int = 2) -> str:
    out = []
    for val, n in runs:
        if n < min_len:
            continue
        count = max(1, int(round(n / symbol_len)))
        out.append(str(val) * count)
    return "".join(out)


def decode_manchester(bits: str, invert: bool = False) -> str | None:
    """Pairs '01'->1 and '10'->0 (IEEE); invert swaps them."""
    if len(bits) < 2:
        return None
    out = []
    for i in range(0, len(bits) - 1, 2):
        pair = bits[i:i + 2]
        if pair == "01":
            out.append("0" if invert else "1")
        elif pair == "10":
            out.append("1" if invert else "0")
        else:
            return None            # not valid manchester
    return "".join(out)


def decode_pwm(runs: list[tuple[int, int]], short: int, long_: int,
               tol: float = 0.4) -> str:
    """Classic EV1527/PT2262: long high + short low = 1, short high + long low = 0."""
    out = []
    highs = [(v, n) for v, n in runs]
    i = 0
    while i + 1 < len(highs):
        (v1, n1), (v2, n2) = highs[i], highs[i + 1]
        if v1 == 1 and v2 == 0:
            if abs(n1 - long_) < long_ * tol and abs(n2 - short) < long_ * tol:
                out.append("1")
            elif abs(n1 - short) < long_ * tol and abs(n2 - long_) < long_ * tol:
                out.append("0")
            i += 2
        else:
            i += 1
    return "".join(out)


def bits_to_hex(bits: str) -> str:
    pad = (-len(bits)) % 8
    b = bits + "0" * pad
    return "".join(f"{int(b[i:i+8], 2):02x}" for i in range(0, len(b), 8))


def analyse(path: str, rate: int, mode: str, fmt: str | None = None) -> dict:
    import numpy as np

    iq = load_iq(path, fmt)
    print(f"loaded {len(iq)} IQ samples ({len(iq)/rate:.3f} s at {rate} sps)")

    if mode == "fsk":
        sig = inst_freq(iq)
        level = float(np.median(sig))
    else:
        sig = envelope(iq)
        noise = float(np.percentile(sig, 20))
        peak = float(np.percentile(sig, 99))
        level = noise + (peak - noise) * 0.5
        print(f"envelope: noise={noise:.4f} peak={peak:.4f} threshold={level:.4f}")

    runs = threshold_runs(sig, level)
    active = [(v, n) for v, n in runs if n > 3]
    sym = estimate_symbol_len(active)
    print(f"{len(runs)} runs, estimated symbol length {sym} samples "
          f"-> {rate/max(1,sym):.0f} symbols/s")

    bits = runs_to_bits(active, sym)
    print(f"raw bits ({len(bits)}): {bits[:200]}")

    man = decode_manchester(bits)
    if man:
        print(f"manchester ({len(man)}): {man[:120]}  hex={bits_to_hex(man)[:64]}")
    lens = sorted({n for _v, n in active})
    if len(lens) >= 2:
        pwm = decode_pwm(active, lens[0], lens[-1] if lens[-1] < lens[0] * 6 else lens[1])
        if pwm:
            print(f"pwm ({len(pwm)}): {pwm[:120]}  hex={bits_to_hex(pwm)[:64]}")
    print(f"raw hex: {bits_to_hex(bits)[:96]}")
    return {"bits": bits, "symbol_len": sym, "manchester": man}


def synth_ook(payload_bits: str, rate: int = 1_000_000, symrate: int = 2000,
              noise: float = 0.02):
    """Generate an OOK burst for the self-test."""
    import numpy as np

    sps = rate // symrate
    samples = []
    for b in payload_bits:
        samples.extend([1.0 if b == "1" else 0.0] * sps)
    env = np.array(samples, dtype=np.float32)
    env = np.concatenate([np.zeros(sps * 4, dtype=np.float32), env,
                          np.zeros(sps * 4, dtype=np.float32)])
    rng = np.random.default_rng(0)
    iq = env * np.exp(1j * 2 * np.pi * 0.01 * np.arange(len(env)))
    iq = iq + (rng.normal(0, noise, len(env)) + 1j * rng.normal(0, noise, len(env)))
    return iq.astype(np.complex64)


def main() -> int:
    ap = argparse.ArgumentParser(description="IQ demodulator")
    ap.add_argument("capture")
    ap.add_argument("--rate", type=int, default=2048000)
    ap.add_argument("--mode", choices=["ook", "ask", "fsk"], default="ook")
    ap.add_argument("--format", default=None)
    args = ap.parse_args()
    analyse(args.capture, args.rate, args.mode, args.format)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        try:
            import numpy as np
        except ImportError:
            print("numpy required for the self-test", file=sys.stderr)
            sys.exit(0)
        import os
        import tempfile

        payload = "1011001110001111"
        iq = synth_ook(payload, rate=1_000_000, symrate=2000)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.cf32")
            inter = np.empty(len(iq) * 2, dtype=np.float32)
            inter[0::2] = iq.real
            inter[1::2] = iq.imag
            with open(p, "wb") as fh:
                fh.write(inter.tobytes())
            res = analyse(p, 1_000_000, "ook")
        bits = res["bits"]
        assert payload in bits, (payload, bits[:80])
        assert decode_manchester("0110") == "10"
        assert decode_manchester("0110", invert=True) == "01"
        assert decode_manchester("0011") is None
        assert bits_to_hex("10110011") == "b3"
        print("selftest ok")
    else:
        sys.exit(main())
```

### Replaying and transmitting

```bash
# replay a raw capture exactly as recorded (hackrf can transmit)
hackrf_transfer -t capture.cs8 -f 433920000 -s 8000000 -x 20 -a 1

# transmit from a raspberry pi gpio (rpitx) - no sdr needed
sudo rpitx -m IQFLOAT -i capture.cf32 -s 250000 -f 433920

# URH: load the capture, modify a field in the Generator tab, then send
urh_cli -d HackRF -f 433.92e6 -s 2e6 -tx -file modified.complex

# flipper zero .sub files are text; the "RAW_Data" lines are microsecond durations
head -20 remote.sub

# synthesise an OOK frame from bits with python, then transmit
python3 - <<'PY'
import numpy as np
bits = "101100111000111101011010"
rate, symrate = 2_000_000, 2000
sps = rate // symrate
env = np.repeat(np.array([1.0 if b == '1' else 0.0 for b in bits]), sps)
iq = (env + 0j).astype(np.complex64)
inter = np.empty(len(iq)*2, dtype=np.float32)
inter[0::2], inter[1::2] = iq.real, iq.imag
inter.tofile('tx.cf32')
print('wrote tx.cf32', len(iq), 'samples')
PY
```

## Variants & pitfalls

- **Nothing in the waterfall** - wrong frequency, gain too low, or the device only
  transmits on an event (press the button while recording). Also check the antenna:
  a 433 MHz whip on a 2.4 GHz signal receives nothing.
- **DC spike at the centre** - normal for direct-conversion receivers. Tune 100-200 kHz
  off the signal so it does not sit under the spike.
- **Rolling codes** (KeeLoq, modern car fobs) cannot be replayed usefully; each press is
  different. CTF targets are almost always fixed-code.
- **Manchester ambiguity** - IEEE 802.3 and G.E. Thomas conventions are inverses.
  If the decoded payload looks like noise, invert.
- **CRC**: many frames end in a CRC-8/CRC-16. `reveng` can identify the polynomial from
  a few known frames.
- **`rtl_433 -A`** prints the pulse timings and even suggests an `-X` flex decoder line -
  that is often the fastest path to the bits.

## Tools

- `rtl_sdr`, `rtl_power`, `rtl_433`, `rtl_fm` (rtl-sdr package).
- `hackrf_transfer`, `hackrf_sweep`, `airspy_rx`.
- `gqrx`, `SDR++`, `CubicSDR` - waterfall and live demod.
- `inspectrum` - IQ inspection with a symbol-extraction overlay.
- `URH` (Universal Radio Hacker) - capture, interpret, decode, generate, fuzz.
- `GNU Radio` / `gnuradio-companion` - custom DSP chains.
- `universal-radio-hacker`, `reveng` (CRC identification), `numpy`.

## References

- rtl_433 project documentation, including the flex decoder (`-X`) syntax.
- Universal Radio Hacker documentation on modulation interpretation and decodings.
- inspectrum project documentation for the amplitude/frequency demod plots.
