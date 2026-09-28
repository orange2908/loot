---
title: "Power Analysis - SPA, DPA and CPA with ChipWhisperer"
category: hardware
subcategory: side-channel
type: technique
tags: [side-channel, power-analysis, spa, dpa, cpa, chipwhisperer, correlation, hamming-weight, aes, sbox, traces, oscilloscope, leakage-model, pearson, key-recovery]
difficulty: hard
summary: "Recover an AES key from power traces: build the leakage model, correlate hypothetical intermediate values against measured power, byte by byte."
when_to_use:
  - "The challenge ships a .npy/.npz/.csv of power traces plus plaintexts"
  - "You have a ChipWhisperer target running a crypto routine"
  - "SPA shows an obvious pattern but you need the key bits"
tools: [chipwhisperer, numpy, scipy, matplotlib, python]
related: [fault-injection-glitching, mcu-reversing, logic-analyzer-decoding, firmware-arch-identification]
---

## TL;DR

CMOS power draw depends on the data being processed. **SPA** reads the key directly from
one trace's shape (square-and-multiply, PIN comparison loops). **DPA/CPA** needs many
traces: guess one key byte, predict an intermediate value's Hamming weight for every
plaintext, and correlate that prediction against the measured power at each sample.
The correct guess spikes. 16 bytes x 256 guesses, independently - that is why it is
feasible.

## Recognise it

- A dataset of `traces.npy` (N x S floats) plus `plaintexts.npy` (N x 16 bytes),
  sometimes `ciphertexts.npy` and a `key.npy` for training.
- A ChipWhisperer notebook/scope in the challenge description.
- A single trace where repeated blocks of a pattern differ in width or height -
  classic RSA square-and-multiply, or a `strcmp` that exits early.
- The firmware does AES/DES/RSA on a microcontroller with no countermeasures.

## Theory

### Leakage models

Power at time *t* is roughly `P(t) = a * HW(v) + noise`, where `v` is the value on the bus
or in a register at that moment and `HW` is its Hamming weight (number of set bits).
The alternative is the **Hamming distance** model, `HD(v_old, v_new) = HW(v_old XOR v_new)`,
which fits hardware registers better.

### The CPA attack on AES-128, round 1

The first-round S-box output is
`s = SBOX[p_i XOR k_i]` for plaintext byte `p_i` and key byte `k_i`.

That value depends on **one** key byte only. So:

1. Fix a byte position `i` (0..15).
2. For each key guess `k` in 0..255 and each trace `n`, predict
   `H[n][k] = HW(SBOX[p[n][i] XOR k])`.
3. For each sample point `t`, compute the Pearson correlation between the column
   `H[:,k]` and the column `T[:,t]` of measured traces.
4. `score[k] = max_t |corr(H[:,k], T[:,t])|`.
5. The true `k_i` has the largest score. Repeat for all 16 bytes.

Divide and conquer: 16 x 256 = 4096 hypotheses instead of 2^128.

### How many traces

| Setup | Traces needed (rough) |
|---|---|
| ChipWhisperer simple-serial AES, clean | 30 - 100 |
| Software AES on an MCU with a cheap scope | 500 - 5000 |
| Noisy capture, misaligned | 10k+ (and align first) |
| Masked/shuffled implementation | first-order CPA fails; use 2nd-order or template |

### Pearson correlation

```
r(x, y) = sum((x - mean_x) * (y - mean_y)) / sqrt(sum((x-mean_x)^2) * sum((y-mean_y)^2))
```

Computed vectorised over all samples at once, this is fast enough in numpy for
100k-sample traces.

### SPA targets

- **RSA square-and-multiply**: a long operation per bit; "square" and "square+multiply"
  have visibly different durations -> read the exponent bits straight off the trace.
- **Password comparison with early exit**: each correct character adds one loop iteration,
  so the trace gets measurably longer. Byte-by-byte brute force with 256 tries per
  position.
- **Conditional branches on secret data**: different code paths, different shapes.

## Attack

1. Load the traces; plot one to see the structure (how many rounds are visible?).
2. Check alignment: plot 10 traces overlaid. If peaks do not line up, align first
   (cross-correlate against a reference trace).
3. Run CPA on byte 0 with a subset (e.g. 200 traces) to validate the pipeline.
4. If a clear winner emerges, run all 16 bytes.
5. Verify: encrypt a known plaintext with the recovered key and compare to the
   captured ciphertext.
6. If the last round leaks instead (hardware AES), attack `SBOX_INV[c_i XOR k10_i]`
   and run the key schedule backwards.

## Code

```python
#!/usr/bin/env python3
"""cpa_aes.py - correlation power analysis against AES-128 round 1.

Works on any dataset of the form:
    traces      : float array, shape (n_traces, n_samples)
    plaintexts  : uint8 array, shape (n_traces, 16)

With no arguments it synthesises a leaking dataset, runs the attack and asserts that
it recovers the key - so the maths is verified without hardware.

Usage:
  python3 cpa_aes.py traces.npy plaintexts.npy
  python3 cpa_aes.py traces.npy plaintexts.npy --bytes 0 1 2 --traces 500
"""
from __future__ import annotations

import argparse
import sys

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
HW = [bin(i).count("1") for i in range(256)]


def cpa_byte(traces, plaintexts, byte_index: int):
    """Return (best_guess, scores[256], best_sample) for one key byte."""
    import numpy as np

    n_traces, n_samples = traces.shape
    t = traces - traces.mean(axis=0)
    t_ss = (t ** 2).sum(axis=0)
    t_ss[t_ss == 0] = 1e-12

    scores = np.zeros(256)
    best_sample = np.zeros(256, dtype=int)
    pt_col = plaintexts[:, byte_index].astype(np.int32)

    for guess in range(256):
        hyp = np.array([HW[SBOX[p ^ guess]] for p in pt_col], dtype=np.float64)
        h = hyp - hyp.mean()
        h_ss = (h ** 2).sum()
        if h_ss == 0:
            continue
        num = h @ t                       # shape (n_samples,)
        corr = np.abs(num / np.sqrt(h_ss * t_ss))
        idx = int(np.argmax(corr))
        scores[guess] = corr[idx]
        best_sample[guess] = idx

    best = int(scores.argmax())
    return best, scores, int(best_sample[best])


def cpa_full(traces, plaintexts, byte_indices=None, verbose: bool = True):
    import numpy as np

    byte_indices = list(range(16)) if byte_indices is None else list(byte_indices)
    key = [0] * 16
    for i in byte_indices:
        guess, scores, sample = cpa_byte(traces, plaintexts, i)
        order = np.argsort(scores)[::-1]
        margin = scores[order[0]] - scores[order[1]]
        key[i] = guess
        if verbose:
            print(f"byte {i:2d}: 0x{guess:02x}  corr={scores[guess]:.4f}  "
                  f"margin={margin:.4f}  peak@sample {sample}  "
                  f"runner-up 0x{order[1]:02x}")
    return key


def align_traces(traces, reference_index: int = 0, window: int = 200):
    """Cross-correlate each trace against a reference window and shift it into place."""
    import numpy as np

    ref = traces[reference_index, :window]
    ref = ref - ref.mean()
    out = np.zeros_like(traces)
    n_samples = traces.shape[1]
    for i, tr in enumerate(traces):
        seg = tr - tr.mean()
        corr = np.correlate(seg, ref, mode="valid")
        shift = int(np.argmax(corr))
        shifted = np.roll(tr, -shift)
        if shift > 0:
            shifted[-shift:] = tr[-1]
        out[i, :n_samples] = shifted
    return out


def synth_dataset(n_traces: int = 400, n_samples: int = 300, key=None,
                  noise: float = 1.2, leak_sample: int = 120, seed: int = 0):
    """Generate traces that leak HW(SBOX[p ^ k]) at a fixed sample, plus noise."""
    import numpy as np

    rng = np.random.default_rng(seed)
    if key is None:
        key = list(rng.integers(0, 256, size=16))
    pts = rng.integers(0, 256, size=(n_traces, 16)).astype(np.uint8)
    traces = rng.normal(0.0, noise, size=(n_traces, n_samples))
    for i in range(16):
        leak_at = leak_sample + i * 5
        if leak_at >= n_samples:
            continue
        vals = np.array([HW[SBOX[int(p) ^ int(key[i])]] for p in pts[:, i]], dtype=np.float64)
        traces[:, leak_at] += vals
    return traces, pts, list(int(k) for k in key)


def main() -> int:
    ap = argparse.ArgumentParser(description="CPA against AES-128 round 1")
    ap.add_argument("traces")
    ap.add_argument("plaintexts")
    ap.add_argument("--bytes", type=int, nargs="*", default=None)
    ap.add_argument("--traces-count", type=int, default=0)
    ap.add_argument("--align", action="store_true")
    args = ap.parse_args()

    import numpy as np

    traces = np.load(args.traces)
    pts = np.load(args.plaintexts).astype(np.uint8)
    if args.traces_count:
        traces = traces[: args.traces_count]
        pts = pts[: args.traces_count]
    if args.align:
        traces = align_traces(traces)
    print(f"traces {traces.shape}, plaintexts {pts.shape}")

    key = cpa_full(traces, pts, args.bytes)
    print("\nrecovered key: " + "".join(f"{b:02x}" for b in key))
    return 0


def _selftest() -> None:
    try:
        import numpy  # noqa: F401
    except ImportError:
        print("numpy not installed - skipping the CPA self-test", file=sys.stderr)
        return
    traces, pts, key = synth_dataset(n_traces=300, noise=1.0, seed=7)
    recovered = cpa_full(traces, pts, byte_indices=[0, 1, 2, 3], verbose=True)
    assert recovered[:4] == key[:4], (recovered[:4], key[:4])
    print("\ntrue key    : " + "".join(f"{b:02x}" for b in key))
    print("recovered[0:4]: " + "".join(f"{b:02x}" for b in recovered[:4]))
    print("selftest ok")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selftest()
    else:
        sys.exit(main())
```

### ChipWhisperer capture

```python
#!/usr/bin/env python3
"""cw_capture.py - capture AES power traces from a ChipWhisperer target.

Requires the chipwhisperer package and connected hardware (CW-Lite/CW-Nano/Husky
plus an XMEGA/STM32 target running the simpleserial-aes firmware).

Usage: python3 cw_capture.py --count 2000 --out traces
"""
from __future__ import annotations

import argparse
import sys


def capture(count: int, samples: int, out_prefix: str) -> int:
    import chipwhisperer as cw  # type: ignore
    import numpy as np

    scope = cw.scope()
    target = cw.target(scope, cw.targets.SimpleSerial)

    scope.default_setup()
    scope.gain.db = 25
    scope.adc.samples = samples
    scope.adc.offset = 0
    scope.adc.basic_mode = "rising_edge"
    scope.clock.clkgen_freq = 7_370_000
    scope.clock.adc_src = "clkgen_x4"
    scope.trigger.triggers = "tio4"
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"
    scope.io.hs2 = "clkgen"

    key, text = cw.ktp.Basic().next()
    target.set_key(key)

    traces = np.zeros((count, samples), dtype=np.float64)
    plaintexts = np.zeros((count, 16), dtype=np.uint8)
    ciphertexts = np.zeros((count, 16), dtype=np.uint8)

    for i in range(count):
        _key, text = cw.ktp.Basic().next()
        trace = cw.capture_trace(scope, target, text, key)
        if trace is None:
            print(f"  trace {i} failed, retrying", file=sys.stderr)
            continue
        traces[i] = trace.wave
        plaintexts[i] = list(trace.textin)
        ciphertexts[i] = list(trace.textout)
        if i % 100 == 0:
            print(f"  {i}/{count}")

    np.save(f"{out_prefix}_traces.npy", traces)
    np.save(f"{out_prefix}_plaintexts.npy", plaintexts)
    np.save(f"{out_prefix}_ciphertexts.npy", ciphertexts)
    np.save(f"{out_prefix}_key.npy", np.array(list(key), dtype=np.uint8))
    print(f"saved {count} traces of {samples} samples to {out_prefix}_*.npy")

    scope.dis()
    target.dis()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="chipwhisperer AES trace capture")
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--samples", type=int, default=5000)
    ap.add_argument("--out", default="cw")
    args = ap.parse_args()
    return capture(args.count, args.samples, args.out)


if __name__ == "__main__":
    sys.exit(main())
```

### Plotting and SPA inspection

Always look at the traces before running CPA: one trace shows the round structure, an
overlay shows misalignment, and the per-sample standard deviation shows where the
data-dependent leakage actually lives.

```python
#!/usr/bin/env python3
"""spa_plot.py - plot traces to find structure and misalignment before running CPA.

Usage: python3 spa_plot.py traces.npy --out overview.png
"""
from __future__ import annotations

import sys


def plot(path: str, out: str, n: int) -> int:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    traces = np.load(path)
    print(f"{traces.shape[0]} traces of {traces.shape[1]} samples")
    fig, axes = plt.subplots(3, 1, figsize=(14, 10))
    axes[0].plot(traces[0])
    axes[0].set_title("single trace - count the repeating blocks (AES rounds)")
    for i in range(min(n, traces.shape[0])):
        axes[1].plot(traces[i], alpha=0.35, linewidth=0.6)
    axes[1].set_title("traces overlaid - peaks must line up or CPA will fail")
    axes[2].plot(traces.std(axis=0))
    axes[2].set_title("per-sample standard deviation - leakage regions spike")
    plt.tight_layout()
    plt.savefig(out, dpi=110)
    print(f"wrote {out}")
    top = np.argsort(traces.std(axis=0))[::-1][:10]
    print("highest-variance samples:", sorted(int(t) for t in top))
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    out = args[args.index("--out") + 1] if "--out" in args else "traces.png"
    sys.exit(plot(args[0], out, 20))
```

## Variants & pitfalls

- **Traces are misaligned** - a variable-latency trigger or a jittery clock. CPA
  collapses. Align by cross-correlation (function above) or use a static-alignment
  preprocessing pass; resampling helps with clock jitter.
- **Wrong leakage model** - hardware implementations often leak Hamming *distance*
  between consecutive register values, not Hamming weight. Try `HW(SBOX[p^k] ^ p)`.
- **Attacking the last round** - for hardware AES, use
  `hyp = HW(SBOX_INV[c_i ^ k10_i])`, recover the round-10 key, then invert the key
  schedule to get the master key.
- **Masked implementations** defeat first-order CPA by construction. Options: second-order
  (combine two sample points), or template attacks with a profiling device.
- **Shuffling** randomises the byte order per execution; you need far more traces or
  an integration-based approach.
- **DPA (difference of means) vs CPA** - DPA splits traces by one bit of the hypothesis
  and subtracts the means. It works, but CPA converges with fewer traces and gives a
  cleaner ranking. Use CPA unless the challenge explicitly wants DPA.
- **Memory** - 100k traces x 50k samples of float64 is 40 GB. Use float32, crop the
  region of interest first, and process in chunks.

## Tools

- `chipwhisperer` - capture hardware plus a complete analysis library
  (`cw.analyzer.cpa`, correlation progress plots).
- `numpy` / `scipy` / `matplotlib` - the whole attack is 40 lines of numpy.
- `lascar`, `scared` - open-source side-channel analysis frameworks with more models.
- `Jlsca` - Julia-based, fast for very large datasets.
- A digital oscilloscope plus a current probe or a 10-50 ohm shunt, if you have no CW.

## References

- ChipWhisperer documentation and its tutorial series on CPA against AES.
- Kocher, Jaffe and Jun, "Differential Power Analysis" (the original DPA paper).
- Brier, Clavier and Olivier, "Correlation Power Analysis with a Leakage Model".
