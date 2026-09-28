---
title: "Fault Injection - Voltage and Clock Glitching for CTF"
category: hardware
subcategory: fault-injection
type: technique
tags: [glitching, fault-injection, voltage-glitch, clock-glitch, chipwhisperer, crowbar, emfi, laser-fi, glitch-parameters, rdp-bypass, secure-boot, mosfet, trigger, search-space]
difficulty: insane
summary: "Skip an instruction or corrupt a comparison by disturbing the target's power or clock at a precisely timed moment, and search the parameter space efficiently."
when_to_use:
  - "A password/PIN check must be bypassed and there is no software bug"
  - "You need to read a readout-protected MCU's flash"
  - "The challenge provides a ChipWhisperer glitch target or a simulator"
tools: [chipwhisperer, python, oscilloscope, mosfet, fpga]
related: [side-channel-power-analysis, jtag-swd, mcu-reversing, uart-serial]
---

## TL;DR

Briefly violate the target's operating conditions (drop Vcc for tens of nanoseconds,
or insert a too-short clock cycle) at the exact moment a security check executes.
The CPU mis-fetches, mis-decodes or mis-writes, and a branch is skipped or a comparison
returns the wrong answer. The whole difficulty is the search: `(offset, width, strength)`
with a reliable trigger, and a way to classify each attempt as normal / reset / success.

## Recognise it

- A device that accepts a PIN/password and has no exploitable software path.
- A bootloader that checks a signature and then jumps.
- A readout-protected MCU (STM32 RDP-1, nRF52 APPROTECT) whose flash you want.
- A CTF that gives you a `glitch()` API, a simulator, or ChipWhisperer hardware.
- The classic target loop: a counter that must reach a value, where a skipped
  instruction breaks the invariant.

## Theory

### What a fault actually does

At the instant of the glitch, the most fragile operations fail first:

| Effect | Typical consequence |
|---|---|
| Instruction skip | a `bl check_password` or a conditional branch never executes |
| Instruction corruption | an opcode decodes as something else (often a NOP or a different register) |
| Register/bus corruption | a loaded value is wrong, e.g. a comparison result flips |
| Memory write failure | a "lock" flag is never written |
| Loop counter corruption | a bounded loop exits early or runs long |

The single most useful mental model in CTF: **you get to skip one instruction**.
Look at the disassembly and ask "which single instruction, if skipped, wins?".

### Voltage glitching (crowbar)

Short Vcc to ground through a MOSFET for a very short time. Parameters:

- **offset** (delay from the trigger): where in the execution you hit. Range:
  0 to a few hundred thousand clock cycles.
- **width** (glitch duration): typically 5-200 ns. Too short does nothing, too long resets.
- **repeat** / number of consecutive glitched cycles.

Decoupling capacitors fight you; a successful voltage glitch often needs the
target's decoupling caps removed.

### Clock glitching

Only works when you control the target's clock (external oscillator). You insert an extra
edge, producing one clock period shorter than the setup time of the logic. Parameters:

- **width** (% of a clock period)
- **offset** (phase within the period, can be negative)
- **ext_offset** (how many clock cycles after the trigger)

Cleaner and more repeatable than voltage glitching, but requires clock access.

### EM and laser

EMFI: a small coil discharges near the die, inducing currents. Needs `X/Y` position as
extra search dimensions, but needs no electrical contact and works through packages.
Laser FI: highest precision, needs a decapsulated die. Both are out of scope for most
CTFs but the parameter-search methodology is identical.

### The search

The space is `offset x width x strength`, typically 10^5-10^7 points. Strategy:

1. **Get a tight trigger.** A GPIO the target toggles, a UART byte, or a power-trace
   pattern match. Without a trigger, offsets drift and nothing is reproducible.
2. **Narrow the offset window** by measuring how long the target takes between the
   trigger and the decision (power trace, or scope on a GPIO).
3. **Random search first**, then local refinement around any anomaly.
4. **Classify every attempt**: `normal`, `reset/crash`, `mute` (no response),
   `SUCCESS`. Resets are informative - they mean you are hitting hard enough.
5. **Keep every result.** The map of "where resets happen" brackets the region where
   successes live.

## Attack

1. Reverse the firmware, find the check, and identify the instruction to skip.
2. Wire a trigger (a GPIO set right before the check is ideal; otherwise use the
   serial command byte).
3. Calibrate: sweep offsets with an aggressive width until you see resets. That proves
   your glitch reaches the target.
4. Back the width off until you see a mix of normal and reset outcomes - successes live
   on that boundary.
5. Random-search the bracketed region, logging every `(params, outcome)`.
6. On the first success, re-run those parameters many times to measure the success rate,
   then refine.

## Code

```python
#!/usr/bin/env python3
"""glitch_search.py - parameter search engine for fault injection.

Separates the search strategy from the hardware. Plug in any `attempt(params)`
callback that arms the glitcher, runs one trial, and returns an Outcome.

Includes a software-simulated target so the search logic can be tested with no
hardware at all.

Usage:
  python3 glitch_search.py                # run against the built-in simulator
  python3 glitch_search.py --trials 20000
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum


class Outcome(str, Enum):
    NORMAL = "normal"      # target behaved as expected
    RESET = "reset"        # target crashed/rebooted - glitch too strong
    MUTE = "mute"          # no response at all
    SUCCESS = "success"    # the check was bypassed


@dataclass
class Params:
    offset: int            # delay from trigger, in clock cycles or ns
    width: int             # glitch duration
    strength: float = 1.0  # voltage level / glitch repeat count

    def key(self) -> tuple:
        return (self.offset, self.width, round(self.strength, 3))


@dataclass
class SearchSpace:
    offset_min: int
    offset_max: int
    width_min: int
    width_max: int
    strength_min: float = 1.0
    strength_max: float = 1.0

    def random(self, rng: random.Random) -> Params:
        return Params(
            offset=rng.randint(self.offset_min, self.offset_max),
            width=rng.randint(self.width_min, self.width_max),
            strength=rng.uniform(self.strength_min, self.strength_max),
        )

    def around(self, p: Params, rng: random.Random, frac: float = 0.05) -> Params:
        ospan = max(1, int((self.offset_max - self.offset_min) * frac))
        wspan = max(1, int((self.width_max - self.width_min) * frac))
        return Params(
            offset=min(self.offset_max, max(self.offset_min,
                                            p.offset + rng.randint(-ospan, ospan))),
            width=min(self.width_max, max(self.width_min,
                                          p.width + rng.randint(-wspan, wspan))),
            strength=min(self.strength_max, max(self.strength_min,
                                                p.strength + rng.uniform(-0.05, 0.05))),
        )


@dataclass
class Campaign:
    space: SearchSpace
    results: dict = field(default_factory=dict)
    successes: list = field(default_factory=list)
    counts: dict = field(default_factory=lambda: {o.value: 0 for o in Outcome})

    def record(self, p: Params, outcome: Outcome) -> None:
        self.results[p.key()] = outcome.value
        self.counts[outcome.value] += 1
        if outcome is Outcome.SUCCESS:
            self.successes.append(p)

    def summary(self) -> str:
        total = sum(self.counts.values())
        lines = [f"attempts: {total}"]
        for k, v in self.counts.items():
            if v:
                lines.append(f"  {k:<8} {v:>7}  ({v/max(1,total):.2%})")
        if self.successes:
            offs = [p.offset for p in self.successes]
            wids = [p.width for p in self.successes]
            lines.append(f"  success offset range: {min(offs)} .. {max(offs)}")
            lines.append(f"  success width  range: {min(wids)} .. {max(wids)}")
        return "\n".join(lines)

    def save(self, path: str) -> None:
        data = {
            "space": asdict(self.space),
            "counts": self.counts,
            "successes": [asdict(p) for p in self.successes],
            "results": {f"{k[0]},{k[1]},{k[2]}": v for k, v in self.results.items()},
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)


def search(attempt, space: SearchSpace, trials: int = 5000, seed: int = 0,
           refine_after_success: int = 200, verbose: bool = True) -> Campaign:
    """Random search with local refinement once anything interesting is seen."""
    rng = random.Random(seed)
    camp = Campaign(space=space)
    focus: Params | None = None
    refine_left = 0

    for i in range(trials):
        if focus is not None and refine_left > 0:
            p = space.around(focus, rng)
            refine_left -= 1
        else:
            p = space.random(rng)
            focus = None

        if p.key() in camp.results:
            continue
        outcome = attempt(p)
        camp.record(p, outcome)

        if outcome in (Outcome.SUCCESS, Outcome.RESET) and refine_left <= 0:
            focus = p
            refine_left = refine_after_success
            if verbose and outcome is Outcome.SUCCESS:
                print(f"[{i}] SUCCESS offset={p.offset} width={p.width} "
                      f"strength={p.strength:.2f}")
        if verbose and i and i % 2000 == 0:
            print(f"[{i}] " + " ".join(f"{k}={v}" for k, v in camp.counts.items() if v))
    return camp


# ---------------------------------------------------------------------------
# software-simulated target: a narrow (offset, width) window flips the check
# ---------------------------------------------------------------------------
def make_simulated_target(true_offset: int = 4200, true_width: int = 38,
                          offset_tol: int = 6, width_tol: int = 4,
                          success_rate: float = 0.35, seed: int = 1):
    rng = random.Random(seed)

    def attempt(p: Params) -> Outcome:
        if p.width > true_width + 25:
            return Outcome.RESET                     # far too strong
        if p.width < true_width - 20:
            return Outcome.NORMAL                    # far too weak, no effect
        near_offset = abs(p.offset - true_offset) <= offset_tol
        near_width = abs(p.width - true_width) <= width_tol
        if near_offset and near_width:
            if rng.random() < success_rate:
                return Outcome.SUCCESS
            return Outcome.RESET if rng.random() < 0.4 else Outcome.NORMAL
        if near_width and rng.random() < 0.08:
            return Outcome.RESET
        return Outcome.NORMAL

    return attempt


def main() -> int:
    ap = argparse.ArgumentParser(description="fault injection parameter search")
    ap.add_argument("--trials", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--save", default=None)
    args = ap.parse_args()

    space = SearchSpace(offset_min=0, offset_max=8000, width_min=1, width_max=80)
    attempt = make_simulated_target()
    camp = search(attempt, space, trials=args.trials, seed=args.seed)
    print("\n" + camp.summary())
    if args.save:
        camp.save(args.save)
        print(f"saved {args.save}")
    return 0 if camp.successes else 1


if __name__ == "__main__":
    if len(sys.argv) == 1:
        space = SearchSpace(offset_min=4000, offset_max=4500, width_min=20, width_max=60)
        camp = search(make_simulated_target(), space, trials=4000, seed=3, verbose=False)
        assert camp.successes, "search found no glitch parameters"
        offs = [p.offset for p in camp.successes]
        assert min(offs) >= 4194 and max(offs) <= 4206, (min(offs), max(offs))
        print(camp.summary())
        print("selftest ok")
    else:
        sys.exit(main())
```

### ChipWhisperer glitch loop

The classification logic is the part worth copying: every attempt must end in a known
state, and a reset must be recovered from before the next trial.

```python
#!/usr/bin/env python3
"""cw_glitch.py - clock or voltage glitch campaign on a ChipWhisperer target.

Requires chipwhisperer and real hardware.

Usage: python3 cw_glitch.py clock 5000
"""
from __future__ import annotations

import random
import sys


def classify(target, expected: bytes) -> str:
    try:
        response = target.read(timeout=50)
    except Exception:                        # noqa: BLE001 - serial layer raises broadly
        return "mute"
    if not response:
        return "mute"
    raw = response.encode() if isinstance(response, str) else bytes(response)
    if b"boot" in raw.lower():
        return "reset"
    return "normal" if expected in raw else "success"


def run(mode: str, trials: int) -> int:
    import chipwhisperer as cw  # type: ignore

    scope = cw.scope()
    target = cw.target(scope, cw.targets.SimpleSerial)
    scope.default_setup()
    scope.glitch.clk_src = "clkgen"
    scope.glitch.trigger_src = "ext_single"
    if mode == "clock":
        scope.glitch.output = "clock_xor"
        scope.io.hs2 = "glitch"
    else:
        scope.glitch.output = "glitch_only"
        scope.io.glitch_lp = True
        scope.io.glitch_hp = True
        scope.io.hs2 = "clkgen"

    rng = random.Random(0)
    successes = []
    for i in range(trials):
        if mode == "clock":
            scope.glitch.width = rng.uniform(-45, 45)
            scope.glitch.offset = rng.uniform(-45, 45)
        else:
            scope.glitch.repeat = rng.randint(1, 12)
        scope.glitch.ext_offset = rng.randint(0, 5000)
        params = (scope.glitch.width if mode == "clock" else scope.glitch.repeat,
                  scope.glitch.ext_offset)

        scope.arm()
        target.flush()
        target.write("p" + "00" * 16 + "\n")     # whatever triggers the check
        scope.capture()

        outcome = classify(target, expected=b"DENIED")
        if outcome == "success":
            successes.append(params)
            print(f"[{i}] SUCCESS params={params}")
        elif outcome in ("reset", "mute"):
            target.flush()
            scope.io.nrst = "low"
            scope.io.nrst = "high_z"
        if i % 250 == 0:
            print(f"[{i}] successes={len(successes)}")

    scope.dis()
    target.dis()
    return 0 if successes else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 2000))
```

### Reading the results

```bash
# where do resets cluster? that brackets the useful offset window
awk -F, '$4=="reset"  {print $3}' glitch_log.csv | sort -n | head -1
awk -F, '$4=="reset"  {print $3}' glitch_log.csv | sort -n | tail -1
awk -F, '$4=="success"{print}' glitch_log.csv

# outcome histogram
awk -F, '{c[$4]++} END {for (k in c) printf "%-8s %d\n", k, c[k]}' glitch_log.csv

# re-run the winning parameters 100 times to measure reliability
awk -F, '$4=="success"{print $1","$2","$3; exit}' glitch_log.csv
```

## Variants & pitfalls

- **No trigger = no attack.** Everything depends on a repeatable time reference.
  If the firmware offers none, trigger on the last byte of the serial command, or use
  a power-trace pattern trigger (ChipWhisperer Husky's SAD trigger).
- **Jitter** - interrupts, cache, DRAM refresh and clock PLLs move the target instruction
  by hundreds of cycles between runs. Disable interrupts in the target if you control it;
  otherwise widen the offset window and accept a low success rate.
- **Decoupling capacitors** absorb voltage glitches. On a real board you often have to
  remove them; on a dev board they are already thinned out.
- **Never seeing resets** means your glitch is not reaching the die: check the MOSFET,
  the path inductance, and that you are glitching the core rail (not a regulated
  downstream rail).
- **Success that does not reproduce** - you glitched a different code path, or the
  "success" classifier is wrong. Make the classifier strict and re-verify.
- **Double glitching** (two faults in one run) is sometimes needed, e.g. to bypass a check
  and then a verification of the check. The search space squares - use the results of the
  single-glitch campaign as priors.

## Tools

- `ChipWhisperer` (Lite / Nano / Husky) - integrated glitcher, trigger and capture.
- A cheap alternative: an FPGA board (iCEBreaker, Lattice) or a fast MCU plus a
  logic-level MOSFET for the crowbar.
- `PicoEMP` - open-source EM fault injection.
- Oscilloscope - essential for confirming the glitch shape actually reaches the pin.
- `numpy`/`matplotlib` - plotting the outcome map over `(offset, width)`.

## References

- ChipWhisperer documentation: clock and voltage glitching tutorials and the
  `scope.glitch` parameter reference.
- Bar-El et al., "The Sorcerer's Apprentice Guide to Fault Attacks" (survey).
- Boneh, DeMillo and Lipton, "On the Importance of Checking Cryptographic Protocols
  for Faults" (the original fault-attack result).
