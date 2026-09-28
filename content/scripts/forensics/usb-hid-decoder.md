---
title: "USB HID Decoder - Keystrokes and Mouse Drawings"
category: forensics
subcategory: usb
type: script
tags: [usb, usbhid, hid, keyboard, mouse, capdata, tshark, keystroke-recovery, scancode, pcap, python, dfir, usbmon, usbpcap, wireshark, matplotlib, keylogger]
summary: "One script that turns usb.capdata hex - from a file, stdin or a pcap via tshark - into the text that was typed or the picture that was drawn."
tools: [python3, tshark, wireshark, usbmon, usbpcap, matplotlib]
related: [network-usb-hid, network-pcap-triage, pcap-extractor, tshark-wireshark-cheatsheet]
---

## What it does

Decodes USB HID boot-protocol reports. In keyboard mode it maps usage IDs through the full
Usage Page 0x07 table, applies the modifier bitmap, suppresses key repeat by diffing each
report's pressed-key set against the previous one, toggles caps lock, applies backspaces and
renders Ctrl/Alt/GUI chords as `<CTRL-c>`. In mouse mode it accumulates the signed dx/dy
deltas, keeps the points where a button is held, and prints an ASCII plot plus an optional
CSV and PNG. Mode is auto-detected from report length, and input can come from a hex file,
stdin, or straight out of a `.pcap` via `tshark`.

## Usage

```bash
# straight from the capture - tshark is called for you, usbhid.data used as fallback
python3 usb_hid.py --pcap usb.pcap
# only one device on the bus (find it with: tshark -r usb.pcap -T fields -e usb.device_address)
python3 usb_hid.py --pcap usb.pcap --device 3 --mode keyboard
# the classic two-step, if you prefer to keep the hex around
tshark -r usb.pcap -T fields -e usb.capdata | grep -v '^$' | tr -d ':' > keys.hex
python3 usb_hid.py keys.hex --mode keyboard
# keep the raw keystrokes: no backspace application, no <F1>/<ESC> markers
python3 usb_hid.py keys.hex --mode keyboard --raw --no-special
# mouse: ASCII art now, PNG and point CSV for later
python3 usb_hid.py --pcap tablet.pcap --mode mouse --width 160 --png draw.png --csv pts.csv
# a signature pad often draws with the right button or with any button held
python3 usb_hid.py mouse.hex --mode mouse --button any
# no input file needed - decodes built-in samples and asserts the result
python3 usb_hid.py --selftest
```

## Script

```python
#!/usr/bin/env python3
"""USB HID decoder: keyboard reports back to text, mouse reports back to a drawing.

Input is one hex report per line (colons, spaces and 0x prefixes tolerated) from a
file or stdin, or a capture via --pcap, in which case tshark is shelled out to for
usb.capdata (falling back to usbhid.data and usb.data_fragment).
Only the PNG output needs a third-party package (matplotlib); everything else is stdlib.
"""
from __future__ import annotations

import argparse, csv, re, shutil, subprocess, sys

HEXLINE = re.compile(r"^[0-9a-fA-F]+$")
BTN = {"left": 0x01, "right": 0x02, "middle": 0x04, "any": 0x07}

# --- HID Usage Page 0x07: usage id -> (unshifted, shifted) -------------------
KEYMAP: dict[int, tuple[str, str]] = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):          # 0x04-0x1D
    KEYMAP[0x04 + _i] = (_c, _c.upper())
for _i, (_lo, _hi) in enumerate(zip("1234567890", "!@#$%^&*()")):   # 0x1E-0x27
    KEYMAP[0x1E + _i] = (_lo, _hi)
KEYMAP.update({                                                  # 0x28-0x38
    0x28: ("\n", "\n"), 0x2B: ("\t", "\t"), 0x2C: (" ", " "), 0x2D: ("-", "_"),
    0x2E: ("=", "+"), 0x2F: ("[", "{"), 0x30: ("]", "}"), 0x31: ("\\", "|"),
    0x32: ("#", "~"), 0x33: (";", ":"), 0x34: ("'", '"'), 0x35: ("`", "~"),
    0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
})
KEYMAP.update({                                                  # 0x54-0x63 keypad
    0x54: ("/", "/"), 0x55: ("*", "*"), 0x56: ("-", "-"), 0x57: ("+", "+"),
    0x58: ("\n", "\n"), 0x59: ("1", "1"), 0x5A: ("2", "2"), 0x5B: ("3", "3"),
    0x5C: ("4", "4"), 0x5D: ("5", "5"), 0x5E: ("6", "6"), 0x5F: ("7", "7"),
    0x60: ("8", "8"), 0x61: ("9", "9"), 0x62: ("0", "0"), 0x63: (".", "."),
})
NAMED = {0x29: "<ESC>", 0x46: "<PRTSC>", 0x47: "<SCRLK>", 0x48: "<PAUSE>", 0x49: "<INS>",
         0x4A: "<HOME>", 0x4B: "<PGUP>", 0x4C: "<DEL>", 0x4D: "<END>", 0x4E: "<PGDN>",
         0x4F: "<RIGHT>", 0x50: "<LEFT>", 0x51: "<DOWN>", 0x52: "<UP>", 0x53: "<NUMLK>"}
for _i in range(12):                                             # 0x3A-0x45
    NAMED[0x3A + _i] = f"<F{_i + 1}>"

MOD_LCTRL, MOD_LSHIFT, MOD_LALT, MOD_LGUI = 0x01, 0x02, 0x04, 0x08
MOD_RCTRL, MOD_RSHIFT, MOD_RALT, MOD_RGUI = 0x10, 0x20, 0x40, 0x80
SHIFT, CTRL = MOD_LSHIFT | MOD_RSHIFT, MOD_LCTRL | MOD_RCTRL
ALT, GUI = MOD_LALT | MOD_RALT, MOD_LGUI | MOD_RGUI
BACKSPACE, CAPSLOCK = 0x2A, 0x39


def parse_reports(text: str) -> list[bytes]:
    """Hex lines -> bytes. Blank lines, colons, spaces and 0x prefixes are tolerated."""
    out = []
    for line in text.splitlines():
        clean = re.sub(r"(?i)^0x|[\s:,\-]", "", line.strip())
        if clean and not len(clean) % 2 and HEXLINE.match(clean):
            out.append(bytes.fromhex(clean))
    return out


def tshark_capdata(pcap: str, device: int | None = None) -> str:
    """Pull HID payload hex out of a capture, trying each field name in turn."""
    if shutil.which("tshark") is None:
        raise SystemExit("tshark not found on PATH - install wireshark/tshark, or dump the\n"
                         "hex yourself and pass it as a file argument instead of --pcap")
    base = ["tshark", "-r", pcap, "-T", "fields"]
    if device is not None:
        base += ["-Y", f"usb.device_address == {device}"]
    for field in ("usb.capdata", "usbhid.data", "usb.data_fragment"):
        proc = subprocess.run(base + ["-e", field], capture_output=True, text=True)
        rows = [r for r in proc.stdout.splitlines() if r.strip()]
        if rows:
            print(f"[+] {len(rows)} rows from {field}", file=sys.stderr)
            return "\n".join(rows)
    raise SystemExit("no usb.capdata / usbhid.data / usb.data_fragment in that capture")


def autodetect(reports: list[bytes]) -> str:
    """8- and 6-byte reports are keyboards; 3- and 4-byte reports are mice."""
    if not reports:
        return "keyboard"
    long_reports = sum(1 for r in reports if len(r) >= 6)
    return "keyboard" if long_reports * 2 >= len(reports) else "mouse"


# --- keyboard ---------------------------------------------------------------
def keys_of(rep: bytes) -> tuple[int, list[int]]:
    """Return (modifier, pressed usage ids) for a 4-, 6- or 8-byte boot report."""
    if len(rep) >= 6:                 # [mod][reserved][k1..k6] or [mod][reserved][k1..k4]
        return rep[0], [k for k in rep[2:8] if k]
    if len(rep) >= 3 and rep[1] == 0:  # [mod][reserved][k1..]
        return rep[0], [k for k in rep[2:] if k]
    return rep[0], [k for k in rep[1:] if k]    # [mod][k1..], no reserved byte


def decode_keyboard(reports: list[bytes], show_special: bool = True,
                    apply_backspace: bool = True) -> str:
    out: list[str] = []
    caps, previous = False, set()
    for rep in reports:
        if len(rep) < 3:
            continue
        mod, keys = keys_of(rep)
        shift, ctrl = bool(mod & SHIFT), bool(mod & CTRL)
        alt, gui = bool(mod & ALT), bool(mod & GUI)
        for code in keys:
            if code in previous:          # still held from the last report: not a new press
                continue
            if code == CAPSLOCK:
                caps = not caps
            elif code == BACKSPACE:
                if apply_backspace and out:
                    out.pop()
                elif show_special:
                    out.append("<BS>")
            elif code in KEYMAP:
                lo, hi = KEYMAP[code]
                ch = hi if shift else lo
                if caps and lo.isalpha():
                    ch = lo if shift else lo.upper()
                if ctrl and show_special:
                    out.append(f"<CTRL-{lo}>")
                elif alt and show_special:
                    out.append(f"<ALT-{lo}>")
                elif gui and show_special:
                    out.append(f"<GUI-{lo}>")
                else:
                    out.append(ch)
            elif code in NAMED and show_special:
                out.append(NAMED[code])
        previous = set(keys)
    return "".join(out)


# --- mouse ------------------------------------------------------------------
def s8(value: int) -> int:
    """Unsigned byte -> signed 8-bit delta."""
    return value - 256 if value > 127 else value


def walk(reports: list[bytes], button: int = 0x01) -> list[tuple[int, int, int, int]]:
    """Accumulate deltas; return (x, y, buttons, wheel) for every report while held."""
    x = y = 0
    points = []
    for rep in reports:
        if len(rep) < 3:
            continue
        buttons, dx, dy = rep[0], s8(rep[1]), s8(rep[2])
        wheel = s8(rep[3]) if len(rep) > 3 else 0
        x, y = x + dx, y + dy
        if buttons & button:
            points.append((x, y, buttons, wheel))
    return points


def render(points, width: int = 100, on: str = "#", off: str = " ") -> str:
    if not points:
        return "(no points - was any button held? try --button any)"
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    span_x, span_y = max(1, maxx - minx), max(1, maxy - miny)
    width = max(10, min(width, span_x + 1))
    height = max(5, int(width * (span_y / span_x) / 2))   # cells are ~2x taller than wide
    grid = [[off] * width for _ in range(height)]
    for px, py, _b, _w in points:
        grid[int((py - miny) / span_y * (height - 1))][int((px - minx) / span_x * (width - 1))] = on
    return (f"x {minx}..{maxx}  y {miny}..{maxy}  {len(points)} points  grid {width}x{height}\n"
            + "\n".join("".join(row) for row in grid))


def save_png(points, path: str) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping PNG:  pip install matplotlib", file=sys.stderr)
        return False
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.scatter([p[0] for p in points], [p[1] for p in points], s=2)
    ax.invert_yaxis()                     # screen Y grows downward
    ax.set_aspect("equal")
    ax.axis("off")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] wrote {path}", file=sys.stderr)
    return True


def save_csv(points, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["i", "x", "y", "buttons", "wheel"])
        for i, (x, y, buttons, wheel) in enumerate(points):
            writer.writerow([i, x, y, buttons, wheel])
    print(f"[+] wrote {path}", file=sys.stderr)


# --- selftest ---------------------------------------------------------------
KBD_SAMPLE = """
02000b0000000000   shift+h -> H
0000000000000000
00000c0000000000   i
0000000000000000
0000390000000000   caps lock on
0000000000000000
0000070000000000   d -> D (caps)
0000000000000000
00001b0000000000   x -> X (caps)
0000000000000000
00002a0000000000   backspace removes it
0000000000000000
0000390000000000   caps lock off
0000000000000000
02001e0000000000   shift+1 -> !
0000000000000000
0100060000000000   ctrl+c
0000000000000000
"""


def mouse_sample() -> list[bytes]:
    """A 20x10 rectangle drawn with the left button held, plus one wheel-only report."""
    reps = [bytes([0x01, 1, 0]) for _ in range(20)]
    reps += [bytes([0x01, 0, 1]) for _ in range(10)]
    reps += [bytes([0x01, 0xFF, 0]) for _ in range(20)]
    reps += [bytes([0x01, 0, 0xFF]) for _ in range(10)]
    reps.append(bytes([0x00, 0, 0, 0x01]))       # 4-byte wheel report, no button
    return reps


def selftest() -> int:
    kbd = parse_reports("\n".join(line.split()[0] for line in KBD_SAMPLE.split("\n") if line.strip()))
    assert len(kbd) == 18, len(kbd)
    text = decode_keyboard(kbd)
    assert text == "HiD!<CTRL-c>", repr(text)
    assert decode_keyboard(kbd, show_special=False) == "HiD!c", decode_keyboard(kbd, False)
    assert decode_keyboard(kbd, apply_backspace=False) == "HiDX<BS>!<CTRL-c>", "raw backspace"
    assert decode_keyboard([bytes([0, 0, 0x04, 0, 0, 0, 0, 0])] * 4) == "a", "key repeat"
    assert decode_keyboard([bytes([0, 0, 0x04, 0])]) == "a", "4-byte report"
    assert autodetect(kbd) == "keyboard" and autodetect(mouse_sample()) == "mouse"
    assert s8(0xFF) == -1 and s8(0x80) == -128 and s8(0x7F) == 127
    points = walk(mouse_sample())
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    assert len(points) == 60, len(points)
    assert (min(xs), max(xs), min(ys), max(ys)) == (0, 20, 0, 10), (min(xs), max(xs), min(ys), max(ys))
    assert "#" in render(points, width=30)
    print("selftest ok: keyboard ->", repr(text), "| mouse ->", len(points), "points")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode USB HID keyboard/mouse reports.")
    ap.add_argument("input", nargs="?", help="file of hex reports; omit to read stdin")
    ap.add_argument("--mode", choices=["keyboard", "mouse", "auto"], default="auto")
    ap.add_argument("--pcap", help="read reports from this capture via tshark")
    ap.add_argument("--device", type=int, help="with --pcap: keep one usb.device_address only")
    ap.add_argument("--button", choices=sorted(BTN), default="left", help="mouse: which button draws")
    ap.add_argument("--raw", action="store_true", help="keyboard: do not apply backspaces")
    ap.add_argument("--no-special", action="store_true", help="keyboard: drop <F1>/<ESC>/<CTRL-x>")
    ap.add_argument("--width", type=int, default=100, help="mouse: ASCII plot width")
    ap.add_argument("--png", help="mouse: also write a PNG (needs matplotlib)")
    ap.add_argument("--csv", help="mouse: write the accumulated points to this CSV")
    ap.add_argument("--selftest", action="store_true", help="decode built-in samples and assert")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    if args.pcap:
        text = tshark_capdata(args.pcap, args.device)
    elif args.input:
        with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    reports = parse_reports(text)
    if not reports:
        print("no hex reports found on input", file=sys.stderr)
        return 1
    mode = autodetect(reports) if args.mode == "auto" else args.mode
    print(f"[+] {len(reports)} reports, mode={mode}", file=sys.stderr)
    if mode == "keyboard":
        print(decode_keyboard(reports, not args.no_special, not args.raw), end="")
        print()
        return 0
    points = walk(reports, BTN[args.button])
    print(render(points, width=args.width))
    if args.csv:
        save_csv(points, args.csv)
    if args.png and points:
        save_png(points, args.png)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Notes

The two report layouts this decodes:

```text
keyboard (8 bytes) : [modifier][reserved][k1][k2][k3][k4][k5][k6]
keyboard (4 bytes) : [modifier][reserved][k1][k2]   <- boot variant, fewer slots
mouse    (3 bytes) : [buttons][dX signed][dY signed]
mouse    (4 bytes) : [buttons][dX][dY][wheel signed]
```

| Modifier bit | Value | Key | Modifier bit | Value | Key |
| --- | --- | --- | --- | --- | --- |
| 0 | 0x01 | Left Ctrl | 4 | 0x10 | Right Ctrl |
| 1 | 0x02 | Left Shift | 5 | 0x20 | Right Shift |
| 2 | 0x04 | Left Alt | 6 | 0x40 | Right Alt (AltGr) |
| 3 | 0x08 | Left GUI | 7 | 0x80 | Right GUI |

- Usage IDs: `0x04-0x1D` a-z, `0x1E-0x27` 1-9 then 0 (shifted `!@#$%^&*()`), `0x28` Enter,
  `0x29` Esc, `0x2A` Backspace, `0x2B` Tab, `0x2C` Space, `0x2D-0x38` punctuation,
  `0x39` CapsLock, `0x3A-0x45` F1-F12, `0x4F-0x52` arrows, `0x54-0x63` keypad.
- Key repeat: a held key is re-sent every report, so the decoder emits a character only when
  the usage ID was absent from the previous report. A genuine double letter still works,
  because the all-zero release report clears the set between the two presses.
- Caps lock is tracked as a toggle and applied to letters only, so `CAPS` + `shift+a` gives
  `a` and `shift+1` still gives `!` - exactly like a real keyboard.
- Mouse Y grows downward on screen. The ASCII plot draws it that way round; `save_png` calls
  `invert_yaxis()` so the PNG matches. If the drawing looks mirrored, that is the axis.
- Auto-detect is a simple length vote (>= 6 bytes means keyboard). Force it with `--mode`
  when a device sends 4-byte keyboard reports on the same bus as a mouse.

## Extending it

- **Non-US layouts**: usage IDs are positional, not characters. Clone `KEYMAP` into a second
  table (AZERTY, QWERTZ) and select with a new `--layout` flag when the decode reads as
  structured nonsense - word shapes are right, letters wrong.
- **Timing**: add `-e frame.time_relative` to the tshark call and zip the timestamps onto the
  reports; sub-10 ms gaps are a Rubber Ducky or `xdotool`, not a human.
- **Consumer-page keys**: media and browser keys live on Usage Page 0x0C with their own report
  IDs; add a table keyed by the report's first byte when `usbhid.data` rows are 2-3 bytes.
- **Mass storage on the same bus**: bulk transfers carry SCSI. Dump them with
  `tshark -r usb.pcap -Y 'usb.transfer_type==0x03' -T fields -e usb.capdata | tr -d ':\n' |
  xxd -r -p > usbms.bin` and carve that file instead.

## Troubleshooting

- `tshark not found on PATH` - install Wireshark's CLI (`brew install wireshark`,
  `apt install tshark`), or extract the hex on another box and pass the file positionally.
- Empty output, or "no hex reports found": the rows were blank. `tshark` prints one empty
  line per URB without data, so `grep -v '^$'` before writing the hex file.
- Rows come back as `usbhid.data` on newer Wireshark builds and `usb.capdata` on older ones -
  the script tries both plus `usb.data_fragment`, in that order, and says which one hit.
- Text decodes as gibberish with plausible word shapes: wrong keyboard layout, not a wrong
  decoder. Try the same usage IDs against an AZERTY or QWERTZ table.
- Two devices on one bus interleave into one usage-ID soup. Split them with `--device N`
  after listing addresses: `tshark -r usb.pcap -T fields -e usb.device_address | sort -u`.
- The mouse plot is a single dot: all deltas were zero because the device reports absolute
  coordinates (a tablet/digitiser, Usage Page 0x0D). Plot bytes 1-2 as absolute values
  instead of accumulating them.
