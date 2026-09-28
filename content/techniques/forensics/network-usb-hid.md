---
title: "USB HID - Decoding Keyboard and Mouse Traffic from a PCAP"
category: forensics
subcategory: network
type: technique
tags: [usb, usbhid, hid, keyboard, mouse, usbmon, capdata, tshark, wireshark, keystroke-recovery, scancode, keylogger, pcap, usb-mass-storage, scsi, dfir]
difficulty: medium
summary: "Turn usb.capdata hex from a USB capture back into the keystrokes that were typed, or the picture that was drawn with the mouse."
when_to_use:
  - "The protocol hierarchy shows usb, usbhid, or the link type is USB"
  - "tshark -T fields -e usb.capdata returns 8-byte hex rows"
  - "The challenge mentions a keylogger, a typed password, or a signature pad"
  - "A USB stick was plugged in and the file transfer is in the capture"
tools: [tshark, wireshark, usbmon, scapy, python3, matplotlib]
related: [network-pcap-triage, network-scapy-analysis, disk-windows-registry, network-covert-channels]
---

## TL;DR

A USB keyboard sends 8-byte interrupt reports: `[modifier][reserved][key1..key6]`. Extract them
with `tshark -T fields -e usb.capdata`, map each non-zero keycode through the HID usage table,
apply shift from the modifier byte, and you have the typed text. A mouse sends
`[buttons][dx][dy]` with signed deltas; accumulate them and plot the points where a button is
held to recover a drawing.

## Recognise it

- `capinfos cap.pcap` reports link type `USB_LINUX_MMAPPED` (220) or `USB_LINUX` (189), or
  `USBPcap` (249) on Windows.
- `tshark -r cap.pcap -q -z io,phs` shows `usb`, `usbhid`, `usbms`, `usbccid`.
- Hundreds of tiny packets, all between the same two "addresses" like `1.3.1` and `host`.
- `tshark -r cap.pcap -T fields -e usb.capdata | head` prints rows like `00:00:04:00:00:00:00:00`.

## Capturing (for reference / reproducing)

```sh
# linux: load the usbmon kernel module and find the bus number
modprobe usbmon
lsusb    # Bus 001 Device 003: ... -> capture on usbmon1
# capture everything on bus 1
tcpdump -i usbmon1 -w usb.pcap
# or with dumpcap/tshark directly
tshark -i usbmon1 -w usb.pcap
# usbmon0 is "all buses"
tcpdump -i usbmon0 -w usb_all.pcap
# windows: USBPcap installs a usbpcap interface Wireshark can select
```

## Isolating the HID stream

```sh
# interrupt transfers only - HID input reports are always interrupt IN
tshark -r usb.pcap -Y 'usb.transfer_type == 0x01'
# which devices are on the bus, and what are they?
tshark -r usb.pcap -Y 'usb.descriptor_type == 1' \
  -T fields -e usb.idVendor -e usb.idProduct -e usb.bcdDevice
# device class: 0x03 == HID; interface protocol 1 == keyboard, 2 == mouse
tshark -r usb.pcap -Y 'usb.bInterfaceClass == 3' \
  -T fields -e usb.device_address -e usb.bInterfaceProtocol | sort -u
# string descriptors often name the device outright
tshark -r usb.pcap -Y 'usb.descriptor_type == 3' -T fields -e usb.bString | sort -u
# narrow to one device and the IN direction (device -> host)
tshark -r usb.pcap -Y 'usb.device_address == 3 && usb.endpoint_address.direction == 1' \
  -T fields -e usb.capdata
# the field name changed across Wireshark versions - try all three
tshark -r usb.pcap -T fields -e usb.capdata   > caps.txt
tshark -r usb.pcap -T fields -e usbhid.data  >> caps.txt
tshark -r usb.pcap -T fields -e usb.data_fragment >> caps.txt
# drop empty lines and normalise the separators
grep -v '^$' caps.txt | tr -d ':' > keystrokes.hex
head keystrokes.hex
```

Sanity check: keyboard rows are 16 hex chars (8 bytes) and the second byte is almost always `00`.
Mouse rows are 6-8 hex chars (3-4 bytes). If you get 4-byte rows from a keyboard the capture is
using a boot-protocol variant with fewer key slots -- the decoder below handles both.

## The keyboard report

```
byte 0 : modifier bitmap
byte 1 : reserved (OEM, usually 0x00)
byte 2 : keycode 1     <- the one that matters in almost every CTF
byte 3 : keycode 2
byte 4 : keycode 3
byte 5 : keycode 4
byte 6 : keycode 5
byte 7 : keycode 6
```

Modifier bits:

| Bit | Value | Key |
| --- | --- | --- |
| 0 | 0x01 | Left Ctrl |
| 1 | 0x02 | Left Shift |
| 2 | 0x04 | Left Alt |
| 3 | 0x08 | Left GUI (Win/Cmd) |
| 4 | 0x10 | Right Ctrl |
| 5 | 0x20 | Right Shift |
| 6 | 0x40 | Right Alt (AltGr) |
| 7 | 0x80 | Right GUI |

Key usage IDs (HID Usage Page 0x07), the subset you need:

| Range / ID | Meaning |
| --- | --- |
| 0x04-0x1D | a b c d e f g h i j k l m n o p q r s t u v w x y z |
| 0x1E-0x26 | 1 2 3 4 5 6 7 8 9 |
| 0x27 | 0 |
| 0x28 | Enter |
| 0x29 | Escape |
| 0x2A | Backspace |
| 0x2B | Tab |
| 0x2C | Space |
| 0x2D | `-` (shift `_`) |
| 0x2E | `=` (shift `+`) |
| 0x2F | `[` (shift `{`) |
| 0x30 | `]` (shift `}`) |
| 0x31 | `\` (shift `\|`) |
| 0x32 | non-US `#`/`~` |
| 0x33 | `;` (shift `:`) |
| 0x34 | `'` (shift `"`) |
| 0x35 | `` ` `` (shift `~`) |
| 0x36 | `,` (shift `<`) |
| 0x37 | `.` (shift `>`) |
| 0x38 | `/` (shift `?`) |
| 0x39 | Caps Lock |
| 0x3A-0x45 | F1 - F12 |
| 0x46-0x4E | PrintScreen, ScrollLock, Pause, Insert, Home, PageUp, Delete, End, PageDown |
| 0x4F-0x52 | Right, Left, Down, Up arrows |
| 0x53 | Num Lock |
| 0x54-0x63 | Keypad `/ * - + Enter 1 2 3 4 5 6 7 8 9 0 .` |

Shifted digits on a US layout: `1!`, `2@`, `3#`, `4$`, `5%`, `6^`, `7&`, `8*`, `9(`, `0)`.

## The mouse report

The standard boot-protocol mouse report is 3 bytes (some devices send 4 with a wheel):

```
byte 0 : buttons bitmap (bit0 = left, bit1 = right, bit2 = middle)
byte 1 : dX, signed 8-bit
byte 2 : dY, signed 8-bit   (positive = DOWN on screen)
byte 3 : wheel, signed 8-bit (optional)
```

To recover a drawing: keep a running (x, y) position, add each delta, and record the position
whenever bit 0 of the buttons byte is set. Plot those points. The image is usually inverted
vertically compared to what you expect, because screen Y grows downward.

## USB mass storage in a capture

```sh
# bulk transfers carrying SCSI commands
tshark -r usb.pcap -Y 'usb.transfer_type == 0x03'
# the SCSI opcodes: 0x28 READ(10), 0x2A WRITE(10), 0x12 INQUIRY, 0x25 READ CAPACITY
tshark -r usb.pcap -Y scsi -T fields -e scsi.cdb.opcode -e scsi_sbc.rdwr10.lba
# dump every bulk data payload and carve it as if it were a disk image
tshark -r usb.pcap -Y 'usb.transfer_type == 0x03 && usb.capdata' \
  -T fields -e usb.capdata | tr -d ':\n' | xxd -r -p > usbms.bin
file usbms.bin && binwalk usbms.bin
foremost -t all -i usbms.bin -o usbms_carved
# if it is a filesystem image, mount it
mmls usbms.bin && fls -o 2048 -r usbms.bin
```

## Code

```python
#!/usr/bin/env python3
"""Decode USB HID keyboard capdata into the text that was typed.

Input: one hex report per line, as produced by
    tshark -r usb.pcap -T fields -e usb.capdata | grep -v '^$' | tr -d ':'
Colons, spaces and 0x prefixes are tolerated. 4-byte and 8-byte reports both work.

    python3 usb_kbd.py keystrokes.hex
    cat keystrokes.hex | python3 usb_kbd.py
    python3 usb_kbd.py --selftest
"""
from __future__ import annotations

import argparse
import re
import sys

# usage id -> (unshifted, shifted)
KEYMAP: dict[int, tuple[str, str]] = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    KEYMAP[0x04 + _i] = (_c, _c.upper())
for _i, (_lo, _hi) in enumerate(zip("1234567890", "!@#$%^&*()")):
    KEYMAP[0x1E + _i] = (_lo, _hi)
KEYMAP.update({
    0x28: ("\n", "\n"), 0x2B: ("\t", "\t"), 0x2C: (" ", " "),
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"), 0x30: ("]", "}"),
    0x31: ("\\", "|"), 0x32: ("#", "~"), 0x33: (";", ":"), 0x34: ("'", '"'),
    0x35: ("`", "~"), 0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"),
})
# keypad
KEYMAP.update({
    0x54: ("/", "/"), 0x55: ("*", "*"), 0x56: ("-", "-"), 0x57: ("+", "+"),
    0x58: ("\n", "\n"), 0x59: ("1", "1"), 0x5A: ("2", "2"), 0x5B: ("3", "3"),
    0x5C: ("4", "4"), 0x5D: ("5", "5"), 0x5E: ("6", "6"), 0x5F: ("7", "7"),
    0x60: ("8", "8"), 0x61: ("9", "9"), 0x62: ("0", "0"), 0x63: (".", "."),
})
NAMED = {
    0x29: "<ESC>", 0x39: "<CAPS>", 0x46: "<PRTSC>", 0x47: "<SCRLK>", 0x48: "<PAUSE>",
    0x49: "<INS>", 0x4A: "<HOME>", 0x4B: "<PGUP>", 0x4C: "<DEL>", 0x4D: "<END>",
    0x4E: "<PGDN>", 0x4F: "<RIGHT>", 0x50: "<LEFT>", 0x51: "<DOWN>", 0x52: "<UP>",
    0x53: "<NUMLK>",
}
for _i in range(12):
    NAMED[0x3A + _i] = f"<F{_i + 1}>"

MOD_LSHIFT, MOD_RSHIFT = 0x02, 0x20
MOD_LCTRL, MOD_RCTRL = 0x01, 0x10
MOD_LALT, MOD_RALT = 0x04, 0x40
BACKSPACE = 0x2A
CAPSLOCK = 0x39
HEXLINE = re.compile(r"^[0-9a-fA-F]+$")


def parse_reports(text: str) -> list[bytes]:
    reports: list[bytes] = []
    for line in text.splitlines():
        clean = re.sub(r"(?i)^0x|[\s:,\-]", "", line.strip())
        if not clean or not HEXLINE.match(clean) or len(clean) % 2:
            continue
        try:
            reports.append(bytes.fromhex(clean))
        except ValueError:
            continue
    return reports


def decode(reports: list[bytes], show_special: bool = True,
           apply_backspace: bool = True) -> str:
    out: list[str] = []
    caps = False
    previous: set[int] = set()
    for rep in reports:
        if len(rep) < 3:
            continue
        mod = rep[0]
        # boot keyboards put keycodes at offset 2; some 4-byte captures omit the
        # reserved byte, so fall back to offset 1 when byte 1 looks like a keycode
        if len(rep) >= 8:
            keys = [k for k in rep[2:8] if k]
        elif rep[1] == 0:
            keys = [k for k in rep[2:] if k]
        else:
            keys = [k for k in rep[1:] if k]
        current = set(keys)
        shift = bool(mod & (MOD_LSHIFT | MOD_RSHIFT))
        ctrl = bool(mod & (MOD_LCTRL | MOD_RCTRL))
        alt = bool(mod & (MOD_LALT | MOD_RALT))
        for code in keys:
            if code in previous:          # key held down, not a new press
                continue
            if code == CAPSLOCK:
                caps = not caps
                continue
            if code == BACKSPACE:
                if apply_backspace and out:
                    out.pop()
                elif show_special:
                    out.append("<BS>")
                continue
            if code in KEYMAP:
                lo, hi = KEYMAP[code]
                ch = hi if shift else lo
                if caps and lo.isalpha():
                    ch = ch.swapcase() if shift else lo.upper()
                if ctrl and show_special:
                    out.append(f"<CTRL-{lo}>")
                elif alt and show_special and lo.isalpha():
                    out.append(f"<ALT-{lo}>")
                else:
                    out.append(ch)
            elif code in NAMED and show_special:
                out.append(NAMED[code])
        previous = current
    return "".join(out)


def selftest() -> int:
    # types: F l a g Enter  with shift held for the F
    sample = [
        "02000900000000 00",   # shift + f  -> F
        "00000f0000000000",    # l
        "0000040000000000",    # a
        "0000050000000000",    # b   (will be removed by the backspace below)
        "00002a0000000000",    # backspace
        "000000000000000 0",   # release
        "0000110000000000",    # n
        "0000280000000000",    # enter
    ]
    reports = parse_reports("\n".join(sample))
    assert len(reports) == 8, reports
    text = decode(reports)
    assert text == "Flan\n", repr(text)
    # caps lock toggling
    caps_sample = ["0000390000000000", "0000040000000000", "0000390000000000",
                   "0000040000000000"]
    assert decode(parse_reports("\n".join(caps_sample))) == "Aa", \
        decode(parse_reports("\n".join(caps_sample)))
    print("self-test OK ->", repr(text))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("hexfile", nargs="?", help="file of hex reports; omit to read stdin")
    ap.add_argument("--raw", action="store_true", help="do not apply backspaces")
    ap.add_argument("--no-special", action="store_true", help="drop <ESC>/<F1>/arrow markers")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.hexfile:
        with open(args.hexfile, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    reports = parse_reports(text)
    if not reports:
        print("no hex reports found on input", file=sys.stderr)
        return 1
    print(decode(reports, show_special=not args.no_special,
                 apply_backspace=not args.raw), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
"""Decode USB HID mouse capdata into a drawing.

Input: one hex report per line (3 or 4 bytes), as produced by
    tshark -r usb.pcap -T fields -e usb.capdata | grep -v '^$' | tr -d ':'

    python3 usb_mouse.py mouse.hex --width 120
    python3 usb_mouse.py mouse.hex --png drawing.png
    python3 usb_mouse.py --selftest
"""
from __future__ import annotations

import argparse
import re
import sys

HEXLINE = re.compile(r"^[0-9a-fA-F]+$")
BTN_LEFT, BTN_RIGHT, BTN_MIDDLE = 0x01, 0x02, 0x04


def s8(value: int) -> int:
    """Interpret an unsigned byte as a signed 8-bit integer."""
    return value - 256 if value > 127 else value


def parse_reports(text: str) -> list[bytes]:
    out: list[bytes] = []
    for line in text.splitlines():
        clean = re.sub(r"(?i)^0x|[\s:,]", "", line.strip())
        if not clean or not HEXLINE.match(clean) or len(clean) % 2:
            continue
        try:
            out.append(bytes.fromhex(clean))
        except ValueError:
            continue
    return out


def walk(reports: list[bytes], button: int = BTN_LEFT) -> list[tuple[int, int]]:
    """Accumulate deltas; return the points visited while `button` was held."""
    x = y = 0
    points: list[tuple[int, int]] = []
    for rep in reports:
        if len(rep) < 3:
            continue
        buttons, dx, dy = rep[0], s8(rep[1]), s8(rep[2])
        x += dx
        y += dy
        if buttons & button:
            points.append((x, y))
    return points


def render(points: list[tuple[int, int]], width: int = 100,
           on: str = "#", off: str = " ") -> str:
    if not points:
        return "(no points - was any button held?)"
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)
    span_x = max(1, maxx - minx)
    span_y = max(1, maxy - miny)
    width = max(10, min(width, span_x + 1))
    # terminal cells are about twice as tall as wide
    height = max(5, int(width * (span_y / span_x) / 2)) if span_x else 10
    grid = [[off] * width for _ in range(height)]
    for px, py in points:
        cx = int((px - minx) / span_x * (width - 1))
        cy = int((py - miny) / span_y * (height - 1))
        grid[cy][cx] = on
    header = (f"x {minx}..{maxx}  y {miny}..{maxy}  "
              f"{len(points)} points  grid {width}x{height}")
    return header + "\n" + "\n".join("".join(row) for row in grid)


def save_png(points: list[tuple[int, int]], path: str) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping PNG (pip install matplotlib)",
              file=sys.stderr)
        return False
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.scatter(xs, ys, s=2)
    ax.invert_yaxis()          # screen Y grows downward
    ax.set_aspect("equal")
    ax.axis("off")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {path}", file=sys.stderr)
    return True


def selftest() -> int:
    # draw a 10x10 square with the left button held
    reports = []
    for _ in range(10):
        reports.append(bytes([BTN_LEFT, 1, 0]))
    for _ in range(10):
        reports.append(bytes([BTN_LEFT, 0, 1]))
    for _ in range(10):
        reports.append(bytes([BTN_LEFT, 0xFF, 0]))   # -1
    for _ in range(10):
        reports.append(bytes([BTN_LEFT, 0, 0xFF]))   # -1
    reports.append(bytes([0x00, 5, 5]))              # moved with no button: ignored
    pts = walk(reports)
    assert len(pts) == 40, len(pts)
    assert min(p[0] for p in pts) == 0 and max(p[0] for p in pts) == 10, pts[:5]
    assert s8(0xFF) == -1 and s8(0x7F) == 127 and s8(0x80) == -128
    art = render(pts, width=24)
    assert "#" in art
    print("self-test OK")
    print(art)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("hexfile", nargs="?", help="file of hex reports; omit to read stdin")
    ap.add_argument("--width", type=int, default=100)
    ap.add_argument("--button", choices=["left", "right", "middle", "any"], default="left")
    ap.add_argument("--png", help="also write a PNG here (needs matplotlib)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    mask = {"left": BTN_LEFT, "right": BTN_RIGHT, "middle": BTN_MIDDLE,
            "any": BTN_LEFT | BTN_RIGHT | BTN_MIDDLE}[args.button]
    if args.hexfile:
        with open(args.hexfile, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    reports = parse_reports(text)
    if not reports:
        print("no hex reports found on input", file=sys.stderr)
        return 1
    points = walk(reports, mask)
    print(render(points, width=args.width))
    if args.png and points:
        save_png(points, args.png)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **Key repeat**: while a key is held the device keeps sending the same report. The decoder above
  suppresses repeats by tracking the previous key set. If the flag has a genuine double letter,
  there will be an intervening all-zero release report -- the logic handles it.
- **Empty rows**: `tshark` emits a blank line for every packet without `usb.capdata`
  (the URB_SUBMIT half of each transfer). Always `grep -v '^$'`.
- **Wrong field name**: older Wireshark used `usb.capdata`, newer builds expose
  `usbhid.data` for HID-class interfaces. Grab both and concatenate.
- **Non-US layout**: the usage IDs are positional, not character-based. A German or French
  keyboard produces the same codes for different letters. If the decode is nonsense but
  structurally word-like, try another layout mapping.
- **Multiple devices** on one bus interleave. Filter by `usb.device_address` first.
- **Mouse Y is inverted** relative to a maths plot. If the drawing looks upside down, negate dY
  or invert the axis (the PNG path already does).
- **Wheel byte**: a 4-byte mouse report adds a wheel delta; ignore it for drawing.
- Some captures give the data as `usb.data_fragment` split over several packets; reassemble by
  concatenating in frame order before decoding.
- A capture of a **USB Rubber Ducky** looks exactly like a normal keyboard, just very fast --
  the inter-packet delta is the tell.

## Tools

`tshark`/`wireshark`, `usbmon` (Linux), `USBPcap` (Windows), `scapy`, `python3`,
`matplotlib` for plotting, `binwalk`/`foremost` for the mass-storage case.

## References

- USB HID Usage Tables, Usage Page 0x07 (Keyboard/Keypad) defines the usage IDs used above.
- USB HID specification, Appendix B, defines the boot-protocol keyboard and mouse report formats.
- `tshark -G fields | grep '^F\tusb'` lists every USB field your build exposes.
