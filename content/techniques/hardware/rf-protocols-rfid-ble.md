---
title: "Common RF Protocols - 433 MHz Remotes, RFID/NFC and Bluetooth LE"
category: hardware
subcategory: rf-protocols
type: technique
tags: [proxmark, rfid, nfc, mifare, mfoc, mfcuk, hardnested, em410x, hid-prox, ble, bluetooth-low-energy, gatt, gatttool, bleah, nrf-sniffer, ev1527, keeloq, flipper-zero]
difficulty: medium
summary: "Read, clone and attack the three RF families that actually show up in CTF: sub-GHz remotes, 125 kHz/13.56 MHz cards, and Bluetooth LE."
when_to_use:
  - "A challenge involves a badge, a key fob, or a BLE device"
  - "You have a Proxmark3, a PN532, an nRF sniffer or a Flipper Zero"
  - "You captured BLE traffic and need the characteristic that holds the flag"
tools: [proxmark3, mfoc, mfcuk, libnfc, bettercap, gatttool, bluetoothctl, wireshark, rtl_433]
related: [rf-sdr-analysis, rf-sdr-cheatsheet, logic-analyzer-decoding, mcu-reversing]
---

## TL;DR

Three families, three toolchains. **Sub-GHz (315/433/868/915 MHz)**: OOK/FSK remotes,
usually fixed-code -> `rtl_433` or a Flipper, then replay. **RFID/NFC**: 125 kHz
(EM410x, HID Prox - trivially cloneable) and 13.56 MHz (MIFARE Classic - broken by
`mfoc`/`mfcuk`/hardnested; MIFARE DESFire/NTAG - not). **BLE**: enumerate GATT services
and characteristics, read everything readable, and look for the flag in a custom
characteristic.

## Recognise it

- A `.sub` file (Flipper Zero), a `.dump`/`.mfd`/`.eml` (MIFARE dump), a `.pcap` with
  `btle` packets, or a `.bin` of 1 KB / 4 KB (MIFARE Classic card image).
- Challenge text mentioning a badge, a garage remote, a smart lock, a fitness tracker.
- A `nRF Connect` screenshot, or a UUID like `0000ffe1-0000-1000-8000-00805f9b34fb`.

## Theory

### Sub-GHz remotes

| Chip / protocol | Bits | Notes |
|---|---|---|
| EV1527 / PT2262 / HT12E | 24 (20 addr + 4 data) | fixed code, OOK PWM, trivially replayed |
| Princeton PT2240 | 24 | same family |
| KeeLoq | 66 | rolling code; replay fails, known cryptanalysis exists |
| Somfy RTS / Nice Flor-S | varies | rolling |
| Weather sensors (Oregon, LaCrosse, Acurite) | varies | `rtl_433` decodes hundreds |
| TPMS | 64-72 | FSK, `rtl_433 -R` has decoders |

Fixed code = capture once, replay forever. Rolling code = the counter increments;
a replayed frame is rejected.

### 125 kHz LF cards

- **EM410x / EM4100**: 64 bits, no security at all. 9 header bits, 10 rows of 4 data
  bits + parity, column parity, stop bit. Read it, write it to a T5577 blank, done.
- **HID Prox (26-bit Wiegand)**: facility code + card number, no crypto. Same story.
- **T5577 / T55x7**: the standard writable blank; it can emulate EM410x, HID, Indala.
- **Hitag2 / Hitag S**: has crypto, and known attacks.

### 13.56 MHz HF cards

| Card | Security | Attack |
|---|---|---|
| MIFARE Classic 1K/4K | CRYPTO1 (broken) | `mfoc` (needs 1 known key), `mfcuk` (needs none), hardnested (hardened cards) |
| MIFARE Ultralight | none / 32-bit password | read directly; brute the password |
| MIFARE Ultralight C | 3DES | needs the key |
| NTAG213/215/216 | none / password | read directly; often holds an NDEF URL |
| MIFARE DESFire EV1/2/3 | AES/3DES | not broken; look for a key elsewhere |
| iCLASS | 3DES + diversified keys | known key leaks for legacy |
| FeliCa | proprietary | rare in CTF |

MIFARE Classic 1K layout: 16 sectors x 4 blocks x 16 bytes. Block 0 of sector 0 is the
manufacturer block (UID + BCC). The last block of each sector is the sector trailer:
`KeyA(6) | AccessBits(4) | KeyB(6)`. Default keys to try first:
`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`, `000000000000`, `B0B1B2B3B4B5`,
`4D3A99C351DD`, `1A982C7E459A`, `AABBCCDDEEFF`.

### Bluetooth LE

- **Advertising** on channels 37/38/39; connections hop over 0-36.
- **GATT**: services contain characteristics; each characteristic has a UUID, a value,
  and properties (`read`, `write`, `write-without-response`, `notify`, `indicate`).
- 16-bit UUIDs are standard (`0x180F` battery, `0x2A19` battery level);
  128-bit UUIDs are vendor-defined and are where CTF flags live.
- **Pairing/bonding**: "Just Works" gives no MITM protection; legacy pairing keys can be
  recovered from a capture of the pairing exchange (crackle).
- Sniffing a connection requires following the hop sequence - an nRF52 sniffer,
  Ubertooth One, or a Sniffle-flashed dongle does this.

## Attack

**Sub-GHz**: capture (see `rf-sdr-analysis`) -> `rtl_433 -A` -> identify -> replay or
synthesise a modified frame.

**LF card**: `lf search` on a Proxmark -> `lf em 410x reader` -> clone to T5577.

**HF card**: `hf search` -> `hf mf chk` default keys -> `hf mf autopwn` (or
`mfoc`/`mfcuk`) -> dump -> read the data blocks -> write a modified dump to a magic card.

**BLE**: scan -> connect -> enumerate GATT -> read every readable characteristic ->
subscribe to notifications -> fuzz writable ones.

## Code

### Proxmark3

```bash
pm3 -p /dev/ttyACM0                 # or: proxmark3 /dev/ttyACM0
```

```text
# --- general ---
hw status
hw version
hw tune                             # antenna tuning: check LF and HF voltages

# --- 125 kHz LF ---
lf search                           # identify any LF tag in the field
lf read                             # raw capture
lf em 410x reader                   # read an EM410x id
lf em 410x clone --id 1234567890    # write it to a T5577 blank
lf em 410x sim --id 1234567890      # emulate it from the proxmark
lf hid reader                       # HID Prox
lf hid clone -r 2004263f88
lf hid sim -r 2004263f88
lf t55xx detect
lf t55xx dump
lf t55xx wipe                       # reset a blank you messed up
lf indala reader
lf hitag2 reader

# --- 13.56 MHz HF ---
hf search                           # identify
hf 14a info                         # ATQA/SAK/UID, tells you the card type
hf 14a reader
hf mf chk --1k -f mfc_default_keys.dic     # try a key dictionary
hf mf fchk --1k                            # fast check of built-in defaults
hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF   # nested attack with one known key
hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta   # hardened cards
hf mf darkside                             # recover a key with no key at all
hf mf autopwn                              # chains chk -> nested -> hardnested -> dump
hf mf dump                                 # writes dumpdata.bin / .eml / .json
hf mf rdbl --blk 4 -a -k FFFFFFFFFFFF      # read one block
hf mf wrbl --blk 4 -a -k FFFFFFFFFFFF -d 00112233445566778899aabbccddeeff
hf mf restore --1k                         # write a dump back to a card
hf mf cload -f dump.eml                    # load onto a magic (gen1a) card
hf mf csetuid --uid 11223344               # change the uid of a magic card
hf mf sim --1k -u 11223344                 # emulate the card from the proxmark
hf mfu info                                # ultralight / ntag
hf mfu dump -k FFFFFFFF
hf mfdes info                              # desfire
hf 15 info                                 # iso15693
hf iclass info

# --- sniffing ---
hf 14a sniff                        # capture reader <-> card traffic
hf list 14a                         # decode the last trace
lf sniff
data plot                           # look at the raw waveform
```

### libnfc / mfoc / mfcuk (no Proxmark)

```bash
# with a PN532 (acr122u, elechouse board, etc.)
nfc-list
nfc-poll
nfc-mfclassic r a dump.mfd keys.mfd        # read with known keys
nfc-mfclassic w a new.mfd dump.mfd         # write
nfc-mfultralight r ultra.dump

# mfoc: needs at least one known key on the card
mfoc -O dump.mfd
mfoc -k FFFFFFFFFFFF -k A0A1A2A3A4A5 -O dump.mfd
mfoc-hardnested -O dump.mfd                # for hardened classics

# mfcuk: darkside attack, needs no key (slow)
mfcuk -C -R 0:A -v 2

# inspect a dump
xxd -g 1 -c 16 dump.mfd | head -20
# block 0 = UID; every 4th block (3,7,11,...) is a sector trailer:
#   bytes 0-5 KeyA, 6-9 access bits, 10-15 KeyB
xxd -g 1 -c 16 dump.mfd | awk 'NR%4==0'
strings -n 4 dump.mfd
```

### MIFARE Classic dump parser

```python
#!/usr/bin/env python3
"""mfc_parse.py - parse a MIFARE Classic 1K/4K dump into sectors, keys and data.

Usage:
  python3 mfc_parse.py dump.mfd
  python3 mfc_parse.py dump.mfd --strings
"""
from __future__ import annotations

import sys

BLOCK = 16
DEFAULT_KEYS = [
    "ffffffffffff", "a0a1a2a3a4a5", "d3f7d3f7d3f7", "000000000000",
    "b0b1b2b3b4b5", "4d3a99c351dd", "1a982c7e459a", "aabbccddeeff",
    "714c5c886e97", "587ee5f9350f", "a0478cc39091", "533cb6c723f6",
]


def sector_of(block: int) -> int:
    return block // 4 if block < 128 else 32 + (block - 128) // 16


def is_trailer(block: int) -> bool:
    if block < 128:
        return block % 4 == 3
    return (block - 128) % 16 == 15


def parse(data: bytes) -> dict:
    n_blocks = len(data) // BLOCK
    info: dict = {"size": len(data), "blocks": n_blocks, "sectors": {}, "keys": []}
    if n_blocks >= 4:
        uid = data[0:4]
        bcc = data[4]
        info["uid"] = uid.hex()
        info["bcc_ok"] = (uid[0] ^ uid[1] ^ uid[2] ^ uid[3]) == bcc
        info["sak"] = data[5]
        info["atqa"] = data[6:8].hex()

    for b in range(n_blocks):
        blk = data[b * BLOCK:(b + 1) * BLOCK]
        sec = sector_of(b)
        info["sectors"].setdefault(sec, {"data": [], "keya": None, "keyb": None,
                                         "access": None})
        if is_trailer(b):
            keya = blk[0:6].hex()
            access = blk[6:10].hex()
            keyb = blk[10:16].hex()
            info["sectors"][sec]["keya"] = keya
            info["sectors"][sec]["keyb"] = keyb
            info["sectors"][sec]["access"] = access
            info["keys"].extend([keya, keyb])
        else:
            info["sectors"][sec]["data"].append((b, blk))
    return info


def printable(blk: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in blk)


def report(path: str, show_strings: bool) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    info = parse(data)
    kind = {1024: "MIFARE Classic 1K", 4096: "MIFARE Classic 4K",
            320: "MIFARE Mini"}.get(info["size"], f"{info['size']} bytes")
    print(f"== {path}: {kind}, {info['blocks']} blocks")
    if "uid" in info:
        print(f"UID  : {info['uid']}  BCC {'ok' if info['bcc_ok'] else 'BAD'}")
        print(f"SAK  : 0x{info['sak']:02x}   ATQA: {info['atqa']}")

    for sec in sorted(info["sectors"]):
        s = info["sectors"][sec]
        ka, kb = s["keya"], s["keyb"]
        note = []
        if ka in DEFAULT_KEYS:
            note.append("KeyA is a DEFAULT key")
        if kb in DEFAULT_KEYS:
            note.append("KeyB is a DEFAULT key")
        if ka == "000000000000":
            note.append("KeyA not recovered (all zeros)")
        print(f"\n-- sector {sec}  KeyA={ka} KeyB={kb} access={s['access']} "
              f"{'  [' + '; '.join(note) + ']' if note else ''}")
        for bnum, blk in s["data"]:
            print(f"   blk {bnum:>3}: {blk.hex()}  |{printable(blk)}|")

    if show_strings:
        print("\n-- printable runs --")
        run = bytearray()
        for c in data:
            if 32 <= c < 127:
                run.append(c)
            else:
                if len(run) >= 4:
                    print("   " + run.decode())
                run = bytearray()
        if len(run) >= 4:
            print("   " + run.decode())

    uniq = sorted(set(info["keys"]))
    print(f"\n{len(uniq)} unique keys found:")
    for k in uniq:
        print(f"   {k}{'   (default)' if k in DEFAULT_KEYS else ''}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    report(argv[1], "--strings" in argv)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        import os
        import tempfile
        uid = bytes([0x11, 0x22, 0x33, 0x44])
        bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
        blocks = []
        blocks.append(uid + bytes([bcc, 0x08, 0x04, 0x00]) + b"\x00" * 8)
        blocks.append(b"flag{rfid_dump}\x00")
        blocks.append(b"\x00" * 16)
        blocks.append(bytes.fromhex("ffffffffffff") + bytes.fromhex("ff078069") +
                      bytes.fromhex("ffffffffffff"))
        for s in range(1, 16):
            for b in range(3):
                blocks.append(bytes([s]) * 16)
            blocks.append(bytes.fromhex("a0a1a2a3a4a5") + bytes.fromhex("ff078069") +
                          bytes.fromhex("b0b1b2b3b4b5"))
        dump = b"".join(blocks)
        assert len(dump) == 1024, len(dump)
        info = parse(dump)
        assert info["uid"] == "11223344", info["uid"]
        assert info["bcc_ok"], "bcc check failed"
        assert info["sectors"][0]["keya"] == "ffffffffffff"
        assert info["sectors"][1]["keya"] == "a0a1a2a3a4a5"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.mfd")
            with open(p, "wb") as fh:
                fh.write(dump)
            report(p, True)
        print("selftest ok")
    else:
        sys.exit(main(sys.argv))
```

### Bluetooth LE

```bash
# --- scanning ---
sudo hciconfig hci0 up
sudo hcitool lescan
sudo hcitool lescan --duplicates
bluetoothctl
#   scan on
#   devices
#   info AA:BB:CC:DD:EE:FF
#   connect AA:BB:CC:DD:EE:FF
#   menu gatt
#   list-attributes
#   select-attribute /org/bluez/hci0/dev_.../service0010/char0011
#   read
#   write 0x41 0x42 0x43
#   notify on

# --- gatttool (deprecated but still the fastest) ---
sudo gatttool -b AA:BB:CC:DD:EE:FF -I
#   connect
#   primary                      # list services
#   characteristics              # list characteristics with handles
#   char-desc                    # descriptors
#   char-read-hnd 0x0025
#   char-write-req 0x0025 414243
#   char-write-cmd 0x0025 01

sudo gatttool -b AA:BB:CC:DD:EE:FF --primary
sudo gatttool -b AA:BB:CC:DD:EE:FF --characteristics
sudo gatttool -b AA:BB:CC:DD:EE:FF --char-read --handle=0x0025
sudo gatttool -b AA:BB:CC:DD:EE:FF --char-write-req --handle=0x0025 --value=deadbeef
sudo gatttool -b AA:BB:CC:DD:EE:FF --listen --char-read --handle=0x0025

# --- bettercap ---
sudo bettercap
#   ble.recon on
#   ble.show
#   ble.enum AA:BB:CC:DD:EE:FF
#   ble.write AA:BB:CC:DD:EE:FF ff01 4142

# --- sniffing ---
# nRF52840 dongle with the nRF Sniffer firmware -> wireshark extcap interface
sudo wireshark -i nRF Sniffer for Bluetooth LE
# ubertooth
ubertooth-btle -f -c capture.pcap
ubertooth-btle -f -t AA:BB:CC:DD:EE:FF
# sniffle (cc1352 dongle)
python3 sniff_receiver.py -s /dev/ttyUSB0 -o capture.pcap -a

# analyse
tshark -r capture.pcap -Y 'btatt' -T fields -e btatt.handle -e btatt.value
tshark -r capture.pcap -Y 'btle.advertising_header' -T fields -e btcommon.eir_ad.entry.device_name
wireshark capture.pcap   # filter: btatt || btle

# crack legacy pairing from a capture of the pairing exchange
crackle -i capture.pcap -o decrypted.pcap
```

### Python BLE enumeration

```python
#!/usr/bin/env python3
"""ble_enum.py - scan for BLE devices, or connect and dump every readable characteristic.

Requires `bleak` (cross platform).

Usage:
  python3 ble_enum.py                              # scan for 8 seconds
  python3 ble_enum.py AA:BB:CC:DD:EE:FF            # enumerate GATT
"""
from __future__ import annotations

import asyncio
import sys


async def scan(seconds: float = 8.0) -> None:
    from bleak import BleakScanner  # type: ignore

    for d in await BleakScanner.discover(timeout=seconds):
        print(f"{d.address}  rssi={getattr(d, 'rssi', '?'):>4}  {d.name or '(no name)'}")
        md = getattr(d, "metadata", {}) or {}
        for uuid in md.get("uuids", []) or []:
            print(f"    service {uuid}")
        for cid, blob in (md.get("manufacturer_data", {}) or {}).items():
            print(f"    manufacturer 0x{cid:04x}: {bytes(blob).hex()}")


async def enumerate_device(addr: str) -> None:
    from bleak import BleakClient  # type: ignore

    async with BleakClient(addr) as client:
        print(f"connected: {client.is_connected}")
        for service in client.services:
            print(f"\nservice {service.uuid}  {service.description}")
            for ch in service.characteristics:
                print(f"  char {ch.uuid}  handle=0x{ch.handle:04x} "
                      f"[{','.join(ch.properties)}]")
                if "read" not in ch.properties:
                    continue
                try:
                    val = await client.read_gatt_char(ch.uuid)
                except Exception as exc:          # noqa: BLE001 - bleak raises broadly
                    print(f"       read failed: {exc}")
                    continue
                text = "".join(chr(b) if 32 <= b < 127 else "." for b in val)
                print(f"       value: {val.hex()}  |{text}|")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(enumerate_device(sys.argv[1]))
    else:
        asyncio.run(scan())
```

## Variants & pitfalls

- **Replaying a rolling code does nothing.** Check whether two captures of the same
  button differ; if they do, it is rolling and replay is out.
- **MIFARE Classic "hardened"** (EV1, Plus in SL1) defeats `mfoc`/darkside; you need
  hardnested, which needs one known key. Try the default dictionary first - CTF cards
  usually leave one sector default.
- **A dump of all `00` keys** means those sectors were never cracked; do not assume the
  data is real.
- **Magic cards**: gen1a accepts the backdoor command (`hf mf csetuid`), gen2 accepts a
  normal write to block 0, gen3/gen4 have their own command sets. Writing a UID to a
  normal card is impossible.
- **BLE connect fails** - the device may only accept one connection; kill the phone app
  first. Or it uses a random resolvable address that rotates.
- **Sniffing BLE needs the connection start** - if you miss the `CONNECT_IND` you cannot
  follow the hop sequence. Restart the device while sniffing.

## Tools

- `Proxmark3` (RDV4/Easy) with the Iceman firmware - the reference RFID tool.
- `PN532` boards + `libnfc` (`nfc-list`, `nfc-mfclassic`), `mfoc`, `mfcuk`,
  `mfoc-hardnested`, `miLazyCracker`.
- `Flipper Zero` - sub-GHz, LF and HF in one device, `.sub`/`.nfc` file formats.
- `bluetoothctl`, `gatttool`, `bettercap`, `bleak` (Python), `nRF Connect` (mobile).
- `Ubertooth One`, nRF52840 dongle + nRF Sniffer, `Sniffle` - BLE capture.
- `crackle` - legacy BLE pairing key recovery; `wireshark`/`tshark` for analysis.

## References

- Proxmark3 Iceman firmware documentation and command reference.
- libnfc and mfoc project documentation.
- Bluetooth Core Specification: GAP advertising and GATT attribute structure.
- Nordic Semiconductor nRF Sniffer for Bluetooth LE user guide.
