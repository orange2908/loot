---
title: "Wireless Forensics - WPA Handshakes, Deauth, WEP and Bluetooth"
category: forensics
subcategory: network
type: technique
tags: [wifi, 802-11, wpa, wpa2, eapol, four-way-handshake, pmkid, aircrack-ng, hashcat, hcxpcapngtool, airdecap-ng, deauth, wep, evil-twin, radiotap, bluetooth, btle, btsnoop, scapy, dfir]
difficulty: medium
summary: "Find the EAPOL handshake in a capture, crack the PSK, decrypt the traffic, and spot deauth or evil-twin activity."
when_to_use:
  - "The capture's link type is 802.11 or radiotap and tshark shows wlan frames"
  - "The challenge gives a .cap plus a wordlist"
  - "You need the WiFi password, or the plaintext traffic inside an encrypted WLAN"
  - "You are handed btsnoop_hci.log from an Android phone"
tools: [aircrack-ng, airdecap-ng, hcxtools, hashcat, john, cowpatty, tshark, wireshark, scapy, btmon]
related: [network-pcap-triage, network-extract-files-creds, network-tls-decryption, network-c2-analysis]
---

## TL;DR

You need a **beacon** (for the SSID) plus **EAPOL messages 1+2 or 2+3** (for the nonces and the
MIC), or a single **message 1 carrying a PMKID**. Convert with `hcxpcapngtool`, crack with
`hashcat -m 22000`, then decrypt the capture with `airdecap-ng` and analyse it as an ordinary
pcap.

## Recognise it

- `capinfos cap.pcap` reports link type `IEEE802_11` (105) or `IEEE802_11_RADIOTAP` (127).
- `tshark -r cap.pcap -q -z io,phs` shows `radiotap`, `wlan`, `wlan_mgt`, `eapol`, `llc`.
- The file is a `.cap` produced by `airodump-ng` rather than a `.pcap`.
- Wireshark shows `Beacon frame`, `Probe Request`, `Deauthentication`, `Key (Message 1 of 4)`.

## 802.11 frame map

`wlan.fc.type_subtype` is the field you filter on:

| Value | Frame | Why you care |
| --- | --- | --- |
| 0x00 | Association Request | Client's supported rates and SSID |
| 0x01 | Association Response | Status code, AID |
| 0x04 | Probe Request | Reveals SSIDs the client has connected to before |
| 0x05 | Probe Response | Reveals a hidden SSID |
| 0x08 | Beacon | SSID, BSSID, channel, encryption suite |
| 0x0A | Disassociation | Often part of a deauth attack |
| 0x0B | Authentication | Open vs shared-key |
| 0x0C | Deauthentication | The attack itself; reason code matters |
| 0x1B | RTS | Control |
| 0x1C | CTS | Control |
| 0x20 | Data | The payload (encrypted unless open) |
| 0x28 | QoS Data | Modern data frames |

```sh
# inventory every AP seen, with SSID and channel
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x08' \
  -T fields -e wlan.bssid -e wlan_radio.channel -e wlan.ssid | sort -u
# older field name for the SSID
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.bssid -e wlan_mgt.ssid | sort -u
# every client that probed, and what it asked for
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x04' -T fields -e wlan.sa -e wlan.ssid | sort -u
# signal strength and frequency from the radiotap header
tshark -r wifi.cap -T fields -e radiotap.channel.freq -e radiotap.dbm_antsignal -e wlan.sa | head
# what encryption does the AP advertise? RSN = WPA2/3, WPA IE = WPA1, neither = open or WEP
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x08' \
  -T fields -e wlan.ssid -e wlan.rsn.akms.type -e wlan.rsn.pcs.type | sort -u
# airodump-ng can summarise an existing capture too
airodump-ng -r wifi.cap
```

## The four-way handshake

```sh
# every EAPOL frame with its message number
tshark -r wifi.cap -Y eapol \
  -T fields -e frame.number -e wlan.sa -e wlan.da -e eapol.keydes.msgnr -e eapol.type
# group by BSSID/station to see which pairs completed a handshake
tshark -r wifi.cap -Y eapol -T fields -e wlan.bssid -e wlan.sa -e eapol.keydes.msgnr \
  | sort | uniq -c
# the nonces and the MIC (what the cracker actually needs)
tshark -r wifi.cap -Y eapol -T fields -e eapol.keydes.nonce -e eapol.keydes.mic
# PMKID lives in the RSN key data of message 1 - a single frame is enough to crack
tshark -r wifi.cap -Y 'eapol.keydes.msgnr == 1' -T fields -e wlan.bssid -e eapol.keydes.data
# how aircrack sees it
aircrack-ng wifi.cap
# strip everything except the beacons and handshakes (much smaller file)
wpaclean clean.cap wifi.cap
```

**What you need:** messages 1 and 2 give you the ANonce and the SNonce plus the MIC over message
2. Messages 2 and 3 work too. Message 1 alone works **only** if it contains a PMKID. You also need
the SSID string, which comes from a beacon or a probe/association response, because the PSK is
salted with it.

## Cracking

```sh
# the modern path: hcxpcapngtool converts to the hashcat 22000 format
hcxpcapngtool -o hash.hc22000 -E wordlist_from_capture.txt wifi.pcapng
# it works on .cap too
hcxpcapngtool -o hash.hc22000 wifi.cap
# what is in the hash file: 01 lines are PMKID, 02 lines are EAPOL MIC
cut -d'*' -f1,2 hash.hc22000 | sort | uniq -c
# crack (mode 22000 covers both PMKID and EAPOL since hashcat 6)
hashcat -m 22000 hash.hc22000 rockyou.txt
# with a rule set
hashcat -m 22000 -r /usr/share/hashcat/rules/best64.rule hash.hc22000 rockyou.txt
# mask attack for a known pattern, e.g. 8 digits
hashcat -m 22000 -a 3 hash.hc22000 '?d?d?d?d?d?d?d?d'
# legacy modes, still seen in older writeups
hashcat -m 2500 handshake.hccapx rockyou.txt    # WPA-EAPOL-PBKDF2 (old hccapx)
hashcat -m 16800 pmkid.txt rockyou.txt          # PMKID only (old format)
# aircrack-ng directly against the capture
aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:FF wifi.cap
# aircrack with a specific essid when the beacon is missing
aircrack-ng -w rockyou.txt -e 'CorpWiFi' wifi.cap
# cowpatty, including with a precomputed rainbow table
cowpatty -r wifi.cap -f rockyou.txt -s 'CorpWiFi'
genpmk -f rockyou.txt -d pmk.db -s 'CorpWiFi'
cowpatty -r wifi.cap -d pmk.db -s 'CorpWiFi'
# john the ripper
wpapcap2john wifi.cap > wpa.john
john --wordlist=rockyou.txt --format=wpapsk wpa.john
```

## Decrypting the traffic

```sh
# produce a decrypted pcap - this is usually the actual objective
airdecap-ng -e 'CorpWiFi' -p 'Passw0rd123' wifi.cap
# writes wifi-dec.cap; analyse it like any other capture
tshark -r wifi-dec.cap -q -z io,phs
# WEP with a known hex key
airdecap-ng -w 1A:2B:3C:4D:5E wifi.cap
# open network: just strip the 802.11 headers
airdecap-ng -b AA:BB:CC:DD:EE:FF wifi.cap
# decrypt inside tshark instead, no new file
tshark -r wifi.cap -o wlan.enable_decryption:TRUE \
  -o 'uat:80211_keys:"wpa-pwd","Passw0rd123:CorpWiFi"' -Y http
# with a raw PSK (64 hex chars) instead of the passphrase
tshark -r wifi.cap -o wlan.enable_decryption:TRUE \
  -o 'uat:80211_keys:"wpa-psk","0123456789abcdef...64hex"' -Y http
# WEP key in tshark
tshark -r wifi.cap -o wlan.enable_decryption:TRUE \
  -o 'uat:80211_keys:"wep","1A:2B:3C:4D:5E"'
```

GUI: *Preferences > Protocols > IEEE 802.11 > Enable decryption* + *Decryption Keys > Edit*,
key type `wpa-pwd` with the value `password:SSID`, or `wpa-psk` with the 256-bit PMK hex.

Remember: decryption only works for **sessions whose handshake is in the capture**. A client that
associated before the capture started stays encrypted even with the right password.

## WEP

WEP uses RC4 with a 24-bit IV prepended to the key. IVs repeat, and the first bytes of every
802.11 payload are a known LLC/SNAP header, which gives known keystream. Enough IVs (tens of
thousands for the PTW attack) recover the key regardless of its length.

```sh
# how many unique IVs do we have?
tshark -r wep.cap -Y 'wlan.wep.iv' -T fields -e wlan.wep.iv | sort -u | wc -l
# PTW attack (default in modern aircrack), needs ~20k-80k data frames
aircrack-ng -z wep.cap
# classic KoreK attacks, needs more IVs but works where PTW does not
aircrack-ng -K wep.cap
# force the key length
aircrack-ng -n 64 wep.cap      # 40-bit key
aircrack-ng -n 128 wep.cap     # 104-bit key
# once cracked, decrypt
airdecap-ng -w AABBCCDDEE wep.cap
```

## Attack detection

```sh
# deauth storm: count deauth frames per BSSID
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x0c' \
  -T fields -e wlan.bssid -e wlan.da -e wlan.fixed.reason_code | sort | uniq -c | sort -rn
# reason codes: 1 unspecified, 3 leaving, 4 inactivity, 6/7 class2/class3 frame from
# nonassociated station - 1 and 7 are the aireplay-ng defaults
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x0c' -T fields -e wlan.fixed.reason_code \
  | sort | uniq -c
# deauth timing: a flood is dozens per second
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x0c' -T fields -e frame.time_relative | head -40
# evil twin: the same SSID advertised by two different BSSIDs
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.ssid -e wlan.bssid \
  | sort -u | awk '{print $1}' | uniq -d
# a BSSID whose OUI does not match the others in the same SSID is a clone
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x08' -T fields -e wlan.ssid -e wlan.bssid | sort -u
# karma / probe-response flood: one BSSID answering every probe
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x05' -T fields -e wlan.sa -e wlan.ssid \
  | sort | uniq -c | sort -rn | head
# WPS enabled (pixie-dust / PIN brute-force target)
tshark -r wifi.cap -Y 'wlan.wfa.ie.wps.version2' -T fields -e wlan.bssid -e wlan.ssid | sort -u
# hidden SSID recovered from an association or probe response
tshark -r wifi.cap -Y 'wlan.fc.type_subtype in {0x00 0x05}' -T fields -e wlan.bssid -e wlan.ssid \
  | grep -v '^\S*\s*$' | sort -u
# clients associated to each AP
tshark -r wifi.cap -Y 'wlan.fc.type_subtype == 0x20 || wlan.fc.type_subtype == 0x28' \
  -T fields -e wlan.bssid -e wlan.sa -e wlan.da | sort -u | head -40
```

## Bluetooth

```sh
# Android saves an HCI snoop log that Wireshark opens directly
adb pull /sdcard/btsnoop_hci.log
tshark -r btsnoop_hci.log -q -z io,phs
# the useful display filters
tshark -r bt.pcap -Y btle          # Bluetooth Low Energy link layer
tshark -r bt.pcap -Y bthci_cmd     # HCI commands from the host
tshark -r bt.pcap -Y bthci_evt     # HCI events from the controller
tshark -r bt.pcap -Y bthci_acl     # ACL data
tshark -r bt.pcap -Y btl2cap       # L2CAP
tshark -r bt.pcap -Y btrfcomm      # RFCOMM (serial over BT, classic)
tshark -r bt.pcap -Y btatt         # GATT attribute protocol (BLE app data)
tshark -r bt.pcap -Y btsmp         # pairing / security manager
# BLE advertising: who is nearby and what do they advertise
tshark -r bt.pcap -Y btle.advertising_header -T fields \
  -e btle.advertising_address -e btcommon.eir_ad.entry.device_name | sort -u
# the actual application data in BLE is in btatt.value
tshark -r bt.pcap -Y 'btatt.opcode' -T fields -e btatt.handle -e btatt.value \
  | tr -d ':' | head -40
# reassemble a GATT characteristic's writes into a byte stream
tshark -r bt.pcap -Y 'btatt.opcode == 0x52 || btatt.opcode == 0x12' \
  -T fields -e btatt.value | tr -d ':\n' | xxd -r -p > gatt.bin
# classic BT device names and addresses
tshark -r bt.pcap -Y 'bthci_evt.bd_addr' -T fields -e bthci_evt.bd_addr -e bthci_evt.remote_name
# live capture on Linux
btmon -w bt.pcap
hcidump -w bt.pcap
```

## Code

```python
#!/usr/bin/env python3
"""Inventory a wireless capture: APs, clients, deauths and EAPOL handshake status.

    pip install scapy
    python3 wifi_inventory.py wifi.cap
    python3 wifi_inventory.py --selftest
"""
from __future__ import annotations

import argparse
import collections
import sys

REASON_CODES = {
    1: "unspecified", 2: "prior auth invalid", 3: "station leaving", 4: "inactivity",
    5: "AP out of resources", 6: "class-2 frame from non-authed station",
    7: "class-3 frame from non-assoc station", 8: "station leaving BSS",
    9: "not authenticated", 15: "4-way handshake timeout",
}


def load_scapy():
    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
                                        Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq,
                                        Dot11Disas)  # type: ignore
        from scapy.layers.eap import EAPOL  # type: ignore
        return {
            "PcapReader": PcapReader, "Dot11": Dot11, "Dot11Beacon": Dot11Beacon,
            "Dot11Elt": Dot11Elt, "Dot11Deauth": Dot11Deauth, "Dot11Disas": Dot11Disas,
            "Dot11ProbeReq": Dot11ProbeReq, "Dot11ProbeResp": Dot11ProbeResp,
            "Dot11AssoReq": Dot11AssoReq, "EAPOL": EAPOL,
        }
    except ImportError:
        print("scapy is required:  pip install scapy", file=sys.stderr)
        raise SystemExit(1)


def ssid_from(pkt, mods) -> str:
    """Walk the tagged parameters for element ID 0 (SSID)."""
    Dot11Elt = mods["Dot11Elt"]
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if int(getattr(elt, "ID", -1)) == 0:
            raw = bytes(getattr(elt, "info", b""))
            if not raw or raw == b"\x00" * len(raw):
                return "<hidden>"
            return raw.decode("utf-8", "replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return ""


def channel_from(pkt, mods) -> str:
    Dot11Elt = mods["Dot11Elt"]
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if int(getattr(elt, "ID", -1)) == 3:
            raw = bytes(getattr(elt, "info", b""))
            if raw:
                return str(raw[0])
        elt = elt.payload.getlayer(Dot11Elt)
    return "?"


def eapol_msgnr(pkt, mods) -> int:
    """Classify an EAPOL-Key frame as message 1..4 of the four-way handshake."""
    EAPOL = mods["EAPOL"]
    body = bytes(pkt[EAPOL].payload) if pkt[EAPOL].payload else b""
    if len(body) < 95:
        return 0
    key_info = int.from_bytes(body[1:3], "big")
    pairwise = bool(key_info & 0x0008)
    install = bool(key_info & 0x0040)
    ack = bool(key_info & 0x0080)
    mic = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)
    if not pairwise:
        return 0
    if ack and not mic:
        return 1
    if mic and not ack and not secure:
        return 2
    if mic and ack and install:
        return 3
    if mic and secure and not ack:
        return 4
    return 0


def has_pmkid(pkt, mods) -> bool:
    """Message 1 with a PMKID carries a 22-byte RSN key-data field ending in the PMKID KDE."""
    EAPOL = mods["EAPOL"]
    body = bytes(pkt[EAPOL].payload) if pkt[EAPOL].payload else b""
    if len(body) < 97:
        return False
    key_data_len = int.from_bytes(body[93:95], "big")
    key_data = body[95:95 + key_data_len]
    return key_data_len >= 22 and key_data[:6] == b"\xdd\x14\x00\x0f\xac\x04"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cap", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.cap:
        ap.print_help()
        return 2

    mods = load_scapy()
    Dot11 = mods["Dot11"]

    aps: dict[str, dict[str, str]] = {}
    probes: dict[str, set[str]] = collections.defaultdict(set)
    deauths: collections.Counter[tuple[str, str]] = collections.Counter()
    reasons: collections.Counter[int] = collections.Counter()
    handshake: dict[tuple[str, str], set[int]] = collections.defaultdict(set)
    pmkids: set[tuple[str, str]] = set()
    clients: dict[str, set[str]] = collections.defaultdict(set)
    total = 0

    with mods["PcapReader"](args.cap) as reader:
        for pkt in reader:
            if not pkt.haslayer(Dot11):
                continue
            total += 1
            d = pkt[Dot11]
            bssid = (d.addr3 or "").lower()
            src = (d.addr2 or "").lower()
            dst = (d.addr1 or "").lower()

            if pkt.haslayer(mods["Dot11Beacon"]) or pkt.haslayer(mods["Dot11ProbeResp"]):
                name = ssid_from(pkt, mods)
                if bssid and (bssid not in aps or aps[bssid]["ssid"] in ("", "<hidden>")):
                    aps[bssid] = {"ssid": name, "channel": channel_from(pkt, mods)}
            elif pkt.haslayer(mods["Dot11ProbeReq"]):
                name = ssid_from(pkt, mods)
                if name and name != "<hidden>":
                    probes[src].add(name)
            elif pkt.haslayer(mods["Dot11Deauth"]) or pkt.haslayer(mods["Dot11Disas"]):
                deauths[(bssid, dst)] += 1
                layer = pkt.getlayer(mods["Dot11Deauth"]) or pkt.getlayer(mods["Dot11Disas"])
                if layer is not None:
                    reasons[int(getattr(layer, "reason", 0))] += 1
            elif pkt.haslayer(mods["EAPOL"]):
                msg = eapol_msgnr(pkt, mods)
                station = dst if msg in (1, 3) else src
                if bssid:
                    handshake[(bssid, station)].add(msg)
                    if msg == 1 and has_pmkid(pkt, mods):
                        pmkids.add((bssid, station))
            if d.type == 2 and bssid and src and src != bssid:
                clients[bssid].add(src)

    print(f"== {total} 802.11 frames")
    print(f"\n== access points ({len(aps)})")
    for bssid, info in sorted(aps.items()):
        print(f"  {bssid}  ch {info['channel']:>3}  {info['ssid']}  "
              f"({len(clients.get(bssid, ()))} clients)")

    by_ssid: dict[str, set[str]] = collections.defaultdict(set)
    for bssid, info in aps.items():
        by_ssid[info["ssid"]].add(bssid)
    twins = {s: b for s, b in by_ssid.items() if len(b) > 1 and s not in ("", "<hidden>")}
    if twins:
        print("\n== possible evil twins (same SSID, multiple BSSIDs)")
        for ssid, bssids in twins.items():
            print(f"  {ssid}: {', '.join(sorted(bssids))}")

    if deauths:
        print(f"\n== deauth/disassoc ({sum(deauths.values())} frames)")
        for (bssid, target), count in deauths.most_common(15):
            print(f"  {count:>6}  bssid {bssid} -> {target}")
        print("  reason codes: " + ", ".join(
            f"{code}={REASON_CODES.get(code, '?')} x{n}" for code, n in reasons.most_common()))

    print(f"\n== EAPOL handshakes ({len(handshake)} station pairs)")
    for (bssid, station), msgs in sorted(handshake.items()):
        ssid = aps.get(bssid, {}).get("ssid", "?")
        crackable = ({1, 2} <= msgs) or ({2, 3} <= msgs) or ((bssid, station) in pmkids)
        tag = "CRACKABLE" if crackable else "incomplete"
        extra = " (PMKID)" if (bssid, station) in pmkids else ""
        print(f"  {bssid} <-> {station}  msgs={sorted(m for m in msgs if m)}  "
              f"[{tag}{extra}]  ssid={ssid}")

    if probes:
        print(f"\n== probe requests ({len(probes)} clients)")
        for sta, names in sorted(probes.items())[:20]:
            print(f"  {sta}: {', '.join(sorted(names))}")

    if any(({1, 2} <= m) or ({2, 3} <= m) for m in handshake.values()) or pmkids:
        print("\nnext:  hcxpcapngtool -o hash.hc22000 %s && "
              "hashcat -m 22000 hash.hc22000 rockyou.txt" % args.cap)
    return 0


def selftest() -> int:
    mods = load_scapy()
    Dot11, Dot11Beacon, Dot11Elt = mods["Dot11"], mods["Dot11Beacon"], mods["Dot11Elt"]
    beacon = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") /
              Dot11Beacon(cap="ESS+privacy") /
              Dot11Elt(ID=0, info=b"CorpWiFi") /
              Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96") /
              Dot11Elt(ID=3, info=b"\x06"))
    assert ssid_from(beacon, mods) == "CorpWiFi", ssid_from(beacon, mods)
    assert channel_from(beacon, mods) == "6", channel_from(beacon, mods)

    hidden = (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2="11:22:33:44:55:66", addr3="11:22:33:44:55:66") /
              Dot11Beacon() / Dot11Elt(ID=0, info=b"\x00\x00\x00"))
    assert ssid_from(hidden, mods) == "<hidden>", ssid_from(hidden, mods)

    assert REASON_CODES[7].startswith("class-3")
    print("self-test OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **A "handshake" Wireshark labels as complete may still be uncrackable** if the SSID is absent.
  Capture or supply the ESSID explicitly (`aircrack-ng -e`).
- **Messages 3+4 alone are not enough** for the classic attack because message 4 may not carry a
  usable MIC over known data in all implementations. Aim for 1+2 or 2+3.
- `hcxpcapngtool` prefers **pcapng**. Convert first: `editcap -F pcapng in.cap out.pcapng`.
- **WPA3 (SAE)** is not crackable this way at all -- there is no offline dictionary attack against
  the handshake. If the beacon advertises AKM 8 (SAE), stop.
- **Enterprise WPA (802.1X/EAP)** has no PSK. You are looking at EAP identities and possibly a
  MSCHAPv2 challenge/response (`hashcat -m 5500`), not a passphrase.
- Decryption only covers sessions whose handshake you have. Traffic from a client that associated
  earlier remains encrypted.
- `airdecap-ng` writes `<name>-dec.cap` next to the input and prints a summary; a "decrypted 0
  packets" line means the key or ESSID is wrong.
- **Monitor-mode artefacts**: retries, FCS errors and duplicated frames are normal. Do not read
  meaning into them.
- Android `btsnoop_hci.log` needs *Developer options > Enable Bluetooth HCI snoop log* and a
  reboot; older devices put it at `/sdcard/btsnoop_hci.log`, newer ones under
  `/data/misc/bluetooth/logs/`.

## Tools

`aircrack-ng` suite (`aircrack-ng`, `airdecap-ng`, `airodump-ng`, `wpaclean`, `aireplay-ng`),
`hcxtools` (`hcxpcapngtool`, `hcxhashtool`), `hashcat`, `john` (`wpapcap2john`), `cowpatty`,
`genpmk`, `tshark`/`wireshark`, `scapy`, `btmon`/`hcidump`, `bettercap` (live only).

## References

- IEEE 802.11 frame control type/subtype values are in the standard's clause 9.
- `tshark -G fields | grep '^F\twlan'` and `grep '^F\teapol'` list every field name.
- `hcxpcapngtool --help` documents the 22000 hash-line format it emits.
