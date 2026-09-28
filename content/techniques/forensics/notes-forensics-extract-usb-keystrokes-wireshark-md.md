---
title: "Extract USB Keystrokes wireshark (Forensics)"
category: "forensics"
subcategory: "network"
type: "technique"
tags: ["my-notes", "personal", "pcap", "wireshark", "tshark", "usb-hid", "forensics"]
summary: "Personal note: Extract USB Keystrokes wireshark (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Extract USB Keystrokes wireshark.md"
---

### Script

```
https://github.com/carlospolop-forks/ctf-usb-keyboard-parser
```

### How to use

- Apply this filter in Wireshark

```
usb.transfer_type == 0x01 && usb.bInterfaceClass == 3
```

- Highlight all the packets and export them to a new file `filtered.pcap`
- Run this

```
tshark -r filtered.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata
```

- Then

```
tshark -r filtered.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > output.txt
```

- Finally

```
python usbkeyboard.py output.txt
```

### Reference

```
https://www.youtube.com/watch?v=EnOgRyio_9Q&t=337s
```

```
https://teamrocketist.github.io/2017/08/29/Forensics-Hackit-2017-USB-ducker/
```

```
https://github.com/carlospolop-forks/ctf-usb-keyboard-parser
```

---

*From your own notes: `Forensics/Extract USB Keystrokes wireshark.md`*
