---
title: "deldeldel - IrisCTF 2025"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "wireshark", "tshark", "usb-hid", "deldeldel", "network", "irisctf", "irisctf-2025", "2025", "ctf-writeup"]
summary: "For this challenge, we were given a .pcapng file named klogger.pcapng."
source:
  name: "CTFtime writeup #39870"
  url: "https://ctftime.org/writeup/39870"
original_source: "https://emree-1.github.io/posts/irisctf2025-forensics-deldeldel/"
ctf:
  name: "IrisCTF 2025"
  year: 2025
  challenge: "deldeldel"
---

## Metadata

- **CTF:** IrisCTF 2025
- **Task:** deldeldel
- **Author team:** Ping's Got Wings
- **CTFtime:** <https://ctftime.org/writeup/39870>
- **Original writeup:** <https://emree-1.github.io/posts/irisctf2025-forensics-deldeldel/>

---
# irisCTF2025 - Forensics - deldel

[**Original writeup**](<https://emree-1.github.io/posts/irisctf2025-forensics-deldeldel/>)

## Ressources

For this challenge, we were given a `.pcapng` file named `klogger.pcapng`. Upon inspection, we found that it contains only USB protocol traffic.

## Tools 

We will primarily use `Wireshark` to analyze the `.pcapng` file.   
Additionally, we will use custom `Python` scripts to parse and reconstruct keyboard strokes from the captured USB packets.

## Resolution

### Initial Analysis 

Before diving into deeper analysis, we first inspect the general structure of the captured traffic. To do so, we leverage `Wireshark’s` built-in statistics tools.

By checking the `Protocol Hierarchy` section, we confirm that the capture file exclusively contains USB packets, which simplifies our analysis since USB communications follow a structured and predictable format.

> **Understanding USB Communication**   
> USB operates on a master-slave architecture, where the master (host) periodically polls connected devices for data.  
A USB device cannot send data autonomously; it must wait for the host to request it.   
> If a device attempts to send data without being polled, the packet is ignored by the operating system.

![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/protocol_hierarchy.png>)

Now that we have confirmed that the capture file contains only USB traffic, our next step is to identify the communicating entities. To do this, we examine the `Endpoints` listing in `Wireshark`.

![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/endpoints.png>)

From this list, we observe several USB devices communicating with the host: `1.3.2`, `1.5.1`, `1.5.2`, `1.7.1`, `1.7.2`.

### Device types

To infer the type of each device, we analyze the packets they transmit. By examining the length and structure of the transferred data, we can make an educated guess about the nature of the connected peripherals.

A closer look at the captured USB packets reveals two types of transfer modes:  
\- `URB_BULK`: used for transferring large amounts of data, mainly by USB storage devices (e.g., flash drives, external hard disks, SSDs).  
\- `URB_INTERRUPT`: primarily used by Human Interface Devices (HID) such as keyboards and mice, which require low-latency, event-driven communication.

Using Wireshark’s USB transfer type filter, we can isolate and classify the devices:  
\- Applying the filter `usb.transfer_type == "URB_BULK"`, we see that only one endpoint (`1.7.2`) appears, alongside the host. This suggests that 1.7.2 is a USB storage device.  
\- Applying the filter `usb.transfer_type == "URB_INTERRUPT"`, we observe that all other devices are listed.

Since HID peripherals (keyboards, mice, game controllers, etc.) use interrupt transfers, this indicates that one of these devices might be a keyboard—which is relevant given the challenge’s context.

### Keylogger?

The filename is klogger.pcapng, as a keylogger is intended to capture every keypress a user doing, we assume at least one of the USB devices must be a USB keyboard.

Based on the HID specifications it is actually pretty easy to spot a USB keyboards as it applying the following criterias :   
\- Transmitted data length is equal to 8 bytes.  
\- Second byte is always equal to 0x00 as it is a Reserverd Byte.  
\- If a keyboard is used by a human, the device should sometimes send some empty reports.  
\- Each keypress is represented by a scancode, the association between scancode and value is defined by the USB HID standards.

The filename `klogger.pcapng` suggests that this capture involves keylogging, meaning at least one of the USB devices should be a keyboard.

According to the HID (Human Interface Device) specifications, USB keyboards follow a predictable structure that makes them relatively easy to identify. A valid USB keyboard exhibits the following characteristics:  
\- Each data transfer is exactly `8` bytes long.  
\- The second byte is always `0x00`, as it is a reserved byte.  
\- Empty reports (all bytes set to `0x00`) appear periodically, as a real user does not press keys continuously.  
\- Keystrokes are encoded using `scancodes`, following the USB HID standard, where each scancode corresponds to a specific key on a standard keyboard.

![](<http://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/keyboard_report_structure.png>)

Since USB keyboards always send 8-byte HID reports, we can filter the packets using Wireshark with:  
```bash  
usb.data_len == 8  
```  
Applying this filter, we identify two devices transmitting packets of this length:   
![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/endpoints_filtered.png>)

To determine which of these devices is an actual keyboard, we inspect the transmitted data.  
**Device `1.3.2`**: The packet contents do not conform to standard HID keyboard scancodes.   
In the USB HID specification, valid scancodes range from 0x00 to 0xE7. Scancodes from 0xE8 to 0xFFFF are reserved and should not appear in keyboard reports. The data from `1.3.2` contains invalid scancodes, meaning it is unlikely to be a keyboard. 

![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/1-3-2_packet.png>)

**Device `1.5.1`**: The data appears more structured, aligning with expected keyboard report formats. This suggests that `1.5.1` is a USB keyboard and likely the one being logged by the keylogger.

![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/1-5-1_packet.png>)

This fits way more the structure of data sent by a keyboard. To be sure we can check for all the properties we mentionned previouvly : 

1\. All the data packets transmitted by device `1.5.1` have a length of 8 bytes.  
2\. All the data packets transmitted by device `1.5.1` have the second byte equal to 0x00.  
3\. And this devices sends sometimes some empty keywoards, representing that there is no key pressed by the user. 

To automate the detection of USB keyboards in a capture file, I wrote a Python script that performs this recognition phase. You can refer to the [guide](<https://emree-1.github.io/posts/KBDscan/>) for instructions on how to use it or find the source code on my [GitHub](<https://github.com/emree-1/tools>).

```bash  
python3 [KBDscan.py](http://KBDscan.py) klogger.pcapng

# === OUTPUT ===  
1.5.1  
```

### Extracting information from the keylogger

Assuming that device `1.5.1` is the keyboard, the next step is to determine which keys were pressed. The captured keystrokes may contain sensitive information, such as passwords or flags.

There are many existing scripts available online to decode USB keyboard captures. A quick search for `usb keyboard ctf` reveals several useful tools. I personally decided to use [TeamRocketIst’s script](<https://github.com/TeamRocketIst/ctf-usb-keyboard-parser/tree/master>) for this purpose.

Following their `README` instructions, the first step is to extract the required packets using `tshark`.

```bash  
tshark -r ./klogger.pcapng -Y 'usb.capdata && usb.data_len == 8 && usb.src == 1.5.1' -T fields -e usb.capdata > usbPcapData  
```  
\- `-r ./klogger.pcapng` : specifies the input `.pcapng` file.  
\- `-Y 'usb.capdata && usb.data_len == 8 && usb.src == 1.5.1'` : filters packets that contain usb.capdata (keyboard data), have a data length of 8 bytes (keyboard HID reports), and priginate from device `1.5.1`.  
\- `-T fields -e usb.capdata` : extracts only the captured USB keyboard data from the packets.

Then, I executed the TeamRocketIst script as instructed. 

```bash   
python3 [usbkeyboard.py](http://usbkeyboard.py) usbPcapData  
```

This produced the following output: 

![](<https://emree-1.github.io/assets/img/irisctf2025/forensics/deldeldel/flag.png>)

Since I like to optimize my workflow (some might say I’m lazy, I prefer "efficient"), I wrote a script to automate both extraction and decoding in a single step. You can look at the detailed guide or at the source code on my [GitHub](<https://github.com/emree-1/tools>).

## Conclusion

And that’s how I successfully extracted the flag from the USB packet capture ! This was my first time analyzing USB protocol traffic, and I really enjoyed diving into it. Not only did I learn more about how USB devices communicate, but I also improved my `Wireshark` skills along the way.

I hope to encounter more USB-based challenges in future CTFs—maybe involving mice movements or audio output.

Thank you for reading my write-up! If you liked this one and would like to see more of my work visit my [website](<https://emree-1.github.io>)!

*emree1*
