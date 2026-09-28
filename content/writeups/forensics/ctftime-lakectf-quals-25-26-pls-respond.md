---
title: "Pls respond - LakeCTF Quals 25-26"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "sms", "wvg", "radare2", "wireshark", "morse", "network", "lakectf-quals-25", "lakectf-quals-25-26", "ctf-writeup"]
summary: "All code used and artifacts produced are available on GitHub."
source:
  name: "CTFtime writeup #40506"
  url: "https://ctftime.org/writeup/40506"
original_source: "https://toranm.me/post/2025-11-29-lakectf-pls-respond/"
ctf:
  name: "LakeCTF Quals 25-26"
  challenge: "Pls respond"
---

## Metadata

- **CTF:** LakeCTF Quals 25-26
- **Task:** Pls respond
- **Author team:** karls royale
- **CTFtime tags:** pcap, sms, wvg
- **CTFtime:** <https://ctftime.org/writeup/40506>
- **Original writeup:** <https://toranm.me/post/2025-11-29-lakectf-pls-respond/>

---
All code used and artifacts produced are available on [GitHub](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup>). Read on my blog for an enhanced reading experience: [Writeup: LakeCTF pls respond](<http://toranm.me/post/2025-11-29-lakectf-pls-respond/>).

The challenge "pls respond" from LakeCTF involved analyzing a network capture file containing SMS messages. Inside the messages are animations, IMelody and wireless vector graphics.

# Challenge Overview  
The challenge provides a pcap file named `chall.pcap`. And the following description:  
*"What are these SMS I received as soon as I connected to the gNB? Hint: To configure NAS5GS, please follow this guide <https://github.com/SysSec-KAIST/LTESniffer/blob/main/pcap_file_example/README.md> for the first part and enable the NR/5GS equivalent protocols of the LTEs one presented in 2nd part (i.e. MAC-NR,PDCP-NR,RLC-NR,NAS-5GS) PS:These packets are valid transmissions with an actual phone"*.

[chall.pcap](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/chall.pcap>)

# Opening the pcap  
First, I opened the pcap file using Wireshark and configured it to accept the relevant protocols.  
I first set the DLT_USER table to dissect the relevant protocols as shown in the guide.  
I then enabled the protocols:  
\- nas_5gs_udp  
\- li5g_tls  
\- rlc_nr_udp  
\- pdcp_nr_udp  
\- mac_nr_udp  
\- ipv6_dect_nr  
\- \\+ the defaults

as suggested in the hint. This allowed Wireshark to properly dissect the packets.  
This configuration is shown in the following screenshots:  
![Wireshark DLT_USER configuration](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-config-dlt.png?raw=true>)  
![Wireshark protocol configuration](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-config-protocols.png?raw=true>)

# Analyzing the packets  
After configuring Wireshark, I looked through the packets. Wireshark could reassemble PDCP-NR packets. Looking through the reassembled PDCP-NR packets, I found several NAS-5GS messages containing SMS data.  
In total, there were 4 SMS messages. The first message is a text message, while the other three contain binary data.  
![Wireshark overview](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-analyze-overview-full.png?raw=true>)  
![Wireshark gsm](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-analyze-overview-gsm.png?raw=true>)

# Extracting the SMS messages  
The contents of the SMS messages are defined in the GSM 03.40 standard, which is now maintained by 3GPP as TS 23.040 and ETSI as TS 123 040. The current version is 19.0.0 (December 2025).  
This standard defines formats for SMS messages, including text, images, animations, and sounds.  
For more advanced formats than just text, a data structure called User Data Header (UDH) is used to indicate the type of SMS message and how to interpret the data.  
Following the UDH are the actual data contained as Information Elements (IEs). These IEs are defined in the standard and are assigned specific identifiers (IEIs, Page 75).  
Outside the UDH, a SMS text indicates a simple text message for the format, when the UDH is not understood by the receiving device.

## Message 1: Text Message  
The first SMS message was a simple text message. No User Data header. I extracted the text and this gives the first part of the flag: `EPFL{Did_y0u_know_th4t_`.  
![Wireshark packet 1](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-packet-1.png?raw=true>)

## Message 2: Animation  
A IEI of `0x0e` indicates a "Large Animation (16*16 times 4)".  
Within the standard, an animation (9.2.3.24.10.3.3) is simply defined as sequence of 4 pictures. A picture (9.2.3.24.10.3.2) is a pixel grid where each bit represents a pixel, that can be white (`0`) or black (`1`).  
![Wireshark packet 2](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-packet-2.png?raw=true>)

I quickly wrote a script to parse the animation data and render each frame as an image.  
The animation frames are as follows:

![SMS](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/2-animation/large_anim_16x16_f0.png?raw=true>)  
![_h4s_](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/2-animation/large_anim_16x16_f1.png?raw=true>)  
![s0_m](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/2-animation/large_anim_16x16_f2.png?raw=true>)  
![any_](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/2-animation/large_anim_16x16_f3.png?raw=true>)

This gives the second part of the flag: `SMS_h4s_s0_many_`.

## Message 3: iMelody  
Next, the third SMS contains the IEI 0x0c, which indicates an "iMelody" message.  
![Wireshark packet 3](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-packet-3.png?raw=true>)  
iMelody is a format for ringtones based on the work of Sony Ericsson back in the day, defined in the iMelody specification by the Infrared Data Association.  
As a side note, I had a Sony Ericsson phone, and I remember opening up iMelody files on it, but not understanding the format.

The iMelody data contained is ASCII text:  
```  
BEGIN:IMELODY  
VERSION:1.2  
FORMAT:CLASS1.0  
STYLE:S2  
MELODY:c4c4c4r2c2r2c4c2c4r2c4c4c4c4c2r2c2c4r2c2c2c4r2c4  
END:IMELODY  
```

The melody section contains notes and durations. I wrote a small script to parse the melody and create a WAV file. c4 denotes a short C note, and c2 a long C note, r2 denotes a rest.  
This is what the IMelody sounds like:  
[imelody.wav](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/3-imelody/out_imelody.wav>)  
Hence, the melody encodes a Morse code message:  
```  
... - .-. ....- -. --. .  
```

Decoding the Morse code gives the third part of the flag: `STR4NGE_`.

Thanks to n0rdan for getting the correct Morse code translation and providing the iMelody spec.

## Message 4: Wireless Vector Graphic (WVG)  
The fourth SMS message was the hardest to interpret. It contained the IEI 0x18, which is a "Standard WVG object".  
![Wireshark packet 4](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/ws-packet-4.png?raw=true>)  
The Wireless Vector Graphic (WVG), is a vector image format for mobile devices, described in Annex G of the standard. I did not find existing parsers for this format.

The Annex G provides a BNF for the format and general descriptions of the various elements. I go into more detail about WVG in Annex A at the end of this writeup.

During the CTF, I did not manage to get the parser to work 100%. Alkalem came in and provided a working parser during the CTF. With his result, my parser could be fixed and the WVG format shown below.

Rendering it to SVG gives the following image:

![WVG rendered spelling _ext3nsi0ns}](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup/blob/main/4-wvg/rendered.svg?raw=true>)

So finally, the fourth part of the flag is: `_ext3nsi0ns}`.

# Wrong Avenues  
At first, I did not see the GSM packets and thought I had to look into more recent NR formats, which might be encrypted with NAS5GS security. So I tried to decrypt them using various methods, but this was a dead end.

# Issues with the specification  
There are some mistakes and missing details in the specification:  
\- Circular polylines have at least two points, but the number of points is stored as point_count - 2.  
\- Signed offset integer size depends on a flag, but the specification lists the same conditions for both sizes (=0). It should be (=1) for the larger size (Page 204 in Annex G).

# Conclusion  
The flag was 

`EPFL{Did_y0u_know_th4t_SMS_h4s_s0_many_STR4NGE_ext3nsi0ns}`

which I did not.

All code used and artifacts produced are available on [GitHub](<https://github.com/xXMarkuski/2025-lakectf-pls-resond-writeup>).

Overall, I had fun working on this challenge. It was the first challenge I looked at, and I made some good progress early on, but the WVG part was hard. I found it interesting to see SMS message formats. There is a world of formats where people put in the effort to make things work on limited devices and networks. They decided to create big PDFs, but in the end these formats became irrelevant with modern smartphones. Still, its in the spec and applicable to 5G SMS messages.

This CTF was played as a collaboration between [Royal Roppers](https://royalroppers.team/) and [KITCTF](<https://kitctf.de/>).

# Sources  
\- Digital cellular telecommunications system (Phase 2+) (GSM);  
Universal Mobile Telecommunications System (UMTS);  
LTE;  
5G;  
Technical realization of the Short Message Service (SMS):  
\- [Originating GSM specification](<https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=747>)  
\- [.docx by 3GPP](<https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=141>)  
\- [PDF by ETSI](<https://www.etsi.org/deliver/etsi_ts/123000_123099/123040/19.00.00_60/ts_123040v190000p.pdf>)  
\- Background on Formats:  
\- <https://en.wikipedia.org/wiki/User_Data_Header>  
\- <https://en.wikipedia.org/wiki/GSM_03.40>  
\- IMelody:  
\- [iMelody Wikipedia](<https://en.wikipedia.org/wiki/IMelody>)  
\- [iMelody by the Infrared Data Association](<https://www.irda.org/standards/pubs/iMelody.pdf>)

# Annex A: More on the Wireless Vector Graphic (WVG)  
Wireless Vector Graphic (WVG) is a binary format for vector graphics. It consists of a header and elements.   
The format comes in various flavors. First, there is standard and character size WVG. The latter is used inline in text to represent handwritten glyphs or glyphs not present in the font.  
There are various compression modes and variable integer lengths. The format supports two coordinate systems, flat and compact.  
Each of these settings changes the semantics of the binary format.  
Coordinates can be represented by absolute positions or relative to another coordinate. The format supports color in multiple formats and has a default websafe color palette.

Elements:  
There are 9 basic elements and additional elements for advanced usage:  
\- Lines  
\- Polyline  
\- Circular polyline  
\- Bezier polyline  
\- Polygons  
\- Basic:  
\- Ellipse  
\- Rectangle (with rounded corners)  
\- Special:  
\- Regular polygon  
\- Star  
\- Grid  
\- Text  
\- Group  
\- Reuse  
\- Simple & Standard animation  
\- Frame  
\- Extended

Relevant for this challenge are standard WVG, flat coordinate system, black & white color scheme, and the elements polyline, circular polyline, and reuse.

The header defines which elements are used, so that the type indicator in each element uses as few bits as possible (2 in this case, for the three elements). The header also defines how many bits are used for coordinates and integers.  
In the format, relative coordinates can be encoded in two levels of precision. The number of bits for each level is given in the header; which level is used is given in the element.

A polyline is a sequence of connected line segments defined by points. In our setup, the first point is absolute, and subsequent points are relative to the previous point.

A circular polyline is similar to a polyline but supports curved segments. Each curved segment has a curve offset defining the curvature, by a formula given in the specification.

A reuse element references another element by its index and applies a transformation (translation, rotation, scaling) to it. In our case, only translation is used.

# Annex B: Parsed WVG  
```  
WvgDrawing  
├── Header  
│ ├── is_standard: true  
│ ├── version: 0  
│ ├── ColorConfig  
│ │ ├── scheme: 0 (Black & White)  
│ │ ├── default_line_color: RGB(0, 0, 0)  
│ │ ├── default_fill_color: RGB(0, 0, 0)  
│ │ └── background_color: RGB(255, 255, 255)  
│ └── CodecParams  
│ ├── ElementMask  
│ │ ├── enabled_count: 3  
│ │ ├── element_type_bits: 2  
│ │ ├── local_envelope: ✗  
│ │ ├── polyline: ✓  
│ │ ├── circular_polyline: ✓  
│ │ ├── bezier_polyline: ✗  
│ │ ├── simple_shape: ✗  
│ │ ├── reuse: ✓  
│ │ ├── group: ✗  
│ │ ├── animation: ✗  
│ │ ├── has_extension: ✗  
│ │ └── enabled_types: [Polyline, CircularPolyline, Reuse]  
│ ├── AttributeMask  
│ │ ├── is_empty: true  
│ │ ├── line_type: ✗  
│ │ ├── line_width: ✗  
│ │ ├── fill: ✗  
│ │ └── line_color: ✗  
│ ├── GenericParams  
│ │ ├── angle_resolution: 3 (22.5°)  
│ │ ├── angle_in_bits: 3  
│ │ ├── scale_resolution: 0 (1/4)  
│ │ ├── scale_in_bits: 3  
│ │ ├── index_in_bits: 4  
│ │ └── curve_offset_in_bits: 4  
│ └── FlatParams  
│ ├── drawing_size: 128x32  
│ ├── max_x_in_bits: 7  
│ ├── max_y_in_bits: 5  
│ ├── xy_all_positive: true  
│ ├── trans_xy_in_bits: 7  
│ ├── offset_x: level1=3, level2=5  
│ ├── offset_y: level1=3, level2=5  
│ └── num_points_in_bits: 3  
└── Elements (18 total)  
├── [0] Polyline  
│ ├── point_count: 1  
│ └── points:  
│ └──[0] (83, 9) ← start (absolute)  
├── [1] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (83, 14) ← start (absolute)  
│ └──[1] (83, 25) Δ(+0, +11)  
├── [2] CircularPolyline  
│ ├── point_count: 4  
│ ├── curve_offsets: [0, -6, -4]  
│ └── points:  
│ ├──[0] (3, 15) ← start (absolute)  
│ ├──[1] (16, 15) Δ(+13, +0) [straight]  
│ ├──[2] (3, 15) Δ(-13, +0) [curve=-6]  
│ └──[3] (16, 22) Δ(+13, +7) [curve=-4]  
├── [3] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (18, 12) ← start (absolute)  
│ └──[1] (28, 23) Δ(+10, +11)  
├── [4] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (18, 23) ← start (absolute)  
│ └──[1] (28, 12) Δ(+10, -11)  
├── [5] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (34, 9) ← start (absolute)  
│ └──[1] (34, 24) Δ(+0, +15)  
├── [6] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (34, 15) ← start (absolute)  
│ └──[1] (37, 15) Δ(+3, +0)  
├── [7] CircularPolyline  
│ ├── point_count: 5  
│ ├── curve_offsets: [4, 4, 4, 4]  
│ └── points:  
│ ├──[0] (41, 10) ← start (absolute)  
│ ├──[1] (49, 10) Δ(+8, +0) [curve=4]  
│ ├──[2] (49, 17) Δ(+0, +7) [curve=4]  
│ ├──[3] (49, 24) Δ(+0, +7) [curve=4]  
│ └──[4] (41, 24) Δ(-8, +0) [curve=4]  
├── [8] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (42, 17) ← start (absolute)  
│ └──[1] (49, 17) Δ(+7, +0)  
├── [9] CircularPolyline  
│ ├── point_count: 3  
│ ├── curve_offsets: [3, 0]  
│ └── points:  
│ ├──[0] (58, 15) ← start (absolute)  
│ ├──[1] (66, 15) Δ(+8, +0) [curve=3]  
│ └──[2] (66, 25) Δ(+0, +10) [straight]  
├── [10] Polyline  
│ ├── point_count: 2  
│ └── points:  
│ ├──[0] (58, 11) ← start (absolute)  
│ └──[1] (58, 25) Δ(+0, +14)  
├── [11] CircularPolyline  
│ ├── point_count: 4  
│ ├── curve_offsets: [-5, 0, 5]  
│ └── points:  
│ ├──[0] (78, 12) ← start (absolute)  
│ ├──[1] (70, 12) Δ(-8, +0) [curve=-5]  
│ ├──[2] (77, 23) Δ(+7, +11) [straight]  
│ └──[3] (70, 23) Δ(-7, +0) [curve=5]  
├── [12] CircularPolyline  
│ ├── point_count: 6  
│ ├── curve_offsets: [0, -3, 0, -3, 0]  
│ └── points:  
│ ├──[0] (89, 12) ← start (absolute)  
│ ├──[1] (89, 26) Δ(+0, +14) [straight]  
│ ├──[2] (95, 26) Δ(+6, +0) [curve=-3]  
│ ├──[3] (95, 12) Δ(+0, -14) [straight]  
│ ├──[4] (89, 12) Δ(-6, +0) [curve=-3]  
│ └──[5] (95, 26) Δ(+6, +14) [straight]  
├── [13] Reuse  
│ ├── element_index: 9 (references element #9)  
│ ├── Transform  
│ │ ├── translate: (41, 0)  
│ │ └── (no rotation/scale)  
│ └── has_array: false (single instance)  
├── [14] Reuse  
│ ├── element_index: 10 (references element #10)  
│ ├── Transform  
│ │ ├── translate: (41, 0)  
│ │ └── (no rotation/scale)  
│ └── has_array: false (single instance)  
├── [15] Reuse  
│ ├── element_index: 11 (references element #11)  
│ ├── Transform  
│ │ ├── translate: (40, 0)  
│ │ └── (no rotation/scale)  
│ └── has_array: false (single instance)  
├── [16] CircularPolyline  
│ ├── point_count: 7  
│ ├── curve_offsets: [6, 0, 0, 0, 0, 6]  
│ └── points:  
│ ├──[0] (122, 7) ← start (absolute)  
│ ├──[1] (124, 10) Δ(+2, +3) [curve=6]  
│ ├──[2] (124, 15) Δ(+0, +5) [straight]  
│ ├──[3] (127, 18) Δ(+3, +3) [straight]  
│ ├──[4] (124, 21) Δ(-3, +3) [straight]  
│ ├──[5] (124, 26) Δ(+0, +5) [straight]  
│ └──[6] (122, 29) Δ(-2, +3) [curve=6]  
└── [17] Polyline  
├── point_count: 2  
└── points:  
├──[0] (0, 28) ← start (absolute)  
└──[1] (6, 28) Δ(+6, +0)  
```
