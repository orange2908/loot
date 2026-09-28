---
title: "USBNet - Nullcon Goa HackIM 2025 CTF"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["wireshark", "forensics", "png", "usb", "pcap", "scapy", "png-chunks", "network", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "SPECT3RR  / Writeups-of-CTFs-  Public"
source:
  name: "CTFtime writeup #39841"
  url: "https://ctftime.org/writeup/39841"
original_source: "https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-USBNET-(Forensics)"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "USBNet"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** USBNet
- **Author team:** ODYNSEC
- **CTFtime tags:** wireshark, forensics, png, usb
- **CTFtime:** <https://ctftime.org/writeup/39841>
- **Original writeup:** <https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-USBNET-(Forensics)>

---
[ SPECT3RR ](https://github.com/SPECT3RR) / **[Writeups-of-CTFs-](https://github.com/SPECT3RR/Writeups-of-CTFs-) ** Public

  * [ Notifications ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-) You must be signed in to change notification settings
  * [ Fork 0 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)
  * [ Star  2 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)


# NULLCON: USBNET (Forensics)

Jump to bottom

Junaid Arshad Malik edited this page Feb 2, 2025 · [1 revision](https://github.com/SPECT3RR/Writeups-of-CTFs-/wiki/NULLCON:-USBNET-\(Forensics\)/_history)

# NullCon CTF Write-up: USBNET

## Challenge Overview

In this challenge, we were provided with a `.pcapng` file that contained USB traffic. Our task was to analyze the packets and extract useful data from the capture. Upon investigating the capture, we discovered that it contained USB Ethernet traffic, and some packets had meaningful data embedded in them.

## Initial Analysis

We opened the `.pcapng` file in **Wireshark** and noticed several packets containing data with `NCMA` and `NCM0` identifiers. This suggested that the packets were part of an **Ethernet over USB** communication.

Upon further inspection, we found a packet larger than 500 bytes that contained recognizable **PNG file signatures** :

  * `IHDR` (Image Header)
  * `PLTE` (Palette)
  * `IDAT` (Image Data)
  * `IEND` (End of Image)


This indicated that a **PNG image** was embedded within the USB data transfer.

## Extracting the PNG

To automate the extraction, we wrote a **Python script** using **Scapy** to parse the `.pcapng` file and extract the PNG image. The script searches for the PNG magic bytes (`\x89PNG\x0D\x0A\x1A\x0A`), extracts the data until the `IEND` marker, and saves it as a valid image file.

### Extraction Script

```
    from scapy.all import rdpcap
    
    # Path to your pcapng file
    pcap_file = "usbnet.pcapng"
    output_png_file = "extracted_image.png"
    
    def extract_png_from_pcap(pcap_file, output_png_file):
        # Read the pcap file
        packets = rdpcap(pcap_file)
        
        # Loop through each packet and search for the PNG signature
        for packet in packets:
            # Ensure the packet contains raw payload (USB communication with data)
            if packet.haslayer("Raw"):
                payload = bytes(packet["Raw"].load)
                
                # Search for the PNG start marker (The PNG signature header: 89 50 4e 47)
                png_start = payload.find(b'\x89\x50\x4e\x47')  # PNG header (89 50 4e 47)
                
                if png_start != -1:
                    # Search for the PNG end marker (IEND chunk: '49 45 4e 44')
                    png_end = payload.find(b'\x49\x45\x4e\x44', png_start)
                    
                    # Check if the end of the PNG (IEND) was found and ensure there's data after the start
                    if png_end != -1 and png_end > png_start:
                        # Extract the PNG image data (from PNG header to IEND)
                        png_data = payload[png_start:png_end + 4]  # Include the IEND marker
                        
                        # Write the extracted PNG data to a file
                        with open(output_png_file, 'wb') as f:
                            f.write(png_data)
                        print(f"PNG image extracted and saved to {output_png_file}")
                        return
    
        print("No valid PNG data found in the pcap file.")
    
    # Run the extraction function
    extract_png_from_pcap(pcap_file, output_png_file)
```

## Results

After running the script, we successfully extracted `extracted_image.png`. Opening the image revealed a hidden flag inside the picture, completing the challenge.

This gave the flag: ENO{REDACTED}

## Conclusion

This challenge demonstrated:

  * **Analyzing USB packet captures** using **Wireshark**.
  * **Recognizing embedded files** in network traffic.
  * **Extracting raw binary data** using **Scapy**.


This method can also be applied in **forensics and reverse engineering** where file extraction from network traffic is required.

### Tools Used

  * **Wireshark** (Packet analysis)
  * **Scapy** (Packet manipulation in Python)
  * **strings** (Checking extracted file contents)


### Final Thoughts

This was an interesting challenge that tested our ability to work with **USB traffic and embedded data extraction**. Understanding protocols like **USB Ethernet (NCM)** and identifying file signatures in network captures can be crucial in real-world **digital forensics and cybersecurity investigations**.

Let me know if you have any questions or suggestions!

* * *

**Author: SPECT3R**  
**Event: NullCon CTF**

### Clone this wiki locally
