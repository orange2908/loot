---
title: "vibrations - JerseyCTF IV"
category: "hardware"
subcategory: "ics"
type: "writeup"
tags: ["hardware", "modbus", "wireshark", "tshark", "vibrations", "ics", "jerseyctf-iv", "ctf-writeup"]
summary: "1\\. Use the protocol statistics to determine that the bulk of the traffic is modbus"
source:
  name: "CTFtime writeup #38964"
  url: "https://ctftime.org/writeup/38964"
original_source: "https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#vibrations"
ctf:
  name: "JerseyCTF IV"
  challenge: "vibrations"
---

## Metadata

- **CTF:** JerseyCTF IV
- **Task:** vibrations
- **Author team:** Weak But Leet
- **CTFtime tags:** modbus, wireshark
- **CTFtime:** <https://ctftime.org/writeup/38964>
- **Original writeup:** <https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#vibrations>

---
1\. Use the protocol statistics to determine that the bulk of the traffic is modbus  
1\. There are several devices. Trial and error determines that the device with IP 10.0.2.7 is the one of interest.  
1\. The TCP payload shows the following structure: 000400000006000600[03]00[66]  
1\. We are interested in the third byte from the end, which is the position and the last byte, which contains the data value.  
1\. We also see that some times, the data value is 01 and a second message with the same position contains the actual data value.  
1\. Use the powerful string utilities in bash to extract the payload, sort it in the right order and convert to ascii values.  
1\. It can be done in a single bash command pipeline as shown here:

```  
% tshark -r final.pcapng -Y "modbus && ip.src==10.0.2.7" -T fields -e "tcp.payload" | cut -c19- | sort | grep -Ev "01$" | cut -c 5- | xxd -r -p  
jctf{I_rEllAy_H0p3_thi$_i$nt_a_p0ol_sy$t3m_aGa1n}  
```

<https://meashiri.github.io/ctf-writeups/posts/202403-jerseyctf/#vibrations>
