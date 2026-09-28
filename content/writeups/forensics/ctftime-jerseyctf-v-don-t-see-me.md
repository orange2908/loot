---
title: "DoN't See Me? - JerseyCTF V"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "pcap", "scapy", "base64", "don", "see", "network", "jerseyctf-v", "ctf-writeup"]
summary: "print(\"invalid argument amount: file only\")"
source:
  name: "CTFtime writeup #40132"
  url: "https://ctftime.org/writeup/40132"
ctf:
  name: "JerseyCTF V"
  challenge: "DoN't See Me?"
---

## Metadata

- **CTF:** JerseyCTF V
- **Task:** DoN't See Me?
- **Author team:** G1tc_Gu4rdians
- **CTFtime:** <https://ctftime.org/writeup/40132>

---
* Examine PCAP file, identify strange DNS requests to random strings prepended to .domainforhire.aws.jerseyctf.com. This is DNS Exfiltration  
* Examine windows sysmon logs, given the archive clue, we can spot execution of the `makecab.exe` executeable with `flag.txt` as an argument.  
* Extract only the needed packets that are DNS packets.  
* Write a script to extracted the subdomains into one block of data from the pcap file: example below. The provided script is an example on how to do that. The script assumes you filtered out the DNS reply packets from the PCAP otherwise you will get duplicate data. The challenge also provided a script showing how the file was encoded to be sent over the network which will help in developing your solution script.  
```  
#!/usr/bin/python3

from scapy.all import *  
import base64

n = len(sys.argv)  
file =""  
if n != 2:  
print("invalid argument amount: file only")  
exit()  
else:  
file = sys.argv[1]

substring = ".domainforhire.aws.jerseyctf.com."  
subdomains = []  
data = ""

pcap=rdpcap(file)  
for packet in pcap:  
if packet.haslayer(IP):  
packet_ip = packet[IP].src  
if packet.haslayer(DNS) and packet_ip == '172.16.0.50':  
domainbyte = packet[DNS].qd.qname  
decoded = domainbyte.decode('UTF-8')  
s = decoded.split(substring)[0]  
print(s)  
data += s

raw_base64 = data.encode('UTF-8')  
base64_clean = base64.b64decode(raw_base64)  
datafile = open("extracted-file", "wb")  
datafile.write(base64_clean)  
datafile.close()  
```  
* Through the analysis above of the log file, the final data may be a cab archive. Install the cabextract tool on linux or other on your respective OS   
* Cabextract the output. The script example above outputs the data to `extracted-file` therefore `cabextract extracted-file`  
* The tool does not work. Examine the header, notice the magic bytes are 11 11 11 11.  
* Replace with the correct magic bytes: `4D 53 43 46` using a tool like hexcurse. The correct magic bytes can be googled.  
* Cabextract to get the flag. cabextract extracted-file.
