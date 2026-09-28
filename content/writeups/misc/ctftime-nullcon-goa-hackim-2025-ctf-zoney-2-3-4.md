---
title: "ZONEy - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "nmap", "zoney", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "$ echo -e \"HELO test\\r\\n\" | nc -u -v 52.59.124.14 5007"
source:
  name: "CTFtime writeup #39872"
  url: "https://ctftime.org/writeup/39872"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "ZONEy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** ZONEy
- **Author team:** BrHackeuses
- **CTFtime:** <https://ctftime.org/writeup/39872>

---
We first did :   
```  
$ echo -e "HELO test\r\n" | nc -u -v 52.59.124.14 5007  
Connection to 52.59.124.14 5007 port [udp/*] succeeded!  
HED  
```  
This returned a very strange response. So, we basically scanned the IP and port given in the challenge using`nmap` and `dig`.

We first found :   
```  
$ dig @52.59.124.14 -p 5007 ZONEy.eno MX  
ZONEy.eno. 7200 IN MX 10 challenge.ZONEy.eno.  
```

Then, we tried bruteforcing all DNS records using the following script :   
```  
#!/bin/bash  
dns_records=(  
"A" "AAAA" "CNAME" "MX" "TXT" "NS" "SOA"  
"SRV" "PTR" "SPF" "CAA" "ANY" "NAPTR" "HINFO"  
"MINFO" "RP" "DNAME" "SSHFP" "TLSA" "DS" "RRSIG"  
"PX" "X25" "ISDN" "A6" "SMIMEA" "OPENPGPKEY" "URI"  
"TKEY" "TSIG" "SIG" "NSEC"  
)  
dig_query() {  
local domain=$1  
local record_type=$2  
echo "[-] Querying $record_type record for $domain..."

result=$(dig -p 5007 @52.59.124.14 +short "$domain" "$record_type")

if [[ -n "$result" ]]; then  
echo "[+] $record_type Record for $domain:"  
echo "$result"  
echo  
else  
echo "[-] No $record_type record found for $domain"  
echo  
fi  
}  
read -p "Enter the domain to query: " domain  
echo  
for record in "${dns_records[@]}"; do  
dig_query "$domain" "$record"  
done  
```  
This gave us the output :   
```  
[+] NSEC Record for challenge.ZONEy.eno:  
hereisthe1337flag.zoney.eno. A RRSIG NSEC  
"ENO{1337_Fl4G_NSeC_W4LK3R}"  
```  
And flag!
