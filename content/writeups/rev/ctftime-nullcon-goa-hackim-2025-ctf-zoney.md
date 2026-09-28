---
title: "ZONEy - Nullcon Goa HackIM 2025 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "zoney", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "dig @ec2-52-59-124-14.eu-central-1.compute.amazonaws.com -p 5007 ZONEy.eno MX"
source:
  name: "CTFtime writeup #39936"
  url: "https://ctftime.org/writeup/39936"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "ZONEy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** ZONEy
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39936>

---
```text  
dig @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 ZONEy.eno MX

; <<>> DiG 9.20.4-3-Debian <<>> @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 ZONEy.eno MX  
; (1 server found)  
;; global options: +cmd  
;; Got answer:  
;; ->>HEADER<<\- opcode: QUERY, status: NOERROR, id: 2161  
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 4  
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:  
; EDNS: version: 0, flags:; udp: 4096  
;; QUESTION SECTION:  
;ZONEy.eno. IN MX

;; ANSWER SECTION:  
ZONEy.eno. 7200 IN MX 10 challenge.ZONEy.eno.

;; AUTHORITY SECTION:  
ZONEy.eno. 7200 IN NS ns1.ZONEy.eno.  
ZONEy.eno. 7200 IN NS ns2.ZONEy.eno.

;; ADDITIONAL SECTION:  
challenge.ZONEy.eno. 7200 IN A 127.0.0.1  
ns1.ZONEy.eno. 7200 IN A 127.0.0.1  
ns2.ZONEy.eno. 7200 IN A 127.0.0.1

;; Query time: 170 msec  
;; SERVER: 52.59.124.14#5007([ec2-52-59-124-14.eu-central-1.compute.amazonaws.com](http://ec2-52-59-124-14.eu-central-1.compute.amazonaws.com)) (UDP)  
;; WHEN: Sat Feb 01 18:52:45 IST 2025  
;; MSG SIZE rcvd: 148  
```

```  
dig @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 challenge.ZONEy.eno NSEC

; <<>> DiG 9.20.4-3-Debian <<>> @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 challenge.ZONEy.eno NSEC  
; (1 server found)  
;; global options: +cmd  
;; Got answer:  
;; ->>HEADER<<\- opcode: QUERY, status: NOERROR, id: 31579  
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 3  
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:  
; EDNS: version: 0, flags:; udp: 4096  
;; QUESTION SECTION:  
;challenge.ZONEy.eno. IN NSEC

;; ANSWER SECTION:  
challenge.ZONEy.eno. 86400 IN NSEC hereisthe1337flag.zoney.eno. A RRSIG NSEC

;; AUTHORITY SECTION:  
ZONEy.eno. 7200 IN NS ns1.ZONEy.eno.  
ZONEy.eno. 7200 IN NS ns2.ZONEy.eno.

;; ADDITIONAL SECTION:  
ns1.ZONEy.eno. 7200 IN A 127.0.0.1  
ns2.ZONEy.eno. 7200 IN A 127.0.0.1

;; Query time: 170 msec  
;; SERVER: 52.59.124.14#5007([ec2-52-59-124-14.eu-central-1.compute.amazonaws.com](http://ec2-52-59-124-14.eu-central-1.compute.amazonaws.com)) (UDP)  
;; WHEN: Sat Feb 01 19:18:00 IST 2025  
;; MSG SIZE rcvd: 165  
```

```  
dig @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 hereisthe1337flag.zoney.eno txt

; <<>> DiG 9.20.4-3-Debian <<>> @ec2[-52-59-124-14.eu-central-1.compute.amazonaws.com](http://-52-59-124-14.eu-central-1.compute.amazonaws.com) -p 5007 hereisthe1337flag.zoney.eno txt  
; (1 server found)  
;; global options: +cmd  
;; Got answer:  
;; ->>HEADER<<\- opcode: QUERY, status: NOERROR, id: 18707  
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 3  
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:  
; EDNS: version: 0, flags:; udp: 4096  
;; QUESTION SECTION:  
;hereisthe1337flag.zoney.eno. IN TXT

;; ANSWER SECTION:  
hereisthe1337flag.zoney.eno. 7200 IN TXT "ENO{1337_Fl4G_NSeC_W4LK3R}"

;; AUTHORITY SECTION:  
zoney.eno. 7200 IN NS ns1.zoney.eno.  
zoney.eno. 7200 IN NS ns2.zoney.eno.

;; ADDITIONAL SECTION:  
ns1.zoney.eno. 7200 IN A 127.0.0.1  
ns2.zoney.eno. 7200 IN A 127.0.0.1

;; Query time: 170 msec  
;; SERVER: 52.59.124.14#5007([ec2-52-59-124-14.eu-central-1.compute.amazonaws.com](http://ec2-52-59-124-14.eu-central-1.compute.amazonaws.com)) (UDP)  
;; WHEN: Sat Feb 01 19:20:07 IST 2025  
;; MSG SIZE rcvd: 163  
```
