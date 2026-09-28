---
title: "Flowt Theory 2 - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "lfi"
type: "writeup"
tags: ["web", "lfi", "path-traversal", "flowt", "theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Target running on port 5070."
source:
  name: "CTFtime writeup #40600"
  url: "https://ctftime.org/writeup/40600"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Flowt Theory 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Flowt Theory 2
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40600>

---
**Challenge Description**:  
Target running on port 5070. Identical interface to Flowt Theory 1.

**Analysis**:  
\- **Blocked LFI**: The `view_receipt` parameter on port 5070 is protected by `basename()`.  
\- **Disk Full**: `errno=28 No space left on device` on 5070 prevents file writes (session files, receipts, fee files).  
\- **Isolation**: 5070 filesystem is separate from 5069.  
\- **Hypothesis**: The "disk full" state might be the intended puzzle. If the disk is full of *existing* files, maybe we need to guess a filename. Or if the random seed is weak, we can predict the "secret" filename.  
\- **Source Code Needed**: We need to read `index.php` from 5069 (assumed code similarity) to analyze the filename generation (`secret_<random>`).

**Solution**:  
Once the disk space issue was resolved, the exploit worked as follows:  
1\. Access the page to create a session (triggers `.lock` and `secret_*` file creation)  
2\. Read `.lock` via `view_receipt=.lock` to get the randomized secret filename  
3\. Read the secret file via `view_receipt=secret_XXXXXXXX` to get the flag

The key insight is that while `basename()` blocks directory traversal (no `../`), it allows reading files within the user's session directory, including the hidden `.lock` file which reveals the secret filename.

**Payload**:  
```  
GET /?view_receipt=.lock → Returns "secret_57VaFmLl"  
GET /?view_receipt=secret_57VaFmLl → Returns the flag  
```

**Flag**: `ENO{s33ms_l1k3_w3_h4d_4_pr0bl3m_k33p_y0ur_fl04t1ng_p01nts_1n_ch3ck}`

### Dinos

**Challenge Description**:  
The challenge involves a DNS server at `52.59.124.14:5052` and a target domain `[dinos.nullcon.net](http://dinos.nullcon.net)`. The goal is to find the hidden flag.

**Analysis**:  
\- Zone transfer (AXFR/IXFR) failed.  
\- DNSSEC was enabled, indicated by the presence of NSEC records.  
\- NSEC records reveal the "next" domain in the zone, allowing us to walk the chain and enumerate all subdomains.  
\- The subdomains appeared to be hashes (e.g., `0utyff...`), but they had TXT records attached.

**Solution**:  
1\. We wrote a script `[walk_nsec.py](http://walk_nsec.py)` to traverse the NSEC chain starting from `[dinos.nullcon.net](http://dinos.nullcon.net)`.  
2\. For each discovered domain, we queried its TXT record.  
3\. The script found a TXT record containing the flag.

**Flag**: `ENO{RAAWR_RAAAAWR_You_found_me_hiding_among_some_NSEC_DiNoS}`
