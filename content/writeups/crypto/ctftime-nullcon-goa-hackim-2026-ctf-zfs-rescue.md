---
title: "ZFS rescue - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "gcm", "zfs", "rescue", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "We are given a corrupted ZFS image nullcongoarescued.img containing flag.txt."
source:
  name: "CTFtime writeup #40594"
  url: "https://ctftime.org/writeup/40594"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "ZFS rescue"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** ZFS rescue
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40594>

---
**Challenge Description**:  
We are given a corrupted ZFS image `nullcongoa_rescued.img` containing `flag.txt`. The dataset is encrypted, and the passphrase is known to be in `rockyou.txt`.

**Analysis**:  
The image does not import cleanly, so we parse ZFS on-disk structures directly. The pool labels and uberblocks are present, but the data region starts at an offset (`BASE_OFFSET=0x400000`).  
The MOS (Meta-Object-Set) can be read from the newest uberblock. From the MOS we locate the root DSL dataset, then traverse its child map to find the encrypted dataset `flag`.  
The flag dataset stores a crypto key object in its DSL dir ZAP (`com.datto:crypto_key_obj`), which contains:  
`DSL_CRYPTO_SUITE` (AES-256-GCM), `GUID`, `IV`, `MAC`, `MASTER_KEY_1`, `HMAC_KEY_1`, `pbkdf2salt`, `pbkdf2iters`, and `keyformat=passphrase`.  
The wrapped master+HMAC keys are decrypted with AES-GCM using a wrapping key derived by PBKDF2-HMAC-SHA1 from the passphrase.

**Solution**:  
1\. Scan the label area for uberblocks and select the highest TXG.  
2\. Decode the root BP, read and parse the MOS.  
3\. From MOS object directory, resolve `root_dataset` and then the child map.  
4\. Find dataset `flag`, read its DSL dir ZAP to get `com.datto:crypto_key_obj`.  
5\. Parse the key ZAP, extract crypto params and wrapped keys.  
6\. Brute force the passphrase from `rockyou.txt` by attempting AES-GCM unwrap.  
7\. With the correct passphrase, derive the wrapping key and unwrap `MASTER_KEY_1` and `HMAC_KEY_1`.  
8\. Decrypt encrypted data blocks in Python using AES-GCM with a per-block key derived by HKDF-SHA512(master_key, salt).  
9\. Read the dataset objset, resolve `ROOT`, and extract `flag.txt`.

**Implementation Notes**:  
We used a custom parser in `misc/ZFS_rescue/[solve_zfs_rescue.py](http://solve_zfs_rescue.py)` to decode BPs, dnodes, and ZAPs. Decompression uses libzpool (LZ4/LZJB/ZLE).  
Libzpool crypto APIs were unstable in userland, so final decryption uses Python AES-GCM with parameters decoded from blkptrs.

**Passphrase**: `reba12345`

**Flag**: `ENO{you_4r3_Truly_An_ZFS_3xp3rt}`
