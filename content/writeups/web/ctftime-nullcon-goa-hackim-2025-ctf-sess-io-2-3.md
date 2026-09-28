---
title: "sess.io - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "sess", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We observe that the session ids are generated from 4 letter blocks of the flag."
source:
  name: "CTFtime writeup #40008"
  url: "https://ctftime.org/writeup/40008"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "sess.io"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** sess.io
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40008>

---
# Web/[sess.io](http://sess.io)

We observe that the session ids are generated from 4 letter blocks of the flag. But, 4 letters is not enough to be secure. We can write a php script to bruteforce all possible 4 letter combinations as shown below:

```php  
\n";  
exit(1);  
}

$target_session_id = $argv[1];  
$found_seed = brute_force_seed($target_session_id);

if ($found_seed) {  
echo "[+] Found seed: " . $found_seed . "\n";  
} else {  
echo "[-] No matching seed found.\n";  
}  
?>  
```

We collect all the unique session ids using a python script and crack all of them using this brute script and reassemble them manually to recover the flag.
