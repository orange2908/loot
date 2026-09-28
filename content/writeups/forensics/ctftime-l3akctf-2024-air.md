---
title: "Air - L3akCTF 2024"
category: "forensics"
type: "writeup"
tags: ["forensics", "air", "l3akctf", "l3akctf-2024", "2024", "ctf-writeup"]
summary: "![AIr.JPG](https://b0ra9.github.io/images/Air.jpg)"
source:
  name: "CTFtime writeup #39178"
  url: "https://ctftime.org/writeup/39178"
original_source: "https://b0ra9.github.io/posts/Air/"
ctf:
  name: "L3akCTF 2024"
  year: 2024
  challenge: "Air"
---

## Metadata

- **CTF:** L3akCTF 2024
- **Task:** Air
- **Author team:** M3l4nCh0l1C
- **CTFtime:** <https://ctftime.org/writeup/39178>
- **Original writeup:** <https://b0ra9.github.io/posts/Air/>

---
Challenge :  **`AiR`**

Categorie :  **`Forensics`**

[![AIr.JPG](https://b0ra9.github.io/images/Air.jpg)](https://b0ra9.github.io/images/Air.jpg)

We were provided with a Disk image, and we need to find the wifi Password.

If you are familiar with Windows and wireless network, or with quick search ,this path should be interesting `С:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\[**Interface** Guid]`

Going there we can get the `{E22F466D-15CE-438C-9245-B25EB9E980E5}.xml` file where the Wifi SSID name and Password are stored. Searching for how to decrypt the password leeds to a bunch of tools, most of them are useless in our case as they don’t support external profiles. Only with “WirelessKeyView” we could import an external profile,but unfortunately the decrypted password was incomplete, for some reason. Keep looking we found this tool <https://www.nirsoft.net/utils/dpapi_data_decryptor.html>

Where we can Decrypt DPAPI data from external drive and a specified string which is the keyMaterial hex string from the XML file. And we got the flag.

Flag :  **`L3AK{BL0b_D3crypt1n9_1s_n0_n3w_t0_u_r1ght?}`**

__[CTF](https://b0ra9.github.io/categories/ctf/), [Writeup](https://b0ra9.github.io/categories/writeup/)

__[ctf](https://b0ra9.github.io/tags/ctf/) [forensics](https://b0ra9.github.io/tags/forensics/)

This post is licensed under [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) by the author.

Share [ __](https://twitter.com/intent/tweet?text=L3AK%20CTF%20Forensics%20-%20MrNo0ne&url=https%3A%2F%2Fb0ra9.github.io%2Fposts%2FAir%2F "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=L3AK%20CTF%20Forensics%20-%20MrNo0ne&u=https%3A%2F%2Fb0ra9.github.io%2Fposts%2FAir%2F "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Fb0ra9.github.io%2Fposts%2FAir%2F&text=L3AK%20CTF%20Forensics%20-%20MrNo0ne "Telegram") __
