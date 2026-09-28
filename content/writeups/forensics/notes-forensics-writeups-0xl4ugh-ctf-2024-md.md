---
title: "0xL4ugh CTF 2024"
category: "forensics"
subcategory: "writeups"
type: "writeup"
tags: ["my-notes", "personal", "xor", "file-carving", "xl4ugh", "forensics"]
summary: "The description discusses the manipulation and deletion of a file."
source:
  name: "Personal notes"
origin_path: "Forensics/Writeups/0xL4ugh CTF 2024.md"
---

### Batman - The Dark Knight Solution

The description discusses the manipulation and deletion of a file. If you attempt to carve for deleted files, you’ll retrieve an `.xlsx` file containing a fake flag [this file is not in the unallocated space]. Recovering the file along with its metadata is not possible because the attacker used `Sdelete` during the deletion process. This can be confirmed by analyzing the `$LogFile`, where you’ll observe extensive overwriting activity. Since file carving won’t work, the focus should shift to artifacts that might still retain traces of the deleted file, such as:

- **Windows Search Index** (but the file size may be too large).
- **Thumbnails** (no useful results expected).
- **Caches** (no relevant data found).
- **Volume Shadow Copies**, which store previous versions of partitions. [This is the recommended approach.]

By mounting the image using **Arsenal Image Mounter** with write access permissions and using **Shadow Explorer** ([download here](https://www.shadowexplorer.com/downloads.html "download here
(https://www.shadowexplorer.com/downloads.html)")), navigate to the mounted partition. You will find a file named `file.dat` in a previous version. Cross-checking this with the `$LogFile` confirms that it is the same file that was deleted. Extracting the file and checking the Zone Identifier ADS to see where this file downloaded from to see if any manipulation happened like stating in the description. That long hex is the flag :”

---

### Batman - **Gotham's Secret**

The description discusses recovering secrets from a stolen MacBook, specifically encrypted secret notes. On macOS, notes are encrypted and stored in the Keychain. The Keychain database (`login.keychain-db`) is itself encrypted using the machine's password. Attempting to crack the Keychain password directly will not work because it is a complex password. To retrieve the machine password, one can check if the user enabled Auto Login on macOS. If Auto Login is enabled [if `/Library/Preferences/com.apple.loginwindow.plist` exists, means auto login is enabled], Also `com.apple.loginwindow.<GUID>.plist` will contain application running when autologin (One of them is keychain XD), the password is stored in the `/etc/kcpassword` file [that file is created once you enable autologin]. This file is encrypted with a static XOR key: `7D 89 52 23 D2 BC DD EA A3 B9 1F` By decrypting the contents of the `kcpassword` file with this XOR key, the machine password can be obtained. Once the machine password is recovered, it can be used to decrypt the `login.keychain-db`. Tools like [Chainbreaker](https://github.com/n0fate/chainbreaker "Chainbreaker
(https://github.com/n0fate/chainbreaker)") can assist in decrypting the Keychain database. By doing this, the encrypted note stored within the Keychain can be accessed and revealed.

---

*From your own notes: `Forensics/Writeups/0xL4ugh CTF 2024.md`*
