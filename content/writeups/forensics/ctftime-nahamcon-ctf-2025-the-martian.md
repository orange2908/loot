---
title: "The Martian - NahamCon CTF 2025"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "foremost", "martian", "disk", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "In this challenge we get a binary file."
source:
  name: "CTFtime writeup #40284"
  url: "https://ctftime.org/writeup/40284"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/misc/TheMartian"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "The Martian"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** The Martian
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40284>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/misc/TheMartian>

---
> Solved by thewhiteh4t

In this challenge we get a binary file. Running `file` command did not help because magic bytes of header and footer were corrupt. So I tried to use `hexdump -C` command to check its contents and magic bytes. At the time of solving idea was that most probably multiple files were concatenated into one file, so I used `binwalk` to extract available files :

binwalk -e challenge.martian

![](<https://i.imgur.com/x92plLw.png>)

So binwalk found multiple `bzip` archives and extracted them in one go, in the next image we can see the extracted directories and inside one of the directories we get a `decompressed.bin`, this is the default naming convention of binwalk so to find actual type of the file we can again use `file` command, and we can see that it's a `JPEG` image

![](<https://i.imgur.com/7CIe5IO.png>)

So I renamed the file and opened it in a gallery viewer : 

![](<https://i.imgur.com/liCEDQ3.jpeg>)

**Key Learning and Takeaways**

\- Tools complexity : Our first instinct is always using the `file` command, but when it did not work we switched to `hexdump`, letting us inspect raw bytes of the file. You start looking for patterns, weird sequences, or signs of something that should be there but isn't.  
\- The "Concatenated Files" : Seeing weird junk in `hexdump` often means one thing, you've got multiple files or the given file might be corrupt. This was our big guess, and it's a super common CTF trick.  
\- Enter binwalk : It's an incredible tool for exactly this scenario. It scans a file, looking for known file "signatures" (those magic bytes we talked about) and extracts them. Another similar tool is `foremost`.
