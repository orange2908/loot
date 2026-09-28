---
title: "No Comment - 1337UP LIVE CTF"
category: "crypto"
subcategory: "metadata"
type: "writeup"
tags: ["crypto", "xor", "exiftool", "exif", "cyberchef", "base64", "metadata", "1337up-live-ctf", "ctf-writeup"]
summary: "Players download an image."
source:
  name: "CTFtime writeup #39678"
  url: "https://ctftime.org/writeup/39678"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/osint/no_comment/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "No Comment"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** No Comment
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/39678>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/osint/no_comment/>

---
Players download an image.

![Image](<https://cryptocat.me/blog/ctf/2024/intigriti/osint/no_comment/images/ripple.jpg>)

Could check for embedded files or stego, or perhaps do a reverse image lookup on Google or TinEye.

In fact, the title and description is a hint! If we check the image metadata (EXIF), we'll see a comment.

```bash  
exiftool ripple.jpg  
ExifTool Version Number : 12.57  
File Name : ripple.jpg  
Directory : .  
File Size : 6.5 MB  
File Modification Date/Time : 2024:09:21 15:51:46+01:00  
File Access Date/Time : 2024:11:10 11:24:06+00:00  
File Inode Change Date/Time : 2024:11:12 11:10:15+00:00  
File Permissions : -rwxrw-rw-  
File Type : JPEG  
File Type Extension : jpg  
MIME Type : image/jpeg  
Comment : /a/pq6TgwS  
Image Width : 4032  
Image Height : 3024  
Encoding Process : Baseline DCT, Huffman coding  
Bits Per Sample : 8  
Color Components : 3  
Y Cb Cr Sub Sampling : YCbCr4:2:0 (2 2)  
Image Size : 4032x3024  
Megapixels : 12.2  
```

Recognise the comment format? It's from Imgur, where [URLs are formatted](<https://www.reddit.com/r/redditdev/comments/35bb7i/imgur_link_format>) like `[imgur.com/a/](http://imgur.com/a/){alphanumeric}` (albums) and `[imgur.com/g/](http://imgur.com/g/){alphanumeric}` (galleries).

Let's visit the [imgur link]([imgur.com/a/pq6TgwS](http://imgur.com/a/pq6TgwS)) and see the same image, along with a comment.

```  
V2hhdCBhICJsb25nX3N0cmFuZ2VfdHJpcCIgaXQncyBiZWVuIQoKaHR0cHM6Ly9wYXN0ZWJpbi5jb20vRmRjTFRxWWc=  
```

We [base64 decode it..](<[https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=VjJoaGRDQmhJQ0pzYjI1blgzTjBjbUZ1WjJWZmRISnBjQ0lnYVhRbmN5QmlaV1Z1SVFvS2FIUjBjSE02THk5d1lYTjBaV0pwYmk1amIyMHZSbVJqVEZSeFdXYz0](https://gchq.github.io/CyberChef/#recipe=From_Base64\('A-Za-z0-9%2B/%3D',true,false\)&input=VjJoaGRDQmhJQ0pzYjI1blgzTjBjbUZ1WjJWZmRISnBjQ0lnYVhRbmN5QmlaV1Z1SVFvS2FIUjBjSE02THk5d1lYTjBaV0pwYmk1amIyMHZSbVJqVEZSeFdXYz0)>)

```  
What a "long_strange_trip" it's been!

<https://pastebin.com/FdcLTqYg>  
```

Visit the [pastebin link](<https://pastebin.com/FdcLTqYg>) and find a password protected note. Enter `long_strange_trip` to uncover a hex string.

Converting from hex [doesn't work](<[https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT](https://gchq.github.io/CyberChef/#recipe=From_Hex\('Auto'\)&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT)>), so we check the users public pastes and find [this one..](<https://pastebin.com/UavLs18i>)

```  
I've been learning all about cryptography recently, it's cool you can just XOR data with a password and nobody can recover it!!

I think I've learnt enough about that now, hopefully I'll learn something new in next weeks topic: <https://specopssoft.com/blog/password-reuse-hidden-danger>  
```

Quite a hint, but at the last minute I worried this part was too guessy. We XOR the data with the same password and [get the flag](<[https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Latin1','string':'long_strange_trip'%7D,'Standard',false)&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT](https://gchq.github.io/CyberChef/#recipe=From_Hex\('Auto'\)XOR\(%7B'option':'Latin1','string':'long_strange_trip'%7D,'Standard',false\)&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT)>) :)

Flag: `INTIGRITI{[instagram.com/reel/C7xYShjMcV0](https://instagram.com/reel/C7xYShjMcV0)}`
