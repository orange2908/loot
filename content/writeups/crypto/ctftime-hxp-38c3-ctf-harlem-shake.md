---
title: "HaRlEm ShAkE - hxp 38C3 CTF"
category: "crypto"
subcategory: "rust"
type: "writeup"
tags: ["crypto", "rust", "poly1305", "chacha20", "harlem", "shake", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Sun, 29 December 2024 ~ sandr0"
source:
  name: "CTFtime writeup #39732"
  url: "https://ctftime.org/writeup/39732"
original_source: "https://hxp.io/blog/112/hxp-38C3-CTF-HaRlEm-ShAkE/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "HaRlEm ShAkE"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** HaRlEm ShAkE
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39732>
- **Original writeup:** <https://hxp.io/blog/112/hxp-38C3-CTF-HaRlEm-ShAkE/>

---
Sun, 29 December 2024 ~ sandr0

## hxp 38C3 CTF: HaRlEm ShAkE

REV, MSC (500 points, 11 solves)

Here we explain some solutions for the reversing challenge [HaRlEm ShAkE](https://2024.ctf.link/internal/challenge/168a3050-bd0b-4053-930a-366d0fe82294/) from our recent CTF.

It is a Rust binary using x11rb to move around windows on the screen and display a flag in plain sight.

### Source code

Find the source code for this reversing challenge on [GitHub](https://github.com/Sandr0x00/harlem_shake).

### Description

[Related°](https://www.youtube.com/watch?v=4hpEnLtqUDg)

°(not actually related)

### Reversing

We’ll go directly into the main method and see some setup until we arrive at a long list of function calls to `sub_942E0` with changing parameters.

![Function calls](https://hxp.io/assets/data/posts/112-harlem/calls.png)

Analyzing `sub_942E0`, we first see a hardcoded key `91b16ca0da5d332cb9909596be5f6918f0e11956f55685f111d105c4a5ec5f58` as well as a string `Stop patching pls :(`. This is triggered if we patch the given blobs of data passed to the function or the key itself so the decryption fails.

Starting the program changes the position and size of all X11 windows. I’m running on Sway, so that doesn’t affect me, but we can also skip that call in the debugger.

We then set a breakpoint in `sub_942E0` and let the program decrypt the image for us. The first image a `{` character.

Well, this seems tedious, why don’t we just decrypt the images ourselves?

We know all offsets as seen in the screenshot above. We also know the key, and the constant `expand 32-byte k` gives us a hint we might be using using Salsa20/ChaCha20.

We see that the decrypt function is called with a 12 byte offset.

![Decrypt](https://hxp.io/assets/data/posts/112-harlem/decrypt.png)

12 bytes nonce length are default for ChaCha20, so let’s just try ChaCha20-Poly1305[1](https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html) and it works out of the box. The first image decodes correctly.

Now we automate it for all character-images and place them to the wanted positions (which are also passed into `sub_942E0`).

We also found this string in the binary: `Screen too small :(, min size 1900 x 900`. These values we use to create our image.

Solve Script:

```
    from Crypto.Cipher import ChaCha20_Poly1305
    from iced_x86 import *
    import re
    from PIL import Image
    from io import BytesIO
    
    image = Image.new("RGB", (1900, 900), "black")
    
    with open("harlem_shake", "rb") as f:
        executable = f.read()
    key = executable[0x19DCC6:0x19DCE6]
    
    def decrypt(img_off, img_len, x, y):
        nonce = executable[img_off:img_off + 12]
        img = executable[img_off + 12: img_off + img_len]
    
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        char_img = Image.open(BytesIO(cipher.decrypt(img)))
    
        image.paste(char_img, (x, y))
    
    img_off = 0
    img_len = 0
    img_pos_x = 0
    img_pos_y = 0
    
    code_offset = 0x95609
    code_end = 0x95D43
    for instr in Decoder(64, executable[code_offset:code_end], ip=0):
        # yolo regex matching just works
        if m := re.match(r"lea rcx,\[(?P<off>\w+)h\]", str(instr)):
            img_off = int(m.group("off"), 16) + code_offset
        if m := re.match(r"mov r8d,(?P<len>\w+)h", str(instr)):
            img_len = int(m.group("len"), 16)
        if m := re.match(r"mov esi,(?P<x>\w+)h", str(instr)):
            img_pos_x = int(m.group("x"), 16)
        if m := re.match(r"mov edx,(?P<y>\w+)h", str(instr)):
            img_pos_y = int(m.group("y"), 16)
        if m := re.match(r"call 0FFFFFFFFFFFFECD7h", str(instr)):
            decrypt(img_off, img_len, img_pos_x, img_pos_y)
    
        if instr.ip > (code_end - code_offset):
            break
    
    image.save("flag.png")
```

![Flag](https://hxp.io/assets/data/posts/112-harlem/flag.png)

`hxp{Alw4ys_ha5_b3en_oN_y0ur_ScrE3n}`

Alternative solution and what is actually going on:

What the program actually does is putting all character images together into one big image and then sending this image to the XServer creating a clickable region.

Meaning: You can click through everything except the characters itself. You might have seen this when hovering over certain areas that “randomly” your mouse changes when `harlem_shake` is running.

Using tools like XScope, or adding logging in XServer, you can just read out the requests and get the flag.
