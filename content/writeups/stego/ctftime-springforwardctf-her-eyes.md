---
title: "Her-Eyes - SpringForwardCTF"
category: "stego"
subcategory: "image"
type: "writeup"
tags: ["stego", "zlib", "zsteg", "forensics", "binwalk", "lsb", "image", "springforwardctf", "ctf-writeup"]
summary: "We are provided with a png image."
source:
  name: "CTFtime writeup #39116"
  url: "https://ctftime.org/writeup/39116"
ctf:
  name: "SpringForwardCTF"
  challenge: "Her-Eyes"
---

## Metadata

- **CTF:** SpringForwardCTF
- **Task:** Her-Eyes
- **Author team:** g00fy_ahh
- **CTFtime tags:** zlib, zsteg, forensics
- **CTFtime:** <https://ctftime.org/writeup/39116>

---
We are provided with a png image.

Using zsteg, we can analyze the png file.  
```  
zsteg -a her-eyes.png  
```

Looking at the zsteg results, we can see that there is some text hidden in zlib with 'b2,rgb,lsb,yx'.  
```  
b2,rgb,lsb,yx .. zlib: data="Her \xF3\xA0\x81\x8Eeyes \xF3\xA0\x81\x89stare \xF3\xA0\x81\x83at \xF3\xA0\x81\x83you \xF3\xA0\x81\xBBwatching \xF3\xA0\x81\x9Fyou \xF3\xA0\x81\x8Eclosely, \xF3\xA0\x81\xA1she \xF3\xA0\x81\xADstarts \xF3\xA0\x81\xA5cryin...", offset=61, size=279  
```

In order to extract the data, we can use the following commands:  
```  
zsteg -e 'b2,rgb,lsb,yx' her-eyes.png > output  
binwalk -e output  
```

We get the zlib file at offset 0x3D. The file is simply a text (poem?) that reads the following:  
> Her ?eyes ?stare ?at ?you ?watching ?you ?closely, ?she ?starts ?crying ?mourning ?over ?lost. ?Two ?people ?walk ?towards ?her comforting her, they're the only one who belive. Two figures approach her, their presence a beacon of solace in the darkness that surrounds her. Family by blood or bond, they offer comfort to the grieving soul before them. With gentle hands and compassionate hearts, they cradle her in an embrace of understanding and support, as though they alone comprehend the depths of her pain and stand ready to bear it alongside her.

Put the zlib file in [hexed.it](http://hexed.it), and we can see that there is some hidden text.  
Suspiciously, there are some characters in hex that are hidden between the visible text.  
Extracting all of them and converting it to utf-8 bytestring as hex gives the following:  
`NICC{_Name1_Name2}`

After reading the poem, and the file name (her_eyes_her_family.png), I guessed that the names represented her family.  
The correct flag is `NICC{_Euryale_Stheno}`, with the two names being the other two gorgons that medusa is grouped with. ( I don't know much about greek mythology )
