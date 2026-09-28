---
title: "Twine - NahamCon CTF 2024"
category: "stego"
subcategory: "metadata"
type: "writeup"
tags: ["stego", "hexeditor", "steganography", "hidden", "exif", "twine", "metadata", "nahamcon-ctf", "nahamcon-ctf-2024", "2024", "ctf-writeup"]
summary: "Steganography challenges are always fun, as is the case with Twine."
source:
  name: "CTFtime writeup #39169"
  url: "https://ctftime.org/writeup/39169"
original_source: "https://usetheswartz.com/2024/05/28/nahamcon-ctf-2024-walkthrough-twine/"
ctf:
  name: "NahamCon CTF 2024"
  year: 2024
  challenge: "Twine"
---

## Metadata

- **CTF:** NahamCon CTF 2024
- **Task:** Twine
- **Author team:** UseTheSwartz
- **CTFtime tags:** hexeditor, steganography, hidden
- **CTFtime:** <https://ctftime.org/writeup/39169>
- **Original writeup:** <https://usetheswartz.com/2024/05/28/nahamcon-ctf-2024-walkthrough-twine/>

---
Steganography challenges are always fun, as is the case with Twine.

For those who don’t know, steganography is the practice of concealing a message, image, or file within another message, image, or file. Unlike encryption, which protects the content of a message, steganography hides the existence of the message itself. This makes it a valuable tool for covert communication.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-17.png?w=864>)

Downloading twine.jpg, you get this image:

![](<https://usetheswartz.com/wp-content/uploads/2024/05/twine.jpg?w=328>)

Nothing crazy, just a bundle of twine. It’s easy in challenges like this to get carried away and start downloading toolkits and start trying to crack into images. Often times, these are not set up to be that difficult on the first go. Let’s start with a beginner’s approach and head to more technical methods as we progress.

So first up, just playing with the image in an image editor. This was something that I missed on a CTF last year and spent over an hour trying to figure out the metadata and open it in various tools when the answer was simply, “What if it was brighter or darker”.

![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-18.png?w=370>)  
Okay, so no luck there. It makes sense. There isn’t a lot of space to hide a flag in the visual space of the image, so let’s keep going. Let’s try our next step, looking at the file’s metadata.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-19.png?w=1024>)

So looking at it using the file command tells us what kind of file it is. Kind of a “No duh” moment, but it’s important to note that we can change file extensions to whatever we want. It could be a .dll that’s really a .png but without verifying, we would have no way of knowing. Okay, so let’s look at it’s exif data.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-20.png?w=995>)

Okay, no flag there. This could be useful if it had more EXIF data like a location or what camera it was shot on, but nothing of note here.

Moving up in our technical scale, let’s try using a hex editor to look at the image. HxD is a great tool on Windows for viewing and modifying hexidecimal data.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-21.png?w=1024>)

So we’ll press Control + F and look for the text string “flag”.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-22.png?w=403>)

And that seems to do the trick.  
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-23.png?w=1024>)

All we have to do is copy that flag and paste it back into the challenge and we’re good to move on. This challenge is an excellent opportunity to develop routines and workflows for different types of problems. It’s not always necessary to jump to the most complex solution when simply checking the basics will solve a good percentage of the challenges.
