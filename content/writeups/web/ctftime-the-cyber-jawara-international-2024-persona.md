---
title: "Persona - The Cyber Jawara International 2024"
category: "web"
type: "writeup"
tags: ["web", "persona", "the-cyber-jawara-international", "the-cyber-jawara-international-202", "2024", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #39609"
  url: "https://ctftime.org/writeup/39609"
original_source: "https://nabilmuafa.gitbook.io/notes/ctfs/2024/cyber-jawara-international-2024/misc-persona"
ctf:
  name: "The Cyber Jawara International 2024"
  year: 2024
  challenge: "Persona"
---

## Metadata

- **CTF:** The Cyber Jawara International 2024
- **Task:** Persona
- **Author team:** dimas fans club
- **CTFtime:** <https://ctftime.org/writeup/39609>
- **Original writeup:** <https://nabilmuafa.gitbook.io/notes/ctfs/2024/cyber-jawara-international-2024/misc-persona>

---
For the complete documentation index, see [llms.txt](https://writeups.nabilmuafa.com/llms.txt). This page is also available as [Markdown](https://writeups.nabilmuafa.com/ctfs/2024/cyber-jawara-international-2024/persona.md).

### Part 1

We were given a website, <https://persona.chall.cyberjawara.pro/>. The website is a simple personal page.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FmpnM69GkixS7olmPtgqG%252Fimage.png%3Falt%3Dmedia%26token%3D15156a4a-8c1e-4b30-88de-22f8514bf8e0&width=768&dpr=3&quality=100&sign=b542a47781065c9174a7420cfb9b1774&sv=3)

The persona challenge page.

Upon inspecting the website source code, apparently there's a hidden part of the flag commented in the HTML. We'll get back to this later.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FdOQxnjiXinZN9EJGVqZH%252Fimage.png%3Falt%3Dmedia%26token%3Df94fbb56-e650-4fb5-a052-b89967270169&width=768&dpr=3&quality=100&sign=8f4ad811f49278ae8cf0e850772a4323&sv=3)

Part 1 of the flag.

### Part 2

Entering the [facebook page](https://www.facebook.com/people/Edina-Salmin/pfbid0s9AaRGiT12idietcjjJFYjJfnG7nDyNb4wSd6w1EHSLnmTBJwzbKWa6nLCkFJjpCl/) from the website, there's not so much information because the user has no friends (literally). The user only has a few posts. The interesting ones are only those with pictures.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FV4hFsNQDN5GKYXyavZ9S%252Fimage.png%3Falt%3Dmedia%26token%3D61c93f62-1c03-4c44-b48c-5d979d4dbff1&width=768&dpr=3&quality=100&sign=9fbc4b80407e23648d340ef961584300&sv=3)

The user's photos.

The most interesting one is the Visual Studio Code screenshot.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FHhbCmH3LXxAArwrYYi4W%252Fimage.png%3Falt%3Dmedia%26token%3Dd5217778-c87c-4a8c-9125-0f246046e9ca&width=768&dpr=3&quality=100&sign=e7875d8e7c181404452052faa44d95e0&sv=3)

The VSCode screenshot.

At first, I thought the next step would be going to the APP_ID or APP_SECRET and do some OSINT to find the Facebook app metadata. But it turns out that the code in this screenshot is a clone from [this GitHub](https://github.com/fideloper/Generic-Facebook-App/blob/master/app.php). So this is a red herring. Upon closer inspection, there is a pastebin link on the bottom left terminal.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252F3zKejmzrXuxRWcgScqhB%252Fimage.png%3Falt%3Dmedia%26token%3De5f664ec-c8c8-4810-ad38-af5a9220bd9a&width=768&dpr=3&quality=100&sign=f60f736b7d02ae249852fe7db6f398cb&sv=3)

Truncated pastebin link.

Although promising, this link turned out to be truncated, because the URL leads to a 404 response (I also felt like this link doesn't have the usual pastebin link length). The usual pastebin link has 8 characters as its ID on the path, so I created a script to bruteforce all alphanumeric characters, append them to the link, and find which link leads to 200 response.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FIoXVGakn2AVTzlEetdAW%252Fimage.png%3Falt%3Dmedia%26token%3D0377c589-7be3-4f3f-b813-6e4e9f13d736&width=768&dpr=3&quality=100&sign=f8aec92942d38325a3f98ac4728d93dd&sv=3)

The result of running the script.

Opening the page gives us the second part of the flag.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252FVNHK1GakjCWVMiy7T0uA%252Fimage.png%3Falt%3Dmedia%26token%3D8699eb70-0344-46af-a877-360fd552160f&width=768&dpr=3&quality=100&sign=dc8afbd749ef22618f0444d83f12a7d8&sv=3)

The second part of the flag.

### Part 3

Looking for the third part took me quite some time. I searched social medias with the keyword "Edina Salmin", tried Google dorking, searching in DuckDuckGo, but none give any result. Then I got curious, maybe the personal website has another path that contains the flag? I tried going to the /flag endpoint and found something interesting.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252F3BAzwe6guoIboz6h0fha%252Fimage.png%3Falt%3Dmedia%26token%3De9d10fb2-6695-4003-a4a5-4575cf5dd52a&width=768&dpr=3&quality=100&sign=ffbd80dbbda593a18ff08e655989e992&sv=3)

The 404 page of /flag.

The personal page is hosted on GitHub, just with a custom domain. It means there might (must) be a GitHub repository and account hosting it. I dig'd the website to find its original URL (the .github.io URL) and found `edsalmin.github.io`.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252F3AGpiqumeBkeKnGF1XNu%252Fimage.png%3Falt%3Dmedia%26token%3Ddd9ced12-d3d3-41e4-9e6a-3ffe8f19c6dd&width=768&dpr=3&quality=100&sign=52198cbccd76a6dec40a20fa9ee3fd76&sv=3)

Dig-ing the website using the web interface.

It means that the user's GitHub account username is `edsalmin`. Upon stalking the GitHub account, I found the [repository to the personal page](https://github.com/edsalmin/edsalmin.github.io). Checking the first or second commit of the repository gives us the third part of the flag. Initially, this was the information supposed to be hidden in the personal page, but changed into part one.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252F1JZU1C9YWbmJAmOqii7i%252Fimage.png%3Falt%3Dmedia%26token%3Ddfb51890-0590-4c60-8282-91b6187c67e5&width=768&dpr=3&quality=100&sign=b089b1c89eed53816c36e51644943e17&sv=3)

The third part of the flag.

### Part 4

After the third part, I was stuck for some time, until my teammate daffainfo assisted in finding the fourth part. The fourth part of the flag was hidden (not so hidden, actually) in `edsalmin`'s gist.<https://gist.github.com/edsalmin>. I also got some insight here: If an OSINT challenge requires us to check for a GitHub account, also check its gist; we might find some interesting information.

![](https://writeups.nabilmuafa.com/~gitbook/image?url=https%3A%2F%2F342791235-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252F1WOe8LWkgVETvxzQBCqw%252Fuploads%252F57RiznKXtknCx0l9Mk8C%252Fimage.png%3Falt%3Dmedia%26token%3Dd85a028f-07de-43c9-96b0-6c2cfd83c97c&width=768&dpr=3&quality=100&sign=7b6039e0c8508b811812a37dbb56e343&sv=3)

The fourth and final part of the flag.

Gathering all the parts, we have the flag.

Last updated 1 year ago
