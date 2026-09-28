---
title: "Not Eelaborate - IrisCTF 2025"
category: "osint"
type: "writeup"
tags: ["osint", "eelaborate", "irisctf", "irisctf-2025", "2025", "ctf-writeup"]
summary: "Flag : irisctf{EdogawaKintetsuNara}"
source:
  name: "CTFtime writeup #39871"
  url: "https://ctftime.org/writeup/39871"
original_source: "https://emree-1.github.io/posts/irisctf2025-osint-not-elaborate/"
ctf:
  name: "IrisCTF 2025"
  year: 2025
  challenge: "Not Eelaborate"
---

## Metadata

- **CTF:** IrisCTF 2025
- **Task:** Not Eelaborate
- **Author team:** Ping's Got Wings
- **CTFtime:** <https://ctftime.org/writeup/39871>
- **Original writeup:** <https://emree-1.github.io/posts/irisctf2025-osint-not-elaborate/>

---
# irisCTF2025 - OSINT - Not Eelaborate  
[**Original writeup**](<https://emree-1.github.io/posts/irisctf2025-osint-not-elaborate/>)

**Flag : `irisctf{Edogawa_Kintetsu_Nara}`**

## Ressources

We were given access to Adam Holmes’ food blog, containing several articles, photos, and reviews of the restaurants he has visited. The website could be accessed via [this URL](<https://osint-food-blog-web.chal.irisc.tf/>).

The challenge description pointed to one of the reviews Adam shared on his blog. In addition, we were provided with the following image:

![Image of the challenge.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/chall_image.png>)

## Tools 

As this is an OSINT challenge we won't need any tool to solve it. We will only need a web browse, I well be using Google Chrome. 

Since this is an OSINT challenge, we didn’t require any specialized tools. A simple web browser sufficed for our needs, I opted to use `Google Chrome`.

## Resolution

### Initial Analysis 

Exploring Adam’s blog, we noticed he had shared a few articles one or two days prior, where he mentioned visiting a friend in `Japan`. This clue strongly suggested that the picture was taken somewhere in Japan.

Additionally, in the review, Adam mentioned a deer park. From this detail, we hypothesized that the restaurant in question might be located near a deer park in Japan. The fact that the restaurant served eel, as shown in the picture of the dish, further narrowed down our search criteria.

### Identifying the deer park

Our first step was to investigate well-known deer parks in Japan. The most famous, and the first to appear in our search, was `Nara Park`. Given that Adam is a tourist and `Nara Park` is one of the most popular tourist destinations in Japan, it seemed highly likely that he visited this park.

![Results of the search Famous Deerk park in Japan on Google Chrome.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/search_deer_park.png>)

### Identifying the dish

Now that we have a lead on the area where Adam likely had his eel dish, we need to identify its exact name. This step was quite straightforward: a quick search for `Japanese dish with eel` revealed that the dish in question was `Unagi` (grilled freshwater eel).  
> We could have deduced this information even faster by checking the image filename, which was `Unagi_Bowl.png`.

![Results of the search Japanese dish with eel.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/search_eel.png>)

### Pinpointing the restaurant

With a strong assumption that the location was near `Nara Park` and that Adam had `Unagi`, the next logical step was to identify a restaurant serving this dish in the area.

To do this, we used `Google Maps`:  
1\. Search for `Nara Park` to center the search area.  
2\. Search for `Unagi` within the region to list restaurants that serve eel dishes.

![Results of the search Unagi around Nara Park.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/search_nara_unagi.png>)

From this point, the process was simple: I manually browsed through the restaurant listings, checking their images to find one that matched the dish in Adam’s blog post. Fortunately, I didn’t have to search for long as one of the first results looked very promising.

![Second image that looked like Adam's picture.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/search_restaurant2.png>)

Comparing it with Adam's picture, the similarities were striking! 

![Image of the challenge.](<https://emree-1.github.io/assets/img/irisctf2025/osint/not_elaborate/chall_image2.png>)

## Conclusion

After verifying all the details, I identified the restaurant where Adam had his Unagi: `Edogawa Kintetsu Nara`.   
Interestingly, this restaurant also goes by another name: `Unagi no Nedoko Edogawa`. However, to validate the challenge, we had to use the name displayed on Google Maps.

Thank you for reading my write-up! I hope it was clear and helpful. If you liked this one and would like to see more of my work visit my [website](<https://emree-1.github.io>)!

*emree1*
