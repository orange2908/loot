---
title: "Clowns APT - 0xL4ugh CTF v5"
category: "osint"
type: "writeup"
tags: ["osint", "nodejs", "clowns", "apt", "0xl4ugh-ctf", "0xl4ugh-ctf-v5", "ctf-writeup"]
summary: "Welcome to my walkthrough."
source:
  name: "CTFtime writeup #40537"
  url: "https://ctftime.org/writeup/40537"
original_source: "https://youssifseliem.github.io/CTF/0xL4ugh%202026/Clowns%20APT%20(osint).html"
ctf:
  name: "0xL4ugh CTF v5"
  challenge: "Clowns APT"
---

## Metadata

- **CTF:** 0xL4ugh CTF v5
- **Task:** Clowns APT
- **Author team:** 0xL4ugh
- **CTFtime tags:** osint
- **CTFtime:** <https://ctftime.org/writeup/40537>
- **Original writeup:** <https://youssifseliem.github.io/CTF/0xL4ugh%202026/Clowns%20APT%20(osint).html>

---
# Welcome

Welcome to my walkthrough.  
This is very special for me, cuz it’s for the first time for me as `Challenge author`.  
And this is more special cuz the challenge is in `0xl4ugh CTF 2026`.  
Huge thanks to my friend [Mushroom](https://mushroom.cat/) who collaporated with me in creating this challenge.  
The challenge is solved 18 times in 41 hours.  
Congratzz to `0xfun` team for the First blood and Let’s dive into the walkthrough.

![](https://youssifseliem.github.io/assets/img/0xl4ugh26/first.png)

* * *

# Description

Hello agent 73 You have a new mission.  
We have a victim to some kind of attacks, but we aren’t sure about the full impact until now.  
This is the message we received from the victim:

“Hi, I’m a beginner nodeJS backend developer. I was practicing my skills on developing a random project.  
After I finished my work I didn’t find my work (seems to be deleted) and found this strange **image** (attached below), am i really hacked ?!!”

You only have this image, Agent 73. Do your job.

![](https://youssifseliem.github.io/assets/img/0xl4ugh26/image.png)

* * *

# Solution

This is `SOCMINT (Social Media Intelligence) challenge`

Here we are going to solve this challenge.

This won’t be just a solution, but also discussing why we used this approach to get the flag.

Let’s dive together and I hope you enjoy the challenge ;)

## foothold on the first the threat actor

When we examine the image attached well we will find many interesting info:

  * `youssifseliem` may lead us to the hacker’s identity
  * `instapoo` may lead us to a domain controlled by that APT
  * The victim is nodeJS developer


After searching for `instapoo` we didn’t find any useful information.

`instapoo` is a rabbithole and won’t lead you to a valuable info, but `youssifseliem` will.

I need to get any useful information and i only have the username: `youssifseliem`

  * using `sherlock` which is an open source tool for Hunting down social media accounts by username
  * searching through search engines like Google, bing, ….etc.


When i used `sherlock` i got results like this

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%201.png)

Not all of them will be useful of course, but github was more than enough.

Let’s visit `https://github.com/youssifseliem`

We found this github profile page

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%202.png)

We have many notes here

  * The person in the image is almost the same as in the attachment of the challenge, but without sunglasses xDDD. This means that we are on the right way and this is this person is one of our targets.
  * There are additional links in the bio to other profiles for the same user and this gives us more space to know more about him.
  * I’m not active on github recently :(((((


What can I do here?

  * I can navigate the repositories of this user’s github account, but i didn’t find an interesting repo.
  * After that I went to the links in the his bio


He shared `linkedin` , `FB` , `his personal blog` links.

His personal blog was more interesting for me.

In that blog a found more profiles for him.

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%203.png)

At this point:

  * I navigated the blog for any project related to nodeJS development (as given in the challenge description) of something useful, but i didn’t find
  * I started my deep search in his social media accounts attached in his blog.


> After going to the next step, I remind you that reaching this point can be from other paths as example you can find `X` account directly by searching on google or bing and `his personal blog link` will be right there at his bio.

## Finding the desired conversation

This search may take some time, but i prefer starting with the accounts with less activity.

So I made `FB` and `Linkedin` my last resort and started with `X` , `reddit` .

When i open reddit and look carefully i find this post.

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%204.png)

This was the second post in his profile.

The post seems to be normal but the comments are very interesting.

From the last comment i think that `youssifseliem` and `MushroomWasp` collaborated in creating a packages in the past and these packages seems to be malicious cuz they called them pranks.

and when we link the puzzle’s pieces together we will remember that in attached image in the challenge we had 2 persons, so we are likely on the right way.

## Checking Mushrooms blog

Let’s check the blog of Mushroom

When we visit his own profile on reddit we find this

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%205.png)

Let’s visit this blog and look for the challenge he was talking about which is called `stylish boss`

Mushroom has a great content btw, so i needed to search using `CTRL + F` to get the blog fast.

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%206.png)

A very valuable blog BTW, and we found out target.

Let’s check it for the package as they said earlier.

## Finding Mushroom’s packages

When we read the writeup we will see that there’s a package called `metadata-stripper` on NPM

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%207.png)

and It’s the only package mentioned in this writeup.

Let’s go to NPM for more information and after moving forward we should remember here that the victim is nodeJS developer and he suffered from a malicious as he thinks, so the package is more likely will be on `NPM` .

This makes me happy and comforts me about being on the right way.

## Reaching the target package

When we search for this package in npm we find this

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%208.png)

It’s created by `mushroomwasp`, but this package isn’t malicious as we saw in the writeup so it is not out target.

Let’s look at `mushroomswasp` npm profile.

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%209.png)

only `terminal-style-pro` is the interesting one for us, cuz `metedata-stripper` is already checked and `xsstesting` is almost empty

When we examine the source code here

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%2010.png)

and deobfuscating it we will find that it loads theme from `/lib/`path

**Note:** The code isn’t that hard to understand, you can use AI for deobfusication and understanding it.

When we go to that path and examine `theme.js` file we will find that it does the malicious action as mentioned in the challenge description like this

  * Getting the image from `.?.theme` (should be the image attached with the challenge as mentioned in the description)
  * then decodes it using b64
  * then saves it on victims machine


## Getting the flag

So this is what we are looking for

when we decode the text in `.?.theme` file we will find this image

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%2011.png)

This is totally right and this all we have uptil now.

After some time i noticed that there’s old versions of this package

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%2012.png)

when i examined `1.0.0` i found that the behavior is the same and difference is in `.?.theme` file only.

Let’s decode it now

![image.png](https://youssifseliem.github.io/assets/img/0xl4ugh26/image%2013.png)

and we got the flag

`0xL4ugh{1_th1nk_w3_c0uld_f0rm_4_g00d_4pt}`

You May Also Like
