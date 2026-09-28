---
title: "All About Robots - NahamCon CTF 2024"
category: "web"
type: "writeup"
tags: ["robots.txt", "web", "robots", "nahamcon-ctf", "nahamcon-ctf-2024", "2024", "ctf-writeup"]
summary: "Once the challenge is started we’re pointed to a URL for a website titled “All About Robots”"
source:
  name: "CTFtime writeup #39170"
  url: "https://ctftime.org/writeup/39170"
original_source: "https://usetheswartz.com/2024/05/28/nahamcon-ctf-2024-walkthrough-all-about-robots/"
ctf:
  name: "NahamCon CTF 2024"
  year: 2024
  challenge: "All About Robots"
---

## Metadata

- **CTF:** NahamCon CTF 2024
- **Task:** All About Robots
- **Author team:** UseTheSwartz
- **CTFtime tags:** robots.txt, web
- **CTFtime:** <https://ctftime.org/writeup/39170>
- **Original writeup:** <https://usetheswartz.com/2024/05/28/nahamcon-ctf-2024-walkthrough-all-about-robots/>

---
![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-3.png?w=949>)

Once the challenge is started we’re pointed to a URL for a website titled “All About Robots”

![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-4.png?w=877>)

For this, it’s clear it’s a challenge about robots.txt, but for those who haven’t caught on, clicking on each robot will describe a bit more about the specific robot, with the “Learn More” button leading to <https://www.robotstxt.org/>, a resource for using robots.txt for websites.

For those who don’t know, the robots.txt file is a standard used by websites to instruct web crawlers which pages or sections should not be crawled or indexed. It helps manage web traffic, protect sensitive information, and control search engine indexing by specifying disallowed paths. Web crawlers check robots.txt for instructions before accessing a site.

However, robots.txt can also be a security weakness. By listing directories and files to be excluded from indexing, it inadvertently highlights potentially sensitive areas of a website to malicious actors. Adversaries can review robots.txt to find and target restricted sections, making it a valuable reconnaissance tool in cyberattacks.

![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-6.png?w=862>)

Back at the “All About Robots” webpage, we can simply modify our URL to path to the robots.txt file. Navigating to the file in our web browser shows us the user agent information and a disallow to /open_the_pod_bay_doors_hal_and_give_me_the_flag.html

![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-7.png?w=537>)

Okay, now we know where the flag actually is. Let’s path there.

![](<https://usetheswartz.com/wp-content/uploads/2024/05/image-8.png?w=1024>)

With a congratulatory confetti blast, we are given the flag.
