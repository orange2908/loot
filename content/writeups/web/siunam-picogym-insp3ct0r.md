---
title: "Insp3ct0r - picoGym"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "insp3ct0r", "web-exploitation", "picogym", "siunam321"]
summary: "web writeup for \"Insp3ct0r\" from picoGym - techniques: insp3ct0r, web-exploitation, picogym, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/picoGym/Web-Exploitation/Insp3ct0r/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoGym/Web-Exploitation/Insp3ct0r/README.md"
ctf:
  name: "picoGym"
  challenge: "Insp3ct0r"
---

## Source

- **CTF:** picoGym
- **Challenge:** Insp3ct0r
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/picoGym/Web-Exploitation/Insp3ct0r/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/picoGym/Web-Exploitation/Insp3ct0r/README.md>

---
# Insp3ct0r | Mar 3, 2023

## Introduction

Welcome to my another writeup! In this picoGym [challenge](https://play.picoctf.org/practice/challenge/18?category=1&page=1&solved=0), you'll learn: Inspecting HTML! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Author: zaratec/danny

Description

Kishor Balan tipped us off that the following code may need inspection: 

`https://jupiter.challenges.picoctf.org/problem/44924/` ([link](https://jupiter.challenges.picoctf.org/problem/44924/)) or http://jupiter.challenges.picoctf.org:44924

## Enumeration

Home page:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/picoGym/Web-Exploitation/Insp3ct0r/images/Pasted%20image%2020230303175505.png)

Pretty empty.

**Let's view source page:**
```html
[...]
  <head>
    <title>My First Website :)</title>
    <link href="https://fonts.googleapis.com/css?family=Open+Sans|Roboto" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="mycss.css">
    <script type="application/javascript" src="myjs.js"></script>
  </head>
[...]
	<!-- Html is neat. Anyways have 1/3 of the flag: picoCTF{tru3_d3 -->
[...]
```

In here, we found the first 3 parts of the flag: `picoCTF{tru3_d3`.

In the `<head>` element, we also see that there are **2 files are being imported: `mycss.css`, `myjs.js`.**

**mycss.css:**
```css
[...]
#tabintro { background-color: #ccc; }
#tababout { background-color: #ccc; }

/* You need CSS to make pretty pages. Here's part 2/3 of the flag: t3ct1ve_0r_ju5t */
```

**myjs.js:**
```js
[...]
window.onload = function() {
    openTab('tabintro', this, '#222');
}

/* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?f10be399} */
```

We found all 3 parts!

- **Flag: `picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?f10be399}`**

# What we've learned:

1. Inspecting HTML
