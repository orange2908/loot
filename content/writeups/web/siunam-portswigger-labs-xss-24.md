---
title: "xss 24 - portswigger labs"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "web-exploitation", "xss-24", "portswigger-labs", "siunam321"]
summary: "web writeup for \"xss 24\" from portswigger labs - techniques: xss, web-exploitation, xss-24, portswigger-labs, siunam321."
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-24/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-24/README.md"
ctf:
  name: "portswigger labs"
  challenge: "xss 24"
---

## Source

- **CTF:** portswigger labs
- **Challenge:** xss 24
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/portswigger-labs/Cross-Site-Scripting/xss-24/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/portswigger-labs/Cross-Site-Scripting/xss-24/README.md>

---
# Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped | Jan 1, 2023

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped), you'll learn: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

## Exploitation

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052054.png)

In here, we can see there is a search box.

Let's search something:

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052115.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052137.png)

As you can see, our input is reflected in the web page.

**View source page:**
```html
<section class=blog-header>
    <h1 id="searchMessage"></h1>
    <script>
        var message = `0 search results for 'test'`;
        document.getElementById('searchMessage').innerText = message;
    </script>
    <hr>
</section>
```

In here, the `innerText` sink is equal to `message`, **which is a JavaScript template literal.**

Literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. **Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the backticks and `${}`:**

**From [Mozilla web docs](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals):**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052709.png)

**Therefore, we can inject a JavaScript template literal:**
```js
${alert(document.domain)}
```

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052904.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/Portswigger-Labs/Cross-Site-Scripting/XSS-24/images/Pasted%20image%2020230101052912.png)

# What we've learned:

1. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
