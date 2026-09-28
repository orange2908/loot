---
title: "HTTP Hidden Parameters (PayloadsAllTheThings)"
category: "web"
subcategory: "hidden-parameters"
type: "reference"
tags: ["payloads", "web", "wayback", "hidden-parameters", "fuzzing", "wordlists", "hidden", "parameters"]
summary: "x8 -u \"https://example.com/\" -w <wordlist>"
source:
  name: "PayloadsAllTheThings"
  url: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Hidden%20Parameters/README.md"
license: "MIT"
---

# HTTP Hidden Parameters

> Web applications often have hidden or undocumented parameters that are not exposed in the user interface. Fuzzing can help discover these parameters, which might be vulnerable to various attacks.

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
    * [Bruteforce Parameters](#bruteforce-parameters)
    * [Old Parameters](#old-parameters)
* [References](#references)

## Tools

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - Burp extension to identify hidden, unlinked parameters.
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - Hidden parameters discovery suite
* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch all the URLs that the Wayback Machine knows about for a domain
* [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) - Mining URLs from dark corners of Web Archives for bug hunting/fuzzing/further probing

## Methodology

### Bruteforce Parameters

* Use wordlists of common parameters and send them, look for unexpected behavior from the backend.

    ```ps1
    x8 -u "https://example.com/" -w <wordlist>
    x8 -u "https://example.com/" -X POST -w <wordlist>
    ```

Wordlist examples:

* [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
* [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
* [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
* [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
* [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)

### Old Parameters

Explore all the URL from your targets to find old parameters.

* Browse the [Wayback Machine](http://web.archive.org/)
* Look through the JS files to discover unused parameters

## References

* [Hacker tools: Arjun – The parameter discovery tool - Intigriti - May 17, 2021](https://web.archive.org/web/20230930093635/https://blog.intigriti.com/2021/05/17/hacker-tools-arjun-the-parameter-discovery-tool/)
* [Parameter Discovery: A quick guide to start - YesWeHack - April 20, 2022](http://web.archive.org/web/20220420123306/https://blog.yeswehack.com/yeswerhackers/parameter-discovery-quick-guide-to-start)

---

## Source

PayloadsAllTheThings - <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Hidden%20Parameters/README.md>

Mirrored into CTF-Brain at commit `3ac27901c711`. Licence: MIT. The text is the original authors' work.
