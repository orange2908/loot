---
title: "Sending Mixed Signals - NahamCon CTF 2025"
category: "forensics"
type: "writeup"
tags: ["forensics", "sending", "mixed", "signals", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "This was a deep-dive into the headlines about the picture of Mike Waltz a US government official, the unexpected public exposure of official communications from a custom Signal application."
source:
  name: "CTFtime writeup #40270"
  url: "https://ctftime.org/writeup/40270"
original_source: "https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/osint/SendingMixedSignals"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "Sending Mixed Signals"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** Sending Mixed Signals
- **Author team:** twc
- **CTFtime:** <https://ctftime.org/writeup/40270>
- **Original writeup:** <https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2025/osint/SendingMixedSignals>

---
> Solved by Starry-lord

This was a deep-dive into the headlines about the picture of Mike Waltz a US government official, the unexpected public exposure of official communications from a custom Signal application. 

In the picture, Waltz's phone screen was visibly displaying a custom Signal app, a critical tool intended for secure official communications.

![](<https://i.imgur.com/ccZH7k0.png>)

The content of these supposedly secure communications was publicly accessible.  
It was leaked because the app’s code was on GitHub, publicly available, and unfortunately holding hard-coded credentials.

Most of the info required to solve this challenge lies within this deep-dive analysis by Micah Lee : 

[Here's the source code for the unofficial Signal app used by Trump officials](<https://micahflee.com/heres-the-source-code-for-the-unofficial-signal-app-used-by-trump-officials/>)

The email of the person who committed the code with credentials can be found in the article and can be matched with the commit history.

I found the leaked credentials in `app/src/tm/java/org/archiver/ArchiveConstants.kt` file within the [open-source repository](<https://github.com/micahflee/TM-SGNL-Android/commit/7da4578dc009a7eddc7ffc471eb202d71826958e#diff-d05eb9cc6305fccd3938b1fbead418fd14e450f2c29e51b439c204be50737c64>)

Third question could be answered by matching the dates with the releases tags.

![](<https://i.imgur.com/wrDxjeo.png>)

And finally after answering all the questions correctly we get the flag : 

![](<https://i.imgur.com/9f5Un20.png>)

**Key Learning & Takeaways**

\- Open repositories must be scanned continuously for secrets before every commit  
\- Operational security lapses such as visible screens can hand attackers the exact breadcrumbs they need  
\- Combining public journalism with version-control forensics (commit diffs, tag timelines, author metadata) is a powerful, low-cost way to validate breaches and attribute responsibility.
