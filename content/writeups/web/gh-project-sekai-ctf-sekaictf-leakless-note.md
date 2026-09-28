---
title: "leakless note - sekaictf 2023"
category: "web"
subcategory: "xss"
type: "writeup"
tags: ["web", "xss", "leakless", "note", "web-exploitation", "leakless-note"]
summary: "web writeup for \"leakless note\" from sekaictf - techniques: xss, leakless, note, web-exploitation, leakless-note."
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/leakless-note/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "leakless note"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** leakless note
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/leakless-note/README.md>

---
## Leakless Note

| Author   | Difficulty | Points | Solves | First Blood   | Time to Blood |
| -------- | ---------- | ------ | ------ | ------------- | ------------- |
| strellic | Master (5) | 499    | 4      | Kalmarunionen | 31 hours      |

---

### Description

> This time my note application will have no leaks!
>
> [Admin Bot](https://xss-bot.chals.sekai.team/leaklessnote)
>
> ❖ **Note**  
> Flag format: SEKAI{[a-z]+}.  
> The admin bot is running Chrome v115 with incognito. Use the provided `adminbot.js` for testing.

<details closed>
<summary><b>Hint</b></summary>

1. Check the difference between a 404 search and a non 404 search carefully.
2. The intended solution uses a timing attack.

</details>

### Challenge Files

* [leaklessnote.tar.gz](https://raw.githubusercontent.com/project-sekai-ctf/sekaictf-2023/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/leakless-note/dist/leaklessnote.tar.gz)
* [adminbot.js](https://raw.githubusercontent.com/project-sekai-ctf/sekaictf-2023/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/web/leakless-note/dist/adminbot.js)
