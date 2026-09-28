---
title: "Bots fbe8e05cbae04821931b785116eaf074 - PeaCTF 29514edc84b44444b4806a6808a3fc68 2020"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "bots", "fbe8e05cbae04821931b785116eaf074", "web-exploitation", "bots-fbe8e05cbae04821931b785116eaf074", "peactf-29514edc84b44444b4806a6808a"]
summary: "web writeup for \"Bots fbe8e05cbae04821931b785116eaf074\" from PeaCTF 29514edc84b44444b4806a6808a3fc68 - techniques: bots, fbe8e05cbae04821931b785116eaf074, web-exploitation, bots-fbe8e05cbae04821931b78"
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Bots%20fbe8e05cbae04821931b785116eaf074.md"
ctf:
  name: "PeaCTF 29514edc84b44444b4806a6808a3fc68"
  year: 2020
  challenge: "Bots fbe8e05cbae04821931b785116eaf074"
---

## Source

- **CTF:** PeaCTF 29514edc84b44444b4806a6808a3fc68 2020
- **Challenge:** Bots fbe8e05cbae04821931b785116eaf074
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Bots%20fbe8e05cbae04821931b785116eaf074.md>

---
# Bots

> What does a machine see?

1. Go to the link they give you
2. We can assume based on the website and the challenge name that we need to look at robots.txt

    ![Bots%20fbe8e05cbae04821931b785116eaf074/Untitled.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Bots%20fbe8e05cbae04821931b785116eaf074/Untitled.png)

3. We see that the sitemap is hidden... lets go to that

    ![Bots%20fbe8e05cbae04821931b785116eaf074/Untitled%201.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Bots%20fbe8e05cbae04821931b785116eaf074/Untitled%201.png)

4. We see a page in the <loc> tag... lets go to that
    - We get a website with the flag

        ![Bots%20fbe8e05cbae04821931b785116eaf074/Untitled%202.png](https://raw.githubusercontent.com/Adamkadaban/CTFs/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/PeaCTF%202020/PeaCTF%202020%2029514edc84b44444b4806a6808a3fc68/Bots%20fbe8e05cbae04821931b785116eaf074/Untitled%202.png)

5. The flag is peaCTF{464d34f2-549a-48e8-bf54-025f9e3b617a}
