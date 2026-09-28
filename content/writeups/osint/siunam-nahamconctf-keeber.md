---
title: "Keeber - nahamconctf 2022"
category: "osint"
subcategory: "stack"
type: "writeup"
tags: ["osint", "buffer-overflow", "wayback", "keeber", "stack", "open-source-intelligence"]
summary: "In this challenge we'll have to use our OSINT skills!"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/nahamconctf2022/OSINT/Keeber/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/OSINT/Keeber/README.md"
ctf:
  name: "nahamconctf"
  year: 2022
  challenge: "Keeber"
---

## Source

- **CTF:** nahamconctf 2022
- **Challenge:** Keeber
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/nahamconctf2022/OSINT/Keeber/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/nahamconctf2022/OSINT/Keeber/README.md>

---
# Keeber 1
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/background.png)

In this challenge we'll have to use our OSINT skills!

According to the challenge's description, we need to investigate the `Keeber Security Group`! The first thing we need to do is **find the person who registered their domain.**

Next, I googled `Keeber Security Group`, and we indeed found their company's website!

![google1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/google1.png)

![google2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/google2.png)

In order to find their domain register, we can use `whois` command.

![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/solution1.png)

![solution2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/solution2.png)

Wow! we can see the flag!! Let's pipe it to `grep` command, so we can see the flag better.

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/1/flag.png)


# Keeber 2
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/2/background.png)

In the part 2 of Keeber challenge, we need to find their ex-employee from their website!

Let's head over to their `Team` page and copy the URL. Then use [`WaybackMachine`](https://archive.org/web/) to view all of their website's archive!

![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/2/solution1.png)

![solution2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/2/solution2.png)

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/2/flag.png)

Yes!! We found their ex-employee and the flag!


# Keeber 3
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/background.png)

In the part 3 of Keeber challenge, we need to find their company's **github page**, and see are there any **secret stuff on their repositories commits.**

Let's use google to find their github page!

![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution1.png)

![solution2](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution2.png)

![solution3](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution3.png)

Yes!! We found their secret commits, `added .gitignore`, in their `security-evaluation-workflow repository`!

Looks like `keeber-tiffany` uploaded a file called `asana_secret.txt` and inside the file, it has a key? `[REDACTED-ASANA-PAT]`

After I banging my head on this commit. I realized that the file name is a company name! `asana`.

> **"Asana is a web and mobile work management platform designed to help teams organize, track, and manage their work."**

Then, I created an asana account to dig deeper what's the key doing.

![solution4](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution4.png)

![solution5](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution5.png)

Hmm... It's used for Personal access token. Let's do some research on their [document](https://developers.asana.com/docs/personal-access-token)!

![solution6](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/solution6.png)

Looks like we can use `asana_secret.txt` token to authenticate! Let's use the `curl` command that Asana provided!

`curl https://app.asana.com/api/1.0/users/me -H "Authorization: Bearer [REDACTED-ASANA-PAT]"`

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/3/flag.png)

Yes!! We've got the flag again!


# Keeber 5
![background](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/5/background.png)

In the part 5 of Keeber challenge, we'll need to **find one of the commits which reveals his/her personal email!**

Next, I googled `github commit email lookup`, and I found a solution from [Stack Overflow](https://stackoverflow.com/questions/42957392/how-to-see-contributors-email-address-on-git-commit-chain). It said:

> **"you can add `.patch` to the end of the commit url to open patch view."**

Then, let's check each of their commits one by one!

![solution1](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/5/solution1.png)

![flag](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/NahamCon-CTF-2022/OSINT/Keeber/images/5/flag.png)

Finally!! We found the flag from `started code_reviews.txt` commit!



> **I didn't solved Keeber 4, 6-8, so there will be no writeup for those part.**
