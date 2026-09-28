---
title: "REPO RIDDLES - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "repo", "riddles", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "So, in this challenge we are supposed to get back to all the commits and branches and dig the folder deeply."
source:
  name: "CTFtime writeup #39521"
  url: "https://ctftime.org/writeup/39521"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Digital%20Forensics/Repo%20Riddles.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "REPO RIDDLES"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** REPO RIDDLES
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39521>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Digital%20Forensics/Repo%20Riddles.pdf>

---
So, in this challenge we are supposed to get back to all the commits and branches and dig the folder deeply.

For this git status, git log, git branch, git checkout <branch_name>, git reset –hard <commit_point>, These commands are enough to get to all the history and get all the files where flags is been hidden. The flag is hidden as a string by breaking it into multiple parts with the help of string slicing. Below are the screenshots for the same →

Viewing logs of branch master.

Going to the last commit of branch master to see the old files.

The Image got there.

Going to branch 2.

Again after checking out the commits. This are the screenshots of files got with the data  
.  
Switching to branch 3 and viewing the logs of branch 3 →

So we got all the indexes value of the string.  
The string after combining all the parts → G1tG1gger_2727

Putting this in proper flag format → VishwaCTF{G1tG1gger_2727}  
This is the required flag.

`Tip → GitLens is a free, open-source extension for Visual Studio Code that provides enhanced Git integration within the code editor. Using this extracting data becomes easier. Which helps in managing complex git repo easily.`
