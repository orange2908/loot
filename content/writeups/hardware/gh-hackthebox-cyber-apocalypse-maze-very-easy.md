---
title: "Maze [Very Easy] - cyber apocalypse 2024"
category: "hardware"
subcategory: "heap"
type: "writeup"
tags: ["hardware", "fsop", "maze", "easy", "heap", "embedded"]
summary: "hardware writeup for \"Maze [Very Easy]\" from cyber apocalypse - techniques: fsop, maze, easy, heap, embedded."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/Maze%20%5BVery%20Easy%5D/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "Maze [Very Easy]"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** Maze [Very Easy]
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/Maze%20%5BVery%20Easy%5D/README.md>

---
![img](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png)

<img src='https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Maze</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: WizardAlfredo

Challenge Author(s): WizardAlfredo

Difficulty: <font color=green>Very Easy</font>

Classification: Official

# Synopsis

- Read a PDF from a printer's filesystem

## Description

- In a world divided by factions, "AM", a young hacker from the Phreaks, found himself falling in love with "echo," a talented security researcher from the Revivalists. Despite the different backgrounds, you share a common goal: dismantling The Fray. You still remember the first interaction where you both independently hacked into The Fray's systems and stumbled upon the same vulnerability in a printer. Leaving behind your hacker handles, "AM" and "echo," you connected through IRC channels and began plotting your rebellion together. Now, it's finally time to analyze the printer's filesystem. What can you find?

## Skills Required

- Basic folder navigation.

## Skills Learned

- Learn the file system structure of a printer.

# Enumeration

## Analyzing the files

In this challenge we only get a downloadable. If we do a simple `tree` command
we will get the following folders and a file called Factory.pdf.

```bash
fs
├── PJL
├── PostScript
├── saveDevice
│   └── SavedJobs
│       ├── InProgress
│       │   └── Factory.pdf
│       └── KeepJob
└── webServer
    ├── default
    │   └── csconfig
    ├── home
    │   ├── device.html
    │   └── hostmanifest
    ├── lib
    │   ├── keys
    │   └── security
    ├── objects
    └── permanent
```

Let's delve into the file structure of a HP laserjet printer's filesystem. There are four main directories: `PJL`, `PostScript`, `saveDevice`, and `webServer`.

- `PJL` and `PostScript`: These directories typically contain files related to Printer Job Language (PJL) and PostScript, respectively. PostScript is a page description language commonly used in printing and desktop publishing.

- `webServer`: This folder holds files associated with the printer's web server functionality.

- `saveDevice`: This directory is our primary focus, as it manages print jobs on the printer. Specifically:
    - `SavedJobs`: This subdirectory has two further subdirectories:
        - `InProgress`: Contains jobs currently being processed or printed.
        - `KeepJob`: Contains completed jobs retained for future reference.

# Solution: 

## Getting the Flag

Upon inspection of the `InProgress` directory, we find a PDF named Factory.pdf. Let's open it and retrieve the flag.

![image-20240314210808496](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/hw/Maze%20[Very%20Easy]/assets/image-20240314210808496.png)
