---
title: "CRACK ME - VishwaCTF 2024"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "ghidra", "crack", "static-analysis", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Run the .exe file and you’ll be prompted for a username and password."
source:
  name: "CTFtime writeup #39512"
  url: "https://ctftime.org/writeup/39512"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Crack%20Me.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "CRACK ME"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** CRACK ME
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39512>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Crack%20Me.pdf>

---
Solution:  
* Initial Exploration:

Run the .exe file and you’ll be prompted for a username and password.  
Using the strings command, we found:  
Username: bank  
Password: BANK101  
* Analyzing with Ghidra:

We noticed that a hidden vault function is triggered when the choice is 0x1a4 (which is 420 in decimal).  
While analyzing the vault function, there was a suspicious condition where temp24 == 0, but it was initially set to -99. Changing this to 0 resolves part of the issue.  
The "error" variable (0xffffff9b) also seemed significant, so we took note of it.  
* Discovering the Flag:

In case 1 of the .exe, the flag is formed by concatenating multiple strings into the ans variable.  
The flag output was incorrectly being printed from an empty temp variable. We modified this to print ans instead.  
Additionally, _temp24 was updated to 99999999, which did not make sense. Based on the provided hint, we changed it to 0.  
* Fixing the Vault Function:

We also found an inconsistency with the "error" variable in both the main function and the vault function. We ensured that the variable remained consistent in both locations.  
* Final Hint – Interest Calculation:

From a decompiled section of the main function, we observed a hint:  
"Interest which u get".  
The fordelay() function was clearing the terminal screen with system("cls"), so we extended the delay to observe the screen output.  
The interest variable was compared with a hidden value Hidden_p. Checking the .data section, we found that Hidden_p was initialized to 7FFFFFFFh (decimal 2147483647).  
We modified the initialization or adjusted the comparison condition to solve the final piece of the puzzle.  
* Flag Extraction:

After depositing an amount to get the interest, we retrieved the hidden part of the flag.  
Final Flag:  
`VishwaCTF{tr4n54ct10n_succ355ful_fl4g_gr4nt3d0$^}`
