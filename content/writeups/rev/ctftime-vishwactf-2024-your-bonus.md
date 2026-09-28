---
title: "YOUR BONUS - VishwaCTF 2024"
category: "rev"
type: "writeup"
tags: ["rev", "engineering", "reverse", "bonus", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "1\\. Analyzing the Main Function:"
source:
  name: "CTFtime writeup #39510"
  url: "https://ctftime.org/writeup/39510"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Your%20bonus.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "YOUR BONUS"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** YOUR BONUS
- **Author team:** CyberCellVIIT
- **CTFtime tags:** engineering, reverse
- **CTFtime:** <https://ctftime.org/writeup/39510>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Reverse%20Engineering/Your%20bonus.pdf>

---
Solution:  
1\. Analyzing the Main Function:  
\- The ransomware's main function contains a loop that calls several functions in sequence:  
devil_function -> zarathos -> Lucifer -> ghost_ridder_wepon -> matter_manipulation -> Trigon.

2\. Function Breakdown:  
\- zarathos: This function rotates strings with random shifts between -3 and 3, starting from index 3 to the string's length minus 1.  
\- Lucifer(string, int): It uses an integer array {-3, -2, -1, 1, 2, 3} and the random_pick(4,0) function to select values from this array, which are then applied to ASCII values of the string’s characters.  
\- ghost_ridder_wepon: This function adds values to a map, which is then used throughout the ransomware's operations.

3\. Map and Final Steps:  
\- matter_manipulation: The ASCII values of the string are mapped, and the ransomware writes the encrypted data to a new file, deleting the original.  
\- Using this analysis, a Java program is created to reverse the process.

4\. Running the Java Program:  
\- After running the program on the hacked data, the flag string is revealed:  
MW4R35_B3AUTIFUL=?_>[:)]]VISHWACTF[<_4R3_R4N50.

5\. Reordering the Flag:  
\- Reorder the string into the flag format:  
VISHWACTF[<_4R3_R4N50MW4R35_B3AUTIFUL].

6\. Final Flag:   
VISHWACTF[4R3_R4N50MW4R35_B3AUTIFUL]

Hope you enjoyed the challenge!
