---
title: "Chalkboard Gag - BCACTF 5.0"
category: "misc"
type: "writeup"
tags: ["misc", "chalkboard", "gag", "bcactf", "bcactf-5-0", "ctf-writeup"]
summary: "While checking the txt file i noticed that some lines don't have the same phrase."
source:
  name: "CTFtime writeup #39264"
  url: "https://ctftime.org/writeup/39264"
original_source: "https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/foren/Chalkboard%20Gag"
ctf:
  name: "BCACTF 5.0"
  challenge: "Chalkboard Gag"
---

## Metadata

- **CTF:** BCACTF 5.0
- **Task:** Chalkboard Gag
- **Author team:** 1c3Gh3tt0
- **CTFtime:** <https://ctftime.org/writeup/39264>
- **Original writeup:** <https://github.com/juke-33/Write-ups/tree/main/BCACTF%205.0/foren/Chalkboard%20Gag>

---
While checking the txt file i noticed that some lines don't have the same phrase.

Some lines which we need have a different letter.

So i wrote a script to recognize the changed line and found the flag.

```  
# Define the phrase you're searching for  
phrase = "I WILL NOT BE SNEAKY"

# Initialize an empty string to store differing letters  
all_differing_letters = ""

# Open the text file  
with open("chalkboardgag.txt", "r") as file:  
# Iterate through each line in the file  
for line in file:  
# Remove leading/trailing whitespaces and newline characters  
clean_line = line.strip()  
  
# Check if the line contains the phrase  
if phrase not in clean_line:  
# Compare each character in the line with the corresponding character in the phrase  
for i in range(min(len(phrase), len(clean_line))):  
if clean_line[i] != phrase[i]:  
# Append differing letters to the accumulator string  
all_differing_letters += clean_line[i]  
else:  
# If the line contains the phrase, move to the next line  
continue

# Print all differing letters found in all lines  
print("All differing letters:", all_differing_letters)  
```

Flag: `bcactf{BaRT_W0U1D_B3_PR0uD}`
