---
title: "Cult-Meeting - hacktheboo"
category: "rev"
subcategory: "image"
type: "writeup"
tags: ["rev", "pie", "lsb", "cult-meeting", "image", "reverse-engineering"]
difficulty: "easy"
summary: "In this challenge, we can download a file and spawn a docker container:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/hacktheboo/Reversing/Cult-Meeting/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Reversing/Cult-Meeting/README.md"
ctf:
  name: "hacktheboo"
  challenge: "Cult-Meeting"
---

## Source

- **CTF:** hacktheboo
- **Challenge:** Cult-Meeting
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/hacktheboo/Reversing/Cult-Meeting/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/hacktheboo/Reversing/Cult-Meeting/README.md>

---
# Cult Meeting

## Background

> After months of research, you're ready to attempt to infiltrate the meeting of a shadowy cult. Unfortunately, it looks like they've changed their password!

> Difficulty: Easy

- Overall difficulty for me: Very easy

## Find the flag

**In this challenge, we can [download a file](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Reversing/Cult-Meeting/rev_cult_meeting.zip) and spawn a docker container:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/HackTheBoo/Reversing/Cult-Meeting/images/a1.png)

**Let's `unzip` that!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing]
└─# unzip rev_cult_meeting.zip 
Archive:  rev_cult_meeting.zip
   creating: rev_cult_meeting/
  inflating: rev_cult_meeting/meeting  

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/rev_cult_meeting]
└─# file meeting         
meeting: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=72d8b06e4ca750d5c24395d3349c3121b9b95283, for GNU/Linux 3.2.0, not stripped
```

It's an 64-bit LSB executable.

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/rev_cult_meeting]
└─# nc -nv 157.245.42.104 31218                      
(UNKNOWN) [157.245.42.104] 31218 (?) open
You knock on the door and a panel slides back
|/👁️ 👁️ \| A hooded figure looks out at you
"What is the password for this week's meeting?"

```

**Looks like we need to find the password!**

**We can use `strings` to list out all the strings in the executable!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/rev_cult_meeting]
└─# strings meeting         
[...]
[3mYou knock on the door and a panel slides back
[3m A hooded figure looks out at you
"What is the password for this week's meeting?" 
sup3r_s3cr3t_p455w0rd_f0r_u!
[3mThe panel slides closed and the lock clicks
|      | "Welcome inside..." 
/bin/sh
   \/
 \| "That's not our password - call the guards!"
[...]
```

- Found the password: `sup3r_s3cr3t_p455w0rd_f0r_u!`

> **Note: You can also find the password in `ltrace`:**

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/rev_cult_meeting]
└─# ltrace ./meeting 
setvbuf(0x7f69867f5760, 0, 2, 0)                                 = 0
puts("\033[3mYou knock on the door and a "...You knock on the door and a panel slides back
)                   = 54
puts("|/\360\237\221\201\357\270\217 \360\237\221\201\357\270\217 \\|\033[3m A hoode"...|/👁️ 👁️ \| A hooded figure looks out at you
) = 62
fwrite(""What is the password for this w"..., 1, 48, 0x7f69867f5760"What is the password for this week's meeting?" ) = 48
fgets(test
"test\n", 64, 0x7f69867f4a80)                              = 0x7ffccef36790
strchr("test\n", '\n')                                           = "\n"
strcmp("test", "sup3r_s3cr3t_p455w0rd_f0r_u!")                   = 1
puts("   \\/"   \/
)                                                   = 6
puts("|/\360\237\221\201\357\270\217 \360\237\221\201\357\270\217 \\| "That's not"...|/👁️ 👁️ \| "That's not our password - call the guards!"
) = 66
+++ exited (status 0) +++
```

**Let's `nc` into the docker container again, and enter the password!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/rev_cult_meeting]
└─# nc -nv 157.245.42.104 31218
(UNKNOWN) [157.245.42.104] 31218 (?) open
You knock on the door and a panel slides back
|/👁️ 👁️ \| A hooded figure looks out at you
"What is the password for this week's meeting?" sup3r_s3cr3t_p455w0rd_f0r_u!
sup3r_s3cr3t_p455w0rd_f0r_u!
The panel slides closed and the lock clicks
|      | "Welcome inside..." 
/bin/sh: 0: can't access tty; job control turned off
$ ls -lah
ls -lah
total 44K
drwxr-xr-x 1 ctf  ctf  4.0K Oct 17 13:55 .
drwxr-xr-x 1 root root 4.0K Oct 17 13:53 ..
-rw-r--r-- 1 ctf  ctf   220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ctf  ctf  3.5K Mar 27  2022 .bashrc
-rw-r--r-- 1 ctf  ctf   807 Mar 27  2022 .profile
-rw-r--r-- 1 root root   36 Oct 17 13:53 flag.txt
-rwxr-xr-x 1 root root  17K Oct 17 13:55 meeting
```

**We're in! Let's grep the flag!**
```
$ cat flag.txt
HTB{1nf1ltr4t1ng_4_cul7_0f_str1ng5}
```

# Conclusion

What we've learned:

1. Listing Strings in an Executable
