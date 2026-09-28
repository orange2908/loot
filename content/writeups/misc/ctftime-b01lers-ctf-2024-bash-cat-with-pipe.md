---
title: "bash cat with pipe - b01lers CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "bash", "cat", "base64", "pipe", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "/bin/bash: line 1: vim: command not found"
source:
  name: "CTFtime writeup #39148"
  url: "https://ctftime.org/writeup/39148"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "bash cat with pipe"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** bash cat with pipe
- **Author team:** nohackspace
- **CTFtime tags:** bash, cat
- **CTFtime:** <https://ctftime.org/writeup/39148>

---
We can see a shell   
```  
$ cat with | vim  
/bin/bash: line 1: vim: command not found  
```  
And apparently the shell is stuck in a mode, where each command is prefixed by a 'cat' command of some file, which is piped to the command we are entering. For example, the command 'more' will result in the piped text to be printed on the screen:  
```  
$ cat with | more  
A cantilever is a rigid structural element that extends horizontally...  
```

We can also transform this text with 'base64'  
```  
$ cat with | base64  
QSBjYW50aWxldmVyIGlzIGEgcmlnaWQgc3RydWN0dXJhbCBlbGVtZW50IHRoYXQgZXh0ZW5kcyBo  
b3Jpem9udGFsbHkgYW5kIGlzIHVuc3VwcG9ydGVkIGF0IG9uZSBlbmQuIFR5cGljYWxseSBpdCBl  
...  
```  
And 'ls' appears to be executable too  
```  
$ cat with | ls  
flag.txt  
run  
with  
```  
Some characters seem to be disallowed

```  
$ cat with | -  
disallowed: -  
$ cat with | ;  
disallowed: ;  
$ cat with | flag  
disallowed: flag

Also disallowed are ", ', $, \, -, & and flag  
```  
We might be able to circumvent the forbidden 'flag' keyword with some command line tools:   
```  
$ cat with | echo fuag.txt | tr u l  
flag.txt  
$ cat with | echo fuag.txt | tr u l | cat  
/bin/bash: fork: retry: Resource temporarily unavailable  
flag.txt  
```  
Another approach  
```  
printf %s fl a g . t x t  
```

Solution:

```  
$ cat with | printf %s fl a g . t x t | xargs cat  
```

Flag:  
```  
bctf{owwwww_th4t_hurt}  
```
