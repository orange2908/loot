---
title: "Ouroboros - World Wide CTF 2025"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "caesar", "ouroboros", "classical", "world-wide-ctf", "world-wide-ctf-2025", "2025", "ctf-writeup"]
summary: "[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)"
source:
  name: "CTFtime writeup #40363"
  url: "https://ctftime.org/writeup/40363"
original_source: "https://srs.writeups.fr/"
ctf:
  name: "World Wide CTF 2025"
  year: 2025
  challenge: "Ouroboros"
---

## Metadata

- **CTF:** World Wide CTF 2025
- **Task:** Ouroboros
- **Author team:** HDFR
- **CTFtime:** <https://ctftime.org/writeup/40363>
- **Original writeup:** <https://srs.writeups.fr/>

---
# Ouroboros - miscellaneous

AUTHORS:  
[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)  
[[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)

# TLDR:  
Instead of creating an ouroboros, create a quine that guess the actual task from its argument, which has a plausible chance of working.

# Challenge presentation

This challenge is asking the player to create an ouroboros.

An ouroboros is a program that is able to print into another code, which can too print itself into another code, etc., and then print itself to its original state.

This [github repo](<https://github.com/mame/quine-relay>) is the perfect example of an orobouros.

What does the challenge do to the player exactly ?

Well, i hope this schema explains it well:  
![](<https://i.imgur.com/TJoRMGN.png>)

Here, the tasks can be any of the following:  
\- Reverse a string  
\- Compute the sum of the elements of a list  
\- Tell if a number is prime or not  
\- Compute the nth number of the fibonacci sequence  
\- Apply a caesar cipher over a list

The code must be a C code, that compiles with the following flags: `'gcc', '-O0', '-std=c99', '-fno-common', '-pipe', '-static', '-nostdlib'`. This means that the C code must be static and cannot use any libraries (yes, we had to recode `printf`, `write` and `read` syscalls)  
Also, the challenge is only allowing the code to execute the following syscalls: `{ read, write, close, execve, exit_group }`.

## First intuition

At first, we got the challenge wrong. We thought that the challenge would run the code with the name of the task it is evaluating, then its arguments.

This would have meant that we only needed to create a code that reads the task name and then dispatch it to the handling function.

The main problem resided in the following question: 

## **How can we create a code that prints itself ?**

When my friend (alexis) asked me how can you write such a code, I simply responded that I would first write a code, then put it a string and print it.

But then I realized, I would then need to put the part where I defined the string and print it, into the string itself, which is just not possible.

So we started doing some research about this problem, and we found out that a code that can print itself **actually has a name**: a **Quine**.

How to write one ? **No idea.**

So we decided to split up the work:  
\- One of us will learn about quine theory and how to write one  
\- One of us will the code: write basic syscalls, write the functions that can actually solve the tasks, which compile with no libraries. Also setup the docker environment and check if the code runs

## Quine theory

After some research, I found out that there was some [very good blog](<http://www.madore.org/~david/computers/quine.html>) that teaches about quines, and that explain how to write one (with C examples !)

I first tried his first example:

```c  
#include <stdio.h>

int  
main (void)  
{  
char *s1="#include <stdio.h>%c%cint%cmain (void)%c{%c";  
char *s2=" char *s%c=%c%s%c;%c char *s%c=%c%s%c;%c";  
char *s3=" char n='%cn', q='%c', b='%c%c';%c";  
char *sp=" printf(";  
char *s4="%ss1,n,n,n,n,n);%c";  
char *s5="%ss2,'1',q,s1,q,n,'2',q,s2,q,n);%ss2,'3',q,s3,q,n,'p',q,sp,q,n);%c";  
char *s6="%ss2,'4',q,s4,q,n,'5',q,s5,q,n);%ss2,'6',q,s6,q,n,'7',q,s7,q,n);%c";  
char *s7="%ss2,'8',q,s8,q,n,'9',q,s9,q,n);%ss2,'0',q,s0,q,n,'x',q,sx,q,n);%c";  
char *s8="%ss3,b,q,b,b,n);%ss4,sp,n);%ss5,sp,sp,n);%c";  
char *s9="%ss6,sp,sp,n);%ss7,sp,sp,n);%ss8,sp,sp,sp,n);%c";  
char *s0="%ss9,sp,sp,sp,n);%ss0,sp,sp,n,n,n);%c return 0;%c}%c";  
char *sx="--- This is an intron. ---";  
char n='\n', q='"', b='\\\';  
printf(s1,n,n,n,n,n);  
printf(s2,'1',q,s1,q,n,'2',q,s2,q,n); printf(s2,'3',q,s3,q,n,'p',q,sp,q,n);  
printf(s2,'4',q,s4,q,n,'5',q,s5,q,n); printf(s2,'6',q,s6,q,n,'7',q,s7,q,n);  
printf(s2,'8',q,s8,q,n,'9',q,s9,q,n); printf(s2,'0',q,s0,q,n,'x',q,sx,q,n);  
printf(s3,b,q,b,b,n); printf(s4,sp,n); printf(s5,sp,sp,n);  
printf(s6,sp,sp,n); printf(s7,sp,sp,n); printf(s8,sp,sp,sp,n);  
printf(s9,sp,sp,sp,n); printf(s0,sp,sp,n,n,n);  
return 0;  
}  
```  
Compiled it, run it, worked just fine.

My first intuition is that I could just write the content of the code that solves the tasks in the `char *s1` string. The problem is that I would then need to change the number of `n` present in the first printf call (` printf(s1,n,n,n,n,n);`), representing the newline in the string. Changing the number of n's has repercurssions on all other strings, changing all of the code, so I realized this method was not the right one.

But, lucky us again, the blog gives us another code sample that is much easier to understand:

```c  
/* See comments below */

const unsigned char data[] = {  
/* 000000 */ 0x2f, 0x2a, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20,  
/* 0x0008 */ 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x6c,  
/* 0x0010 */ 0x66, 0x72, 0x65, 0x70, 0x20, 0x28, 0x71, 0x75,  
/* 0x0018 */ 0x69, 0x6e, 0x65, 0x29, 0x20, 0x70, 0x72, 0x6f,  
/* Several lines snipped. See the original file on the website for a complete listing. */  
/* 0x02c0 */ 0x20, 0x28, 0x64, 0x61, 0x74, 0x61, 0x5b, 0x69,  
/* 0x02c8 */ 0x5d, 0x29, 0x3b, 0x0a, 0x20, 0x20, 0x72, 0x65,  
/* 0x02d0 */ 0x74, 0x75, 0x72, 0x6e, 0x20, 0x30, 0x3b, 0x0a,  
/* 0x02d8 */ 0x7d, 0x0a,  
};

/* This is a selfrep (quine) program. It uses the above data (which  
* is no other than the ASCII representation of everything starting  
* from this comment) to print its own listing. */

#include <stdio.h>

int  
main (void)  
/* The main program. We output the data in the format used at  
* the top of this file, and then we use it to generate the rest  
* of this file. */  
{  
unsigned int i;

printf ("/* See comments below */\n\n");  
printf ("const unsigned char data[] = {");  
for ( i=0 ; i<sizeof(data) ; i++ )  
{  
if ( i%8 == 0 )  
printf ("\n/* %0#6x */",i);  
printf (" %0#4x,", data[i]);  
}  
printf ("\n};\n\n");  
for ( i=0 ; i<sizeof(data) ; i++ )  
putchar (data[i]);  
return 0;  
}  
```

This version is very cool. All of the code content is contained in raw bytes in the `unsigned char data[]` array.

This means that I can just take alexis code, add my main that actually makes it a quine, *et voilà !*

I just need Alexis to recode `printf` without any library.

### Automated quine generation

Let's write a tool that takes Alexis code and actually generates a quine.

Alexis code will be contained in the file `code.c`. The tool `[generate_quine.py](http://generate_quine.py)` will generate the quine `quine.c`.

`[generate_quine.py](http://generate_quine.py)`:  
```python=  
#!/usr/bin/env python3

# Read all bytes from the file code.c  
code = None  
with open("code.c", "rb") as f:  
code = f.read()

# Add the _start function that makes it a quine  
_start_function="""void _start (void)  
{  
main();  
unsigned int i;  
printf ("const unsigned char data[] = {");  
for ( i=0 ; i<sizeof(data) ; i++ )  
{  
if (i % 8 == 0)  
printf("\\\n");  
print_byte_as_hexadecimal(data[i]);  
printf(", ");  
}  
printf ("};\\\n");  
for ( i=0 ; i<sizeof(data) ; i++ )  
print_char(data[i]);  
exit(0);  
}  
"""  
code += _start_function.encode()

# Create a string that is the definition of our data array  
data = "const unsigned char data[] = {"  
i = 0  
for byte in code:  
if i % 8 == 0:  
data += "\n"  
i += 1  
byte_repr = hex(byte)[2:].zfill(2) # Convert byte to hex and pad with zeros  
byte_repr = "0x" + byte_repr  
data += byte_repr + ", "  
data += "};\n"

# Contatenate the data and the code into a single file  
with open("quine.c", "w") as f:  
f.write(data)  
f.write(code.decode())  
```

The `_start` function calls the main function from alexis.  
Also, it supposes that he implemented   
\- the `exit` function  
\- printf function  
\- print_char function  
\- print_byte_as_hexadecimal

Yes, normally the printf does all that normally, but remember, we code everything by ourselves, so for edge cases we coded different functions.

## C Coding

### Understanding the assignment

As said previously, the code itself must compile with the following flags: `'-O0', '-std=c99', '-fno-common', '-pipe', '-static', '-nostdlib'`, so we cannot use any libraries. We are only allow to use these syscalls: `read`, `write`, `close`, `execve` and `exit_group`.

This actually means that we have to write assembly code inside our C code in order to read or write any data.

Let's focus on what the program actually need to solve.  
There are 5 different types of task:  
| Name of the task | Format | Answer |  
|-----------|-----------|-----------|  
| reverse | string (from 3 to 10 chars) | the string reverse |   
| sum | list of number separated by space, where the first one is the number of number | the sum of all numbers except the first one |  
| is_prime | number between 2 and 100 | True if the number is prime, False otherwise  
| fibonacci | number between 1 and 15 | the number of fibonacci corresponding to the number given  
| caesar | number and string separated by a space | the string encoded by doing a caesar cipher using the number

As seen in the introduction part, we are given the `name of the task` the iteration before we actually have to do the task. Therefore, we have two possibilities:  
\- Writing a code that modifies itself because he actually takes into consideration the task given the round before (so an `Ouroboros`)  
\- Writing a code that simply prints himself each time (so a `Quine`). To choose between which task to do, we just have to look at the type of the input given. There is only a problem if we are given a number between 2 and 15, but this is the only case where the code is not certain to work. Therefore we will have to launch the code until we are able to pass all the 69 tasks.

The first option is for sure the cleanest one, but the second option seem easier. So obviously we took the second option.

### Syscalls in C

The first part of the code is to be able to read and write. We are not allowed any libs, so we have to write our own syscalls, therefore do a little bit of assembly.

To understand how to write assembly in C, we can use the function `asm`. Here is the link for the [documentation](<https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html>).

This is the format to write assembly using `asm` in C:  
```  
asm asm-qualifiers ( AssemblerTemplate   
: OutputOperands   
[ : InputOperands  
[ : Clobbers ] ])  
```

`AssemblerTemplate`, `OutputOperands` and `InputOperands` are very explicit, and `Clobbers` are the variable that will be modified by our assembly code.  
You will find below the implementation of the syscalls useful for this challenge:

```C  
long read(int fd, void *buf, long count) {  
long ret;  
__asm__("mov $0, %%rax; mov %1, %%rdi; mov %2, %%rsi; mov %3, %%rdx; syscall"  
: "=a"(ret) : "r"((long)fd), "r"(buf), "r"((long)count) : "rdi","rsi","rdx");  
return ret;  
}  
long write(int fd, const void *buf, long count) {  
long ret;  
__asm__("mov $1, %%rax; mov %1, %%rdi; mov %2, %%rsi; mov %3, %%rdx; syscall"  
: "=a"(ret) : "r"((long)fd), "r"(buf), "r"((long)count) : "rdi","rsi","rdx");  
return ret;  
}  
void exit(int status) {  
__asm__("mov $231, %%rax; mov %0, %%rdi; syscall"  
: : "r"((long)status) : "rax","rdi");  
}  
```

### Writing the code logic

This part is not the hardest part, as syscalls have been already implemented. It's just writing some basic C code in order to do the 5 different tasks.

```C  
long read(int fd, void *buf, long count) {  
long ret;  
__asm__("mov $0, %%rax; mov %1, %%rdi; mov %2, %%rsi; mov %3, %%rdx; syscall"  
: "=a"(ret) : "r"((long)fd), "r"(buf), "r"((long)count) : "rdi","rsi","rdx");  
return ret;  
}  
long write(int fd, const void *buf, long count) {  
long ret;  
__asm__("mov $1, %%rax; mov %1, %%rdi; mov %2, %%rsi; mov %3, %%rdx; syscall"  
: "=a"(ret) : "r"((long)fd), "r"(buf), "r"((long)count) : "rdi","rsi","rdx");  
return ret;  
}  
void exit(int status) {  
__asm__("mov $231, %%rax; mov %0, %%rdi; syscall"  
: : "r"((long)status) : "rax","rdi");  
}  
void print_char(char c) {  
write(1, &c, 1);  
}  
char **separate_words(char *str, int **size) {  
static char *words[64];  
static int sizes[64];  
int count = 0;  
char *start = str;  
while (*str) {  
if (*str == ' ') {  
if (start != str) {  
words[count] = start;  
sizes[count] = str - start;  
count++;  
}  
*str = '\0';  
start = str + 1;  
}  
if (*str == '\n')  
{  
*str = '\0';  
}  
str++;  
}  
if (start != str) {  
words[count] = start;  
sizes[count] = str - start;  
count++;  
}  
words[count] = 0;  
sizes[count] = 0;  
*size = sizes;  
return words;  
}  
int mystrcmp(const char *s1, const char *s2) {  
while (*s1 && *s2) {  
if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;  
s1++; s2++;  
}  
return (unsigned char)*s1 - (unsigned char)*s2;  
}  
int atoi(const char *str) {  
int result = 0;  
while (*str) {  
if (*str < '0' || *str > '9') return -1;  
result = result * 10 + (*str - '0');  
str++;  
}  
return result;  
}  
char *itoa(int num) {  
static char buffer[12];  
char *ptr = buffer + sizeof(buffer) - 1;  
*ptr = '\0';  
if (num == 0) {  
*(--ptr) = '0';  
} else {  
int is_negative = num < 0;  
if (is_negative) num = -num;  
while (num > 0) {  
*(--ptr) = (num % 10) + '0';  
num /= 10;  
}  
if (is_negative) *(--ptr) = '-';  
}  
return ptr;  
}  
int fibonacci(int n) {  
if (n < 0) return -1;  
if (n == 0) return 0;  
if (n == 1) return 1;  
int a = 0, b = 1, c;  
for (int i = 2; i <= n; i++) {  
c = a + b;  
a = b;  
b = c;  
}  
return b;  
}  
int is_prime(int n) {  
if (n <= 1) return 0;  
for (int i = 2; i * i <= n; i++) {  
if (n % i == 0) return 0;  
}  
return 1;  
}  
char *ceasar_shift(const char *str, int shift) {  
static char buffer[256];  
char *ptr = buffer;  
while (*str) {  
if (*str >= 'a' && *str <= 'z') {  
*ptr++ = ((*str - 'a' + shift) % 26) + 'a';  
} else if (*str >= 'A' && *str <= 'Z') {  
*ptr++ = ((*str - 'A' + shift) % 26) + 'A';  
} else {  
*ptr++ = *str;  
}  
str++;  
}  
*ptr = '\0';  
return buffer;  
}  
int mystrlen(const char *str) {  
int len = 0;  
while (*str++) len++;  
return len;  
}  
void dispatch(char *buf, int len) {  
int *size;  
char **words = separate_words(buf, &size);  
if (size[1] == 0){  
int num = atoi(words[0]);  
if (num < 0) {  
for (int i = size[0] - 1; i >= 0; i--)  
print_char(words[0][i]);  
print_char('\n');  
return;  
}  
if (num <= 15 && num >= 1)  
{  
int res = fibonacci(num);  
char *result_str = itoa(res);  
write(1, result_str, mystrlen(result_str));  
print_char('\n');  
return;  
}  
int res = is_prime(num);  
if (res)  
{  
write(1, "True\n", 5);  
return;  
}  
write(1, "False\n", 6);  
return;  
}  
if (words[2] == 0)  
{  
int num = atoi(words[0]);  
char *res = ceasar_shift(words[1], num);  
write(1, res, mystrlen(res));  
print_char('\n');  
return;  
}  
int total = 0;  
int i = 1;  
while (words[i] != 0) {  
total += atoi(words[i]);  
i++;  
}  
char *result_str = itoa(total);  
write(1, result_str, mystrlen(result_str));  
print_char('\n');  
return;  
}  
void main(void) {  
char buf[256];  
int nread = read(0, buf, sizeof(buf) - 1);  
buf[nread] = '\0';  
if (mystrcmp(buf, "reverse") == 0 || mystrcmp(buf, "sum") == 0 || mystrcmp(buf, "fibonacci") == 0 || mystrcmp(buf, "is_prime") == 0 || mystrcmp(buf, "ceasar_shift") == 0) {  
write(1, "\n", 1);  
return;  
}  
dispatch(buf, nread);  
}  
```

I also need to implement some functions for Robin:  
```C  
void print_str(const char *s) {  
if (!s) return;  
while (*s)  
{  
print_char(*s);  
s++;  
}  
}  
void print_int(int n) {  
if (n < 0) {  
print_char('-');  
n = -n;  
}  
if (n >= 10)  
print_int(n / 10);  
print_char('0' + (n % 10));  
}  
void printf(const char *fmt, ...) {  
va_list args;  
va_start(args, fmt);  
while (*fmt) {  
if (*fmt == '%') {  
fmt++;  
if (*fmt == 'd') {  
int val = va_arg(args, int);  
print_int(val);  
} else if (*fmt == 's') {  
char *str = va_arg(args, char *);  
print_str(str);  
} else if (*fmt == 'c') {  
char c = (char)va_arg(args, int);  
print_char(c);  
} else if (*fmt == '%') {  
print_char('%');  
}  
} else {  
print_char(*fmt);  
}  
fmt++;  
}  
va_end(args);  
}  
void print_byte_as_hexadecimal(unsigned char byte) {  
const char *hex_digits = "0123456789abcdef";  
printf("0x");  
print_char(hex_digits[(byte >> 4) & 0x0F]);  
print_char(hex_digits[byte & 0x0F]);  
}  
```

And that's it for the C coding part!

## Putting it together

First let's test if the quine actually works, by combining our work.

`Makefile`:  
```makefile=  
CC=gcc  
CFLAGS= -O0 -std=c99 -fno-common -pipe -static -nostdlib -g

all: quine

quine:  
./[generate_quine.py](http://generate_quine.py) && $(CC) $(CFLAGS) -o quine quine.c

clean:  
rm -f quine

.PHONY: clean quine  
```

Let's simulate the first execution of the code (Init in the schema)  
```shell  
$ make quine  
$ ./quine > quine_output.txt # Run the code and give it the name of next task  
reverse  
$ diff quine.c quine_output.txt  
0a1  
> esrever  
```  
We see that there is no difference between the output and the code itself, except that the output contains the string given.

This is normal, because we designed ourcode to guess the task from the arguments. Here, it thought it was the arguments of the reverse task. It does not cause any problem, because the challenge does not check the output for the first iteration so it's fine.

Let's now do a simple script that sends our program to the server:  
```python   
from pwn import *  
import sys

context.log_level = 'debug'

if len(sys.argv) != 2:  
print("Usage: python [run_code.py](http://run_code.py) <path_to_code>")  
sys.exit(1)

p = remote('localhost', 1337)

p.recvuntil(b"nd)\n")  
with open(sys.argv[1], 'r') as f:  
code = f.read()  
p.sendline(code.encode())  
p.sendline()  
p.recvall()

```

Locally, it works on the third try !  
We can just now run it on the server and get the flag:  
`wwf{you_are_a_quine_master_now_congratulations}`
