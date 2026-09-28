---
title: "bug-me - BSidesSF 2025 CTF"
category: "rev"
subcategory: "image"
type: "writeup"
tags: ["rev", "engineering", "reverse", "pie", "lsb", "bug-me", "image", "bsidessf-2025-ctf", "2025", "ctf-writeup"]
summary: "/tmp/bug-me: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bba44183929dfb6b700cc612c4319639d46cc6e6, for GNU/Linux"
source:
  name: "CTFtime writeup #40205"
  url: "https://ctftime.org/writeup/40205"
original_source: "https://happyhacks.bearblog.dev/bsidessf-ctf-2025-re-bug-me-writeup/"
ctf:
  name: "BSidesSF 2025 CTF"
  year: 2025
  challenge: "bug-me"
---

## Metadata

- **CTF:** BSidesSF 2025 CTF
- **Task:** bug-me
- **Author team:** Sithis
- **CTFtime tags:** engineering, reverse
- **CTFtime:** <https://ctftime.org/writeup/40205>
- **Original writeup:** <https://happyhacks.bearblog.dev/bsidessf-ctf-2025-re-bug-me-writeup/>

---
# BSidesSF CTF 2025 RE bug-me writeup

_ 27 Apr, 2025  _

```
    $ file /tmp/bug-me
    /tmp/bug-me: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bba44183929dfb6b700cc612c4319639d46cc6e6, for GNU/Linux 3.2.0, not stripped
```

The file is not stripped - for a reason we’ll see.

The binary is easily decompiled.

```
    int __fastcall main(int argc, const char **argv, const char **envp)
    {
      int v4; // [rsp+18h] [rbp-18h]
      int c; // [rsp+1Ch] [rbp-14h]
    
      if ( argc != 2 )
      {
        fprintf(stderr, "Usage: %s <flag>\n", *argv);
        exit(1);
      }
      puts("Loading...");
      sleep(1u);
      puts("Checking your flag...");
      if ( strlen(argv[1]) != 30 )
      {
        puts("Flag is not correct!!");
        exit(0);
      }
      check_flag(0, -1);
      v4 = 0;
      for ( c = 0; c < strlen(argv[1]); ++c )
      {
        v4 += check_flag(argv[1][c], c) != 0;
        LODWORD(null) = 'WTF?';
      }
      if ( v4 <= 0 )
        puts("Flag is correct!! YAY!");
      else
        puts("Flag is not correct!!");
      return -1;
    }
```

So simple. But when we run this the binary doesn’t crash at

```
        LODWORD(null) = 'WTF?';
```

So we do a quick `strace` and find that process `fork`s somewhere before `main`

Checking the `init_array`

```
    .init_array:0000000000003DC0 off_3DC0        dq offset sub_1170      ; DATA XREF: LOAD:0000000000000168↑o
    .init_array:0000000000003DC0                                         ; LOAD:00000000000002F0↑o
    .init_array:0000000000003DC8                 dq offset __gmon_init__
    .init_array:0000000000003DC8 _init_array     ends
```

`__gmon_init__` is a function that employs some obfuscation

`__gmon_map__` is called to decrypt strings with - now renamed to `decrypt_str`

```
    char *__fastcall decrypt_str(char *a1, int len, char *a3)
    {
      int i; // [rsp+24h] [rbp-4h]
    
      for ( i = 0; i < len; ++i )
        a3[i] = ~((2 * i) ^ a1[i]);
      a3[i] = 0;
      return a3;
    }
```

We can decompile `__gmon_init__` in IDA and then use this script to decrypt and rename variables to get a cleaner decompilation

```
    import idaapi
    import ida_bytes
    import ida_name
    import idc
    
    DECRYPT_FUNC_NAME = "decrypt_str"
    
    def decrypt_str(ea, length):
        out = []
        for i in range(length):
            b = ida_bytes.get_byte(ea + i)
            dec = ~(b ^ (2 * i)) & 0xFF
            out.append(dec)
        return bytes(out).split(b'\x00')[0].decode('ascii', errors='replace')
    
    def safe_str(s):
        return ''.join(c if c.isalnum() else '_' for c in s)[:30]
    
    class DecryptStrVisitor(idaapi.ctree_visitor_t):
        def __init__(self, decrypt_func_ea):
            super().__init__(idaapi.CV_FAST)
            self.decrypt_func_ea = decrypt_func_ea
    
        def visit_expr(self, expr):
            if expr.op == idaapi.cot_call:
                callee = expr.x
                if callee.op == idaapi.cot_obj and callee.obj_ea == self.decrypt_func_ea:
                    args = expr.a
                    if len(args) >= 3:
                        array_arg = args[0]
                        length_arg = args[1]
    
                        array_ea = self.resolve_arg(array_arg)
                        length_val = self.resolve_arg(length_arg)
    
                        if array_ea is not None and length_val is not None:
                            print(f"[+] Found call: array=0x{array_ea:X}, length={length_val}")
                            try:
                                s = decrypt_str(array_ea, length_val)
                                new_name = f"str_{safe_str(s)}"
                                ida_name.set_name(array_ea, new_name, ida_name.SN_CHECK)
                                print(f"    Renamed 0x{array_ea:X} -> {s}")
    
                                # (Optional) Add comment in pseudocode
                                expr.cmt = f"Decrypted: {s}"
    
                                # Set type at array_ea: unsigned char[length]
                                typename = f"unsigned char[{length_val}]"
                                idc.SetType(array_ea, typename)
    
                            except Exception as e:
                                print(f"    Error decrypting: {e}")
                        else:
                            print(f"[-] Invalid arguments: {expr.ea:X} {array_ea}, {length_val}")
    
            return 0  # Continue visiting
    
        def resolve_arg(self, arg):
            if arg.op == idaapi.cot_obj:
                return arg.obj_ea
            elif arg.op == idaapi.cot_cast:
                return self.resolve_arg(arg.x)
            elif arg.op == idaapi.cot_num:
                return arg.numval()
            else:
                return None
    
    def process_function(func_ea, decrypt_func_ea):
        try:
            cfunc = idaapi.decompile(func_ea)
            visitor = DecryptStrVisitor(decrypt_func_ea)
            visitor.apply_to(cfunc.body, None)
            cfunc.save_user_cmts()  # Save any comments we added
        except idaapi.DecompilationFailure:
            print(f"[-] Failed to decompile 0x{func_ea:X}")
    
    def main():
        decrypt_func_ea = idc.get_name_ea_simple(DECRYPT_FUNC_NAME)
        if decrypt_func_ea == idc.BADADDR:
            print(f"Cannot find function {DECRYPT_FUNC_NAME}")
            return
    
        for func_ea in [0x178E]:
            process_function(func_ea, decrypt_func_ea)
    
    main()
```

This visits the `__gmon_init__` with `idaapi.ctree_visitor_t` and checks when `__gmon_map__` is called to identify the string and rename it

We get the following decompilation

```
        name = decrypt_str(str_fork, 4, a3);
      fork = dlsym(0, name);
      result = fork();
      if ( !result )
      {
        name_1 = decrypt_str(str_getppid, 7, a3);
        getppid = dlsym(0, name_1);
        ppid = getppid();
        name_2 = decrypt_str(str_ptrace, 6, a3);
        ptrace = dlsym(0, name_2);
        if ( (ptrace)(PTRACE_ATTACH, ppid, 0, 0) < 0 )
        {
          name_3 = decrypt_str(str_exit, 4, a3);
          exit = dlsym(0, name_3);
          exit(0);
        }
        name_4 = decrypt_str(str_waitpid, 7, a3);
        waitpid = dlsym(0, name_4);
        (waitpid)(ppid, v55, 0);
        name_5 = decrypt_str(str_ptrace, 6, a3);
        _ptrace = dlsym(0, name_5);
        _ptrace(PTRACE_CONT, ppid, 0xFFFFFFFFLL, 0);
        name_6 = decrypt_str(str_open, 4, a3);
        open = dlsym(0, name_6);
        proc_self_exe = decrypt_str(str__proc_self_exe, 14, a3);
        exe_fd = open(proc_self_exe, 0);
        name_7 = decrypt_str(str_lseek, 5, a3);
        lseek = dlsym(0, name_7);
        (lseek)(exe_fd, 0x3A00, 0);
        name_8 = decrypt_str(str_sprintf, 7, a3);
        sprintf = dlsym(0, name_8);
        v20 = decrypt_str(str__proc__d_mem, 12, a3);
        (sprintf)(proc_ppid_mem, v20, ppid);
        name_9 = decrypt_str(str_open, 4, a3);
        _open = dlsym(0, name_9);
        parent_mem_fd = _open(proc_ppid_mem, 0x80002);
        name_10 = decrypt_str(str_ignoremeplz, 11, a3);
        LOWORD(sprintf) = dlsym(0, name_10);
        name_11 = decrypt_str(str_main, 4, a3);
        ignoremeplz_minus_main = sprintf - dlsym(0, name_11);
        name_12 = decrypt_str(str_pread, 5, a3);
        pread = dlsym(0, name_12);
        name_13 = decrypt_str(str_main, 4, a3);
        main = dlsym(0, name_13);
        pread(parent_mem_fd, main_buf, ignoremeplz_minus_main, main);
        main_sum = 0;
        for ( i = 0; i < ignoremeplz_minus_main; ++i )
          main_sum += main_buf[i];
        while ( 1 )
        {
          while ( 1 )
          {
            name_14 = decrypt_str(str_waitpid, 7, a3);
            _waitpid = dlsym(0, name_14);
            _waitpid(ppid, &n127, 0);
            if ( n127 == 127 )
              break;
            name_15 = decrypt_str(str_exit, 4, a3);
            exit_1 = dlsym(0, name_15);
            exit_1(0);
          }
          name_16 = decrypt_str(str_ptrace, 6, a3);
          ptrace_1 = dlsym(0, name_16);
          (ptrace_1)(PTRACE_GETREGS, ppid, 0, &user_regs_struct_);
          if ( n11 == SIGFPE )
          {
            user_regs_struct_.rip += 2LL;
          }
          else if ( n11 == SIGSEGV )
          {
            user_regs_struct_.rip += 6LL;
          }
          name_17 = decrypt_str(str_ptrace, 6, a3);
          ptrace_2 = dlsym(0, name_17);
          (ptrace_2)(PTRACE_SETREGS, ppid, 0, &user_regs_struct_);
          read = decrypt_str(str_read, 4, a3);
          read_1 = dlsym(0, read);
          read_1(exe_fd, &v52, 1);
          name_19 = decrypt_str(str_read, 4, a3);
          read_3 = dlsym(0, name_19);
          read_3(exe_fd, &j_1, 1);
          name_20 = decrypt_str(str_read, 4, a3);
          read_2 = dlsym(0, name_20);
          (read_2)(exe_fd, patched_check_flag, j_1);
          for ( j = 0; j < j_1; ++j )
            patched_check_flag[j] ^= (4 * j) ^ v52 ^ main_sum;
          name_21 = decrypt_str(str_pwrite, 6, a3);
          pwrite = dlsym(0, name_21);
          (pwrite)(parent_mem_fd, patched_check_flag, j_1, check_flag);
          name_22 = decrypt_str(str_ptrace, 6, a3);
          name_43 = dlsym(0, name_22);
          (name_43)(PTRACE_CONT, ppid, 0xFFFFFFFFLL, 0);
        }
      }
```

This is what the function does

  * Fork self.
  * Child attaches to parent with `ptrace`.
  * Child opens its own executable and reads embedded encrypted data.
  * Child decrypts it dynamically.
  * Child writes patches directly into the parent’s memory (`/proc/<ppid>/mem`).
  * Child continuously monitors parent traps and keeps patching.


At `0x3A00` we have some encrypted data which is written over the `check_flag` implementation

and the `NULL` crash is fixed every time to continue execution.

The memory is patched with `pwrite` \- the first call to `check_flag` might raise a `SIGFPE` and the returns from `check_flag` will raise the NULL pointer deref `SIGSEGV`

So now we know how the patches are being made.

The idea to solve - hook `pwrite` with `LD_PRELOAD` and store the patched bytes

```
    // File: hook_pwrite.c
    // gcc -Wall -fPIC -shared -o hook_pwrite.so hook_pwrite.c -ldl
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <dlfcn.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <fcntl.h>
    #include <string.h>
    
    static ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
    
    __attribute__((constructor))
    static void init(void) {
        real_pwrite = dlsym(RTLD_NEXT, "pwrite");
        if (!real_pwrite) {
            write(2, "Failed to resolve pwrite\n", 25);
            _exit(1);
        }
    }
    
    ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
        // Dump the call
        int dump_fd = open("/tmp/pwrite_dump.bin", O_CREAT | O_APPEND | O_WRONLY, 0644);
        if (dump_fd != -1) {
            fprintf(stdout, "pwrite(fd=%d, count=%zu, offset=0x%lx)\n", fd, count, (unsigned long)offset);
            write(dump_fd, buf, count);
            close(dump_fd);
        }
    
        // Call the real pwrite
        return real_pwrite(fd, buf, count, offset);
    }
```

So now we have the updated `check_flag` for each byte

```
    $ LD_PRELOAD=./hook_pwrite.so /tmp/bug-me AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Loading...
    Checking your flag...
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=50, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=57, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=49, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=57, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=50, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=49, offset=0x625c72f52179)
    pwrite(fd=5, count=55, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    pwrite(fd=5, count=54, offset=0x625c72f52179)
    Flag is not correct!!
```

We can now load these function implementations in `unicorn` and brute-force for all possible bytes for each index

```
    from unicorn import *
    from unicorn.x86_const import *
    
    with open("/tmp/pwrite_dump.bin", "rb") as f:
        code = f.read()
    
    ADDRESS = 0x1000000
    STACK_ADDR = 0x2000000
    STACK_SIZE = 0x10000
    
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    
    def hook_ret(uc, address, size, user_data):
        c = mu.mem_read(address, size)
        if c != b"\xc3":
            return
        uc.emu_stop()
    
    mu.hook_add(UC_HOOK_CODE, hook_ret, begin=ADDRESS, end=ADDRESS + len(code))
    mu.mem_write(ADDRESS, code)
    
    def f(c, idx, rip):
        mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x8)
        arg1 = c
        arg2 = idx
        mu.reg_write(UC_X86_REG_RDI, arg1)
        mu.reg_write(UC_X86_REG_RSI, arg2)
    
        try:
            mu.emu_start(rip, rip + len(code))
        except UcError as e:
            pass
    
        rax = mu.reg_read(UC_X86_REG_RAX)
        rip = mu.reg_read(UC_X86_REG_RIP)
        return rax, rip
    
    curr = ADDRESS
    keyspace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_{()}[]"
    flag = ""
    for _ in range(30):
        for c in keyspace:
            rax, rip = f(ord(c), 0, curr)
            if rax == 0:
                flag += c
                curr = rip + 1
                break
        print(flag)
```

This will print the flag

```
    C
    CT
    CTF
    CTF{
    CTF{h
    CTF{ho
    CTF{hop
    CTF{hope
    CTF{hope-
    CTF{hope-y
    CTF{hope-yo
    CTF{hope-you
    CTF{hope-you-
    CTF{hope-you-e
    CTF{hope-you-en
    CTF{hope-you-enj
    CTF{hope-you-enjo
    CTF{hope-you-enjoy
    CTF{hope-you-enjoye
    CTF{hope-you-enjoyed
    CTF{hope-you-enjoyed-
    CTF{hope-you-enjoyed-t
    CTF{hope-you-enjoyed-th
    CTF{hope-you-enjoyed-thi
    CTF{hope-you-enjoyed-this
    CTF{hope-you-enjoyed-this-
    CTF{hope-you-enjoyed-this-o
    CTF{hope-you-enjoyed-this-on
    CTF{hope-you-enjoyed-this-one
    CTF{hope-you-enjoyed-this-one}
```

`CTF{hope-you-enjoyed-this-one}` is accepted

[#CTF](https://happyhacks.bearblog.dev/blog/?q=CTF) [#IDA](https://happyhacks.bearblog.dev/blog/?q=IDA) [#IDAPython](https://happyhacks.bearblog.dev/blog/?q=IDAPython) [#LD_PRELOAD](https://happyhacks.bearblog.dev/blog/?q=LD_PRELOAD) [#reversing](https://happyhacks.bearblog.dev/blog/?q=reversing) [#unicorn](https://happyhacks.bearblog.dev/blog/?q=unicorn) [#writeup](https://happyhacks.bearblog.dev/blog/?q=writeup)
