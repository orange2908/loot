---
title: "odd-bacon - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
type: "writeup"
tags: ["crypto", "ecb", "xor", "odd-bacon", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Key is hardcoded, so we can just use the C impelmentation of SpeckCipher and multithreading to brute force all 2^32 possibilities of k1 super fast and recover k2 along with it."
source:
  name: "CTFtime writeup #39922"
  url: "https://ctftime.org/writeup/39922"
original_source: "https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#odd-bacon"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "odd-bacon"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** odd-bacon
- **Author team:** Infobahn
- **CTFtime:** <https://ctftime.org/writeup/39922>
- **Original writeup:** <https://hackmd.io/@Jm6TApV6RIqYGkPXof9GJA/BkNKejftkl#odd-bacon>

---
Key is hardcoded, so we can just use the C impelmentation of SpeckCipher and multithreading to brute force all 2^32 possibilities of k1 super fast and recover k2 along with it.

```c=  
#include "speck.h"  
#include <stdio.h>  
#include <pthread.h>  
#include <stdlib.h>

#define NUM_THREADS 20 // Number of threads to use  
#define GOAL_AAAA 0x0edb0e75 // replace this after connecting to remote  
#define GOAL_BBBB 0x92746e5c // replace this after connecting to remote  
#define GOAL_CCCC 0xa0ad757a // replace this after connecting to remote

#define AAAA_INT 0x41414141  
#define BBBB_INT 0x42424242  
#define CCCC_INT 0x43434343

static SimSpk_Cipher speck;  
  
uint8_t init_speck() {  
uint8_t IV[] = {0, 0, 0, 0};  
uint8_t counter[] = {0, 0, 0, 0};  
uint64_t u64_key = 0x0123456789abcdef;  
uint8_t *speck64_32_key = (uint8_t*)&u64_key;  
return Speck_Init(&speck, cfg_64_32, ECB, speck64_32_key, IV, counter);  
}

void F(const uint8_t *block, uint8_t *out) {  
Speck_Encrypt(speck, block, out);  
}

typedef struct {  
uint64_t start;  
uint64_t end;  
int thread_id;  
} ThreadData;

void* thread_func(void* arg) {  
ThreadData* data = (ThreadData*)arg;  
uint8_t ciphertext_buffer[16];

for (uint64_t i = data->start; i < data->end; ++i) {  
uint8_t* buf = (uint8_t*)&i;  
F(buf, ciphertext_buffer);

uint32_t expected_k1 = (uint32_t)i ^ AAAA_INT;  
uint32_t expected_k2 = *(uint32_t*)(&ciphertext_buffer) ^ GOAL_AAAA;

uint32_t expected_bbbb_xor = BBBB_INT ^ expected_k1;  
buf = (uint8_t*)&expected_bbbb_xor;  
F(buf, ciphertext_buffer);  
uint32_t result_k2 = *(uint32_t*)(&ciphertext_buffer) ^ GOAL_BBBB;

if (result_k2 != expected_k2)  
continue;

uint32_t expected_cccc_xor = CCCC_INT ^ expected_k1;  
buf = (uint8_t*)&expected_cccc_xor;  
F(buf, ciphertext_buffer);  
result_k2 = *(uint32_t*)(&ciphertext_buffer) ^ GOAL_CCCC;  
  
if (result_k2 == expected_k2)  
{  
FILE* fp = fopen("FOUND.txt", "w");  
fprintf(fp, "FOUND! k1=%#x k2=%#x\n", expected_k1, expected_k2);  
printf("FOUND! k1=%#x k2=%#x\n", expected_k1, expected_k2);  
fclose(fp);  
pthread_exit(NULL);  
}

/*if (i % 0x100000 == 0) {  
printf("Thread %d at %#lx (%.2f%%)\n", data->thread_id, i, (i - data->start) * 100.0 / (data->end - data->start));  
}*/  
}

printf("Thread %d done\n");  
// fclose(fp);  
pthread_exit(NULL);  
}

int main(void) {  
init_speck();

pthread_t threads[NUM_THREADS];  
ThreadData thread_data[NUM_THREADS];

uint64_t range = UINT32_MAX / NUM_THREADS;  
for (int i = 0; i < NUM_THREADS; ++i) {  
thread_data[i].start = i * range;  
thread_data[i].end = (i + 1) * range;  
thread_data[i].thread_id = i;

pthread_create(&threads[i], NULL, thread_func, (void*)&thread_data[i]);  
}

for (int i = 0; i < NUM_THREADS; ++i) {  
pthread_join(threads[i], NULL);  
}

return 0;  
}  
```
