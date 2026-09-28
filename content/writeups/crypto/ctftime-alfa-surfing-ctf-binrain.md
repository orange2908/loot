---
title: "Бинарный ливень (binrain) - Alfa Surfing CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["aes", "pwn", "crypto", "ecb", "memcpy", "alfa-surfing-ctf", "ctf-writeup"]
summary: "We're given the TCP server which implements AES128ECB encryption using the static key."
source:
  name: "CTFtime writeup #40435"
  url: "https://ctftime.org/writeup/40435"
original_source: "https://blog.kelte.cc/posts/alfa-2025-binrain/"
ctf:
  name: "Alfa Surfing CTF"
  challenge: "Бинарный ливень (binrain)"
---

## Metadata

- **CTF:** Alfa Surfing CTF
- **Task:** Бинарный ливень (binrain)
- **Author team:** C4T BuT S4D
- **CTFtime tags:** aes, pwn, crypto
- **CTFtime:** <https://ctftime.org/writeup/40435>
- **Original writeup:** <https://blog.kelte.cc/posts/alfa-2025-binrain/>

---
## Description

> Внезапно тучи сгущаются. На вас налетает тропический ливень! С неба валятся цифры 0 и 1, от которых не спасает пляжный зонтик. Нужно срочно найти убежище, чтобы не стать мокрой двоичной курицей.

> Suddenly, the clouds thicken. A tropical downpour descends upon you! The numbers 0 and 1 are falling from the sky, and a beach umbrella is no help. You need to find shelter quickly, or you will become a wet binary chicken. _(machine translation)_

## Overview

We're given the TCP server which implements AES_128_ECB encryption using the static key.

The server gives us an encrypted flag and provides the following interface:

1\. encrypt the arbitrary plaintext and output the ciphertext  
2\. print the previous plaintext and ciphertext

```c  
char message[MAX_MESSAGE_LEN];  
data_t data;

switch (choice) {  
case MENU_AES128: {  
printf("?️ Say something to the cave: ");  
fflush(stdout);

if (fgets(message, MAX_MESSAGE_LEN, stdin) == NULL) break;

size_t recv_len = strlen(message);  
if (recv_len > 0 && message[recv_len - 1] == '\n') {  
message[recv_len - 1] = '\0';  
recv_len--;  
}  
if (recv_len % 16 != 0) {  
for (size_t i = recv_len; i % 16 != 0; i++) {  
message[i] = 0;  
recv_len++;  
}  
}

if (last_encryption->has_data) {  
free(last_encryption->last_ciphertext);  
if (last_encryption->is_malloced) {  
free(last_encryption->last_plaintext);  
}  
}

if (recv_len <= 16) {  
memcpy(data.plaintext, message, AES_BLOCKLEN);  
last_encryption->last_ciphertext = aes_encrypt_128(&data, client_key);  
last_encryption->last_plaintext = (uint8_t *) &data.plaintext;  
last_encryption->is_malloced = false;  
} else {  
last_encryption->last_ciphertext = malloc(recv_len+1);

for (size_t i = 0; i < recv_len; i += 16) {  
memcpy(data.plaintext, message + i, 16);  
uint8_t * result = aes_encrypt_128(&data, client_key);  
memcpy(last_encryption->last_ciphertext + i, result, 16);  
free(result);  
}

last_encryption->last_plaintext = malloc(recv_len+1);  
memcpy(last_encryption->last_plaintext, message, recv_len);  
last_encryption->is_malloced = true;  
}  
last_encryption->has_data = 1;  
last_encryption->ciphertext_len = recv_len;

char * hex_result = malloc(recv_len*2 + 1);

bytes_to_hex(last_encryption->last_ciphertext, hex_result, recv_len);  
printf(  
"?️ The cave echoes back...\n"  
"?️ You said: '%s'\n"  
"? Encrypted echo: %s\n"  
"? Your words bounce off the cave walls\n"  
" and return as magical symbols...\n\n",  
message, hex_result);  
free(hex_result);  
break;  
}

case MENU_SHOW_LAST: {  
if (last_encryption->has_data) {  
char * hex_result = malloc(last_encryption->ciphertext_len * 2 + 1);  
bytes_to_hex(last_encryption->last_ciphertext, hex_result, last_encryption->ciphertext_len);  
printf(  
"? ═══════ LAST ECHO ═══════ ?\n"  
"?️ You said: '%s'\n"  
"? Encrypted echo: %s\n"  
"? The echo still reverberates from the cave walls...\n\n",  
last_encryption->last_plaintext,  
hex_result);  
free(hex_result);  
} else {  
printf(  
"? The echo in the cave has quieted...\n"  
" You haven't said anything yet.\n"  
" Say something to hear the echo!\n\n");  
}  
break;  
}  
}  
```

## Investigation

Although the challenge is marked as pwn, there are no binary vulnerabilities in the provided code. But there is a hidden data leak instead. Note that during the `MENU_SHOW_LAST` option the content of `last_encryption->last_plaintext` buffer is printed as `%s` without any length check. We can abuse this property as follows.

Let's encrypt the single plaintext block (16 bytes), then the `last_plaintext` will be set to `data.plaintext`:

```c  
if (recv_len <= 16) {  
memcpy(data.plaintext, message, AES_BLOCKLEN);  
last_encryption->last_ciphertext = aes_encrypt_128(&data, client_key);  
last_encryption->last_plaintext = (uint8_t *) &data.plaintext;  
last_encryption->is_malloced = false;  
}  
```

Let's look at the `data_t` structure:

```c  
typedef struct {  
uint8_t plaintext[16];  
uint8_t ciphertext[16];   
} data_t;  
```

Right after `data.plaintext` there is `data.ciphertext`, so if the plaintext does not have null terminator the service will also output the content of the `data.ciphertext`. Let's check this:

```  
> ./binrain.elf  
?️ ═════════ VOICE OF THE CAVE ═════════ ?️  
I hear your footsteps, traveler...  
Say something, and I'll echo it back to you!

?️ 1. Say something to the cave (hear echo)  
? 2. Read the last echo  
? 3. Leave the cave  
Choose your path (1-3): 1  
?️ Say something to the cave: AAAAAAAAAAAAAAAA  
?️ The cave echoes back...  
?️ You said: 'AAAAAAAAAAAAAAAA'  
? Encrypted echo: 2b25f123af2431d40754bccb89833cc3  
? Your words bounce off the cave walls  
and return as magical symbols...

?️ ═════════ VOICE OF THE CAVE ═════════ ?️  
I hear your footsteps, traveler...  
Say something, and I'll echo it back to you!

?️ 1. Say something to the cave (hear echo)  
? 2. Read the last echo  
? 3. Leave the cave

Choose your path (1-3): 2  
? ═══════ LAST ECHO ═══════ ?  
?️ You said: 'AAAAAAAAAAAAAAAA*L\x94e\xbelp|\xcc\xceL\xeb\xee\x06\x1f\xb4AAAAAAAAAAAAAAAA'  
? Encrypted echo: 2b25f123af2431d40754bccb89833cc3  
? The echo still reverberates from the cave walls...

?️ ═════════ VOICE OF THE CAVE ═════════ ?️  
I hear your footsteps, traveler...  
Say something, and I'll echo it back to you!

?️ 1. Say something to the cave (hear echo)  
? 2. Read the last echo  
? 3. Leave the cave  
```

So we've got the following buffers:

```  
'AAAAAAAAAAAAAAAA' (16 bytes) -> data.plaintext  
'*L\x94e\xbelp|\xcc\xceL\xeb\xee\x06\x1f\xb4' (16 bytes) -> data.ciphertext  
'AAAAAAAAAAAAAAAA' -> message  
```

Please note that the received `data.ciphertext` does not match the resulting ciphertext given by the server. So it's obviously something different.

Let's look at the AES implementation in `aes.c`:

```c  
void RoundFunction(state_t * state, const uint8_t* RoundKey, uint8_t round) {  
SubBytes(state);  
ShiftRows(state);  
MixColumns(state);  
AddRoundKey(round, state, RoundKey);  
}

uint8_t* LastRound(state_t *state, const uint8_t* RoundKey, uint8_t round) {  
SubBytes(state);  
ShiftRows(state);  
AddRoundKey(round, state, RoundKey);  
uint8_t * output = (uint8_t *) malloc(AES_BLOCKLEN*sizeof(uint8_t));  
memcpy(output, state, AES_BLOCKLEN);  
return output;  
}

static uint8_t* Cipher(state_t* state, const uint8_t* RoundKey) {  
uint8_t round = 0;

state_t temp;  
memcpy(&temp, state, AES_BLOCKLEN);  
AddRoundKey(0, &temp, RoundKey);

for (round = 1; round < Nr ; ++round) {  
memcpy(state, &temp, AES_BLOCKLEN);  
RoundFunction(&temp, RoundKey, round);  
}

return LastRound(&temp, RoundKey, round);  
}

uint8_t * AES_ECB_encrypt(const struct AES_ctx* ctx, state_t* buf) {  
return Cipher(buf, ctx->RoundKey);  
}

uint8_t* aes_encrypt_128(data_t *data, const uint8_t *key) {  
struct AES_ctx ctx;

AES_init_ctx(&ctx, key);  
memcpy(data->ciphertext, data->plaintext, AES_BLOCKLEN);

return AES_ECB_encrypt(&ctx, (state_t*)data->ciphertext);  
}  
```

Note that `data->ciphertext` is casted to `state_t` struct and passed to internal AES operations. In the `Cipher()` function there are another `state_t` struct `temp` which is actually used within functions. After each step the value of `temp` is copied into the original `state`, except for the last `RoundFunction()` and for the `LastRound()`:

```c  
static uint8_t* Cipher(state_t* state, const uint8_t* RoundKey) {  
uint8_t round = 0;

state_t temp;  
memcpy(&temp, state, AES_BLOCKLEN);  
AddRoundKey(0, &temp, RoundKey);

for (round = 1; round < Nr ; ++round) {  
memcpy(state, &temp, AES_BLOCKLEN); // <\- the last copy  
RoundFunction(&temp, RoundKey, round);  
}

return LastRound(&temp, RoundKey, round);  
}  
```

So the `data->ciphertext` buffer contains the AES state before the last two rounds. In other words:

```  
data->ciphertext = temp  
// RoundFunction()  
temp = SubBytes(temp)  
temp = ShiftRows(temp)  
temp = MixColumns(temp)  
temp = AddRoundKey(9, temp, RoundKey)  
// LastRound()  
temp = SubBytes(temp)  
temp = ShiftRows(temp)  
temp = AddRoundKey(10, temp, RoundKey)  
// output temp  
ciphertext = temp  
```

So we need to solve a 2-rounds AES to retrieve 9th and 10th round keys.

## Solution

Note that `SubBytes()`, `ShiftRows()` and `MixColumns()` are independent from the key schedule, so our target is simplified a bit:

```  
state1 = MixColumns(ShiftRows(SubBytes(temp)))  
state2 = AddRoundKey(ShiftRows(SubBytes(AddRoundKey(state2))))  
```

We've got a relation between `state1` and `state2`, both states are known. Moreover, we're able to get arbitrary many pairs of `(state1, state2)` for the same AES key:

```python  
def download_state_pair():  
io.sendline(b'1')  
io.sendline(os.urandom(4).hex())  
io.recvuntil(b'You said: ')  
io.sendline(b'2')  
io.recvuntil(b'You said: ')  
line = io.recvline().strip()[1:-1]  
state1 = line[16:32]  
assert len(state1) == 16, 'try again'

io.recvuntil(b'Encrypted echo: ')  
line = io.recvline().strip()  
state2 = bytes.fromhex(line.decode())  
assert len(state2) == 16, 'try again'

# print(f'{state1 = }')  
# print(f'{state2 = }')

state1 = sub_bytes(state1)  
state1 = shift_rows(state1)  
state1 = mix_columns(state1)

return state1, state2  
```

Let's recover the 9th and 10th round keys. We will bruteforce each byte of the 9th key, calculate corresponding byte of the 10th key, and validate these bytes against each `state2` from the `pairs`:

```python  
def recover_round_keys(pairs: List[Tuple[bytes, bytes]]):  
K9 = bytearray(16)  
K10 = bytearray(16)

for j in range(16):  
i = SHIFT_ROWS[j]  
found = False

for k9_candidate in range(256):  
C0 = pairs[0][0][i]  
s0 = pairs[0][1][j]  
k10_candidate = SBOX[C0 ^ k9_candidate] ^ s0

for idx, (_, state2) in enumerate(pairs[1:], 1):  
Cx = pairs[idx][0][i]  
sy = state2[j]  
if SBOX[Cx ^ k9_candidate] ^ sy != k10_candidate:  
break  
else:  
K9[i] = k9_candidate  
K10[j] = k10_candidate  
found = True  
break

if not found:  
raise ValueError('try again')

return bytes(K9), bytes(K10)  
```

When the `K10` is found, we just need to reverse the AES key schedule and recover the master key.

## Flag

```  
alfa{ITs_Ra1ning_4Es_halLeLUjaH}  
```
