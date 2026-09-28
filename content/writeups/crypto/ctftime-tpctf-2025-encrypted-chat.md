---
title: "encrypted chat - TPCTF 2025"
category: "crypto"
subcategory: "race"
type: "writeup"
tags: ["crypto", "mtp", "xor", "race-condition", "base64", "race", "tpctf", "tpctf-2025", "2025", "ctf-writeup"]
summary: "All senders share the same key stream, so race condition will happen if two participants send messages at the same time, before receiving the message sent from the other side, and then the key stream"
source:
  name: "CTFtime writeup #40068"
  url: "https://ctftime.org/writeup/40068"
original_source: "https://ouuan.moe/post/2025/03/tpctf-2025#encrypted-chat-15-solves"
ctf:
  name: "TPCTF 2025"
  year: 2025
  challenge: "encrypted chat"
---

## Metadata

- **CTF:** TPCTF 2025
- **Task:** encrypted chat
- **Author team:** TP-Link
- **CTFtime tags:** crypto, mtp
- **CTFtime:** <https://ctftime.org/writeup/40068>
- **Original writeup:** <https://ouuan.moe/post/2025/03/tpctf-2025#encrypted-chat-15-solves>

---
All senders share the same key stream, so race condition will happen if two participants send messages at the same time, before receiving the message sent from the other side, and then the key stream will be reused.

So we need to locate the parts where the key is reused and then decrypt them. Since the messages are in ASCII, we can use the highest bit in each byte to find reused key. The remaining of this challenge is [this assignment in CS255](<https://crypto.stanford.edu/~dabo/cs255/hw_and_proj/hw1.html>).

A simple approach is to XOR the messages and notice that XORing a letter with a space is to toggle its casing. So a character is likely to be a space if its XORs with others are letters. Then manually fix the broken words.

Another approach is to use some language model (e.g. GPT, a small one is enough) to calculate the probability of the next character (use the internal results, not to ask an AI assistant) and apply the Viterbi algorithm. Reference: [A Natural Language Approach to Automated Cryptanalysis of Two-time Pads](<https://dl.acm.org/doi/abs/10.1145/1180405.1180435>). This approach is more accurate but too expensive to implement during a CTF.

Or you can use the known plaintext `TPCTF{` as a starting point.

Here’s my script with an interactive solver to fix the broken words:

```python  
import json  
from base64 import b64decode, b64encode  
from string import ascii_letters

def solve(ciphertexts: list[bytes]):  
n = len(ciphertexts)  
m = len(ciphertexts[0])  
key = bytearray(m)  
for i in range(m):  
count = [0] * n  
for j, x in enumerate(ciphertexts):  
for k, y in enumerate(ciphertexts[:j]):  
if chr(x[i] ^ y[i]) in ascii_letters:  
count[j] += 1  
count[k] += 1  
key[i] = 32 ^ ciphertexts[count.index(max(count))][i]  
plaintexts = []  
for ciphertext in ciphertexts:  
plaintext = bytes(c ^ k for c, k in zip(ciphertext, key))  
plaintexts.append(b64encode(plaintext).decode())  
print(json.dumps(plaintexts))

with open('messages.txt') as f:  
stream = b64decode(f.read())

n = len(stream)  
high_bits = bytes([b >> 7 for b in stream])

i = 0  
while i < n:  
if high_bits.count(high_bits[i:i+50], i) < 5:  
i += 1  
continue  
l = i + 10  
r = i + 40  
k = high_bits.count(high_bits[l:r], i)  
while high_bits.count(high_bits[l-1:r], i) == k:  
l -= 1  
while high_bits.count(high_bits[l:r+1], i) == k:  
r += 1  
pattern = high_bits[l:r]  
ciphertexts = []  
while (p := high_bits.find(pattern, i)) != -1:  
ciphertexts.append(stream[p:p+len(pattern)])  
i = p + len(pattern)  
solve(ciphertexts)  
```

```html

<html>

<head>  
<meta charset="utf-8">  
<title>Encrypted Chat Solver</title>  
<script src="<https://unpkg.com/vue@3/dist/vue.global.prod.js>"></script>  
</head>

<body>  
<div id="app">  
<label>Input: <input v-model="input"></label>  
<div style="font-family: monospace; font-size: 1rem; white-space: pre;">  
<div v-for="(plaintext, i) of plaintexts" :key="i" style="margin-top: 1rem; display: flex; gap: 1px;">  
<div v-for="(c, p) in plaintext" :key="p" @click="changeKey(i, p, c)" style="padding: 1px; cursor: pointer;">  
<span>{{ c }}</span>  
<span>?</span>  
</div>  
</div>  
</div>  
</div>

<script>  
const {createApp, ref, computed, watch} = Vue;

createApp({  
setup() {  
const input = ref('');

const bases = computed(() => {  
try {  
return JSON.parse(input.value).map((b64) => Array.from(atob(b64)));  
} catch {  
return [];  
}  
});

const key = ref([]);  
watch(bases, (stream) => {  
key.value = new Array(bases[0]?.length).fill(0);  
});

const plaintexts = computed(() =>  
bases.value.map((base) => {  
return base.map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ key.value[i]));  
})  
);

function isAsciiPrintable(c) {  
return c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126;  
}

function changeKey(i, p, oldChar) {  
const newChar = prompt(`Change '${oldChar}' to:`, oldChar)?.[0];  
if (!newChar) return;  
key.value[p] ^= plaintexts.value[i][p].charCodeAt(0) ^ newChar.charCodeAt(0);  
}

return {  
input,  
plaintexts,  
isAsciiPrintable,  
changeKey,  
}  
},  
}).mount('#app');  
</script>  
</body>

</html>  
```
