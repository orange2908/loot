---
title: "Flag as a service - Break the Syntax CTF 2025"
category: "misc"
subcategory: "rust"
type: "writeup"
tags: ["misc", "rust", "aes", "cbc", "base64", "break-the-syntax-ctf", "break-the-syntax-ctf-2025", "2025", "ctf-writeup"]
summary: "The provided service exposes a single /flags endpoint that returns AES-CBC-encrypted copies of the secret flag along with their IVs."
source:
  name: "CTFtime writeup #40227"
  url: "https://ctftime.org/writeup/40227"
ctf:
  name: "Break the Syntax CTF 2025"
  year: 2025
  challenge: "Flag as a service"
---

## Metadata

- **CTF:** Break the Syntax CTF 2025
- **Task:** Flag as a service
- **Author team:** rakuz4n
- **CTFtime tags:** misc, rust
- **CTFtime:** <https://ctftime.org/writeup/40227>

---
# **Overview - FlagAsService - Zero Key Vulnerability Due to RDSEED Failure**

The provided service exposes a single /flags endpoint that returns AES-CBC-encrypted copies of the secret flag along with their IVs. Our goal is to decrypt the flag without knowing the key.

We're given a zip containing [main.rs](http://main.rs) which we suspect is backend for this service.

[main.rs](http://main.rs)

```rust

#![feature(vec_into_raw_parts)]

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

use axum::{Router, extract::Json, http::StatusCode, routing::get};

use base64::prelude::*;

use std::arch::x86_64;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

lazy_static::lazy_static! {

static ref FLAG: String = std::env::var("FLAG").unwrap_or_else(|_| {

println!("THE FLAG ENVIRONMENT VARIABLE HAS NOT BEEN SET!!!");

std::process::exit(1);

});

}

fn encrypt_flag(key: [u8; 32], iv: [u8; 16], flag: &str) -> String {

let mut flag_bytes = flag.as_bytes().to_vec();

let len = flag_bytes.len();

flag_bytes.extend_from_slice([0u8; 16].as_ref());

let ct = Aes256CbcEnc::new(&key.into(), &iv.into())

.encrypt_padded_mut::<Pkcs7>(&mut flag_bytes, len)

.unwrap_or_else(|e| panic!("Encryption failed: {e:?}"));

BASE64_STANDARD.encode(ct)

}

fn make_keys(count: usize) -> Vec<[u8; 32]> {

let mut keys: Vec<u64> = vec![0; count * 2];

for num in keys.iter_mut() {

unsafe { x86_64::_rdseed64_step(num) };

}

unsafe {

let (ptr, length, capacity) = keys.into_raw_parts();

Vec::from_raw_parts(ptr as *mut [u8; 32], length / 4, capacity / 4)

}

}

fn make_iv() -> [u8; 16] {

let mut iv = [0u64; 2];

for i in iv.iter_mut() {

unsafe { x86_64::_rdseed64_step(i) };

}

unsafe { std::mem::transmute(iv) }

}

// Define request and response structs

#[derive(serde::Deserialize)]

struct FlagRequest {

amount: usize,

}

#[derive(serde::Serialize)]

struct FlagResponse {

flags: Vec<(String, u128)>,

}

async fn get_encrypted_flags(

Json(request): Json<FlagRequest>,

) -> Result<Json<FlagResponse>, StatusCode> {

// Validate the request

if request.amount > 64 || request.amount == 0 {

return Err(StatusCode::BAD_REQUEST);

}

let amount = request.amount;

let mut encrypted_flags = Vec::with_capacity(amount);

// Generate keys and IVs

#[allow(non_snake_case)]

let mut iv = u128::from_ne_bytes(make_iv());

let keys = make_keys(amount);

// Encrypt the flags

for key in keys {

iv += 1;

let encrypted = encrypt_flag(key, iv.to_ne_bytes(), &FLAG);

encrypted_flags.push((encrypted, iv));

}

// Return the encrypted flags

Ok(Json(FlagResponse {

flags: encrypted_flags,

}))

}

#[tokio::main]

async fn main() {

// Set up the Axum router with /flags endpoint

let app = Router::new().route("/flags", get(get_encrypted_flags));

// Start the server on port 1337

let listener = tokio::net::TcpListener::bind("0.0.0.0:1337").await.unwrap();

axum::serve(listener, app)

.await

.expect("Axum server failed!");

}

```

Rust is super memory safe, right? Then keywords "unsafe" should instantly pique or interest (afterall it has to do something with the keys and IVs {~; )..

It's not that unsafe is inherently bad, but it's where Rust lets you juggle with raw pointers and memory layouts, assuming you've read the safety manual hahaha (which, in this case, involves checking return codes from hardware RNGs!). The Vec::from_raw_parts and std::mem::transmute are doing exactly what they're told: "here's a bunch of bytes, believe they are keys/IVs." If those bytes are zeroes because _rdseed64_step took an unannounced coffee break, then zero-keys it is!

so what happens if this _rdseed64_step() fails

The[ _rdseed64_step intrinsic returns 1 on success and 0 on failure.](<https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/rdseed16-step-rdseed32-step-rdseed64-step.html>) Because the code discards this return value, any failure silently leaves that 64-bit word at zero. -> make_keys builds a Vec<u64> of these (mostly) zeroed words and then reinterprets that buffer as 32-byte AES keys, you get a fair number of all-zero AES-256 keys in your batch.

The vec![0; count * 2] initialization is key. If it were uninitialized memory, the behavior on _rdseed64_step failure would be to leave whatever garbage was in memory, making the exploit harder. But thankfully our Rust programmator did a good job (even with unsafe rust)!

With this we suspect that vulnerability in this service arises from unchecked failures of the Intel _rdseed64_step hardware RNG intrinsic and an unsafe reinterpretation of a raw Vec<u64> buffer into AES keys and IVs, resulting in all-zero keys, predictable IVs, and ultimately a trivial zero-key attack against AES-CBC.

# **Solution script**

[flagasservice.py](http://flagasservice.py)

```python

import requests

import base64

from Crypto.Cipher import AES

from Crypto.Util.Padding import unpad

# Endpoint URL (adjust if you bind to a different host or port)

URL = "http://127.0.0.1:1337/flags"

def u128_to_bytes(iv_int: int) -> bytes:

"""

Convert the 128-bit IV integer into 16 little-endian bytes.

"""

return iv_int.to_bytes(16, byteorder='little')

def try_zero_key(cipher_b64: str, iv_int: int) -> str | None:

"""

Attempt AES-CBC decryption using the all-zero 256-bit key.

Returns the UTF-8 plaintext if padding & decoding succeed, else None.

"""

ciphertext = base64.b64decode(cipher_b64)

iv = u128_to_bytes(iv_int)

zero_key = b"\x00" * 32

cipher = AES.new(zero_key, AES.MODE_CBC, iv=iv)

try:

plaintext_padded = cipher.decrypt(ciphertext)

plaintext = unpad(plaintext_padded, AES.block_size)

return plaintext.decode('utf-8')

except (ValueError, UnicodeDecodeError):

return None

def main():

# Request a batch of 64 encrypted flags

response = requests.get(

URL,

json={"amount": 64},

headers={"Content-Type": "application/json"}

)

response.raise_for_status()

entries = response.json()["flags"]

recovered = []

for idx, (cipher_b64, iv_int) in enumerate(entries):

pt = try_zero_key(cipher_b64, iv_int)

if pt is not None:

print(f"[+] Index {idx}: recovered flag → {pt}")

recovered.append(pt)

if not recovered:

print("[-] No flags recovered; RNG likely did not fail this batch.")

else:

print(f"\n[!] Total recovered: {len(recovered)}")

if __name__ == "__main__":

main()

```

We use snicat to point localhost:1337 to the service : [./sc](<https://github.com/CTFd/snicat>) -b 1337 [feaas-2e50ec1d80afe971.chal.bts.wh.edu.pl](http://feaas-2e50ec1d80afe971.chal.bts.wh.edu.pl)

python3 [flagasservice.py](http://flagasservice.py)

[+] Index 2: recovered plaintext: 'BtSCTF{0h_n0_s0m5_k5ys_ar3_un1n1tl1z3d-5}'

...

[+] Index 62: recovered plaintext: 'BtSCTF{0h_n0_s0m5_k5ys_ar3_un1n1tl1z3d-5}'

[!] Recovered 30 plaintext(s).

# **SUMMARY**

**Failure Model**

The Intel _rdseed64_step intrinsic can silently fail (returning 0), leaving the target word at its previous value (here, zero). Because the code ignores the return value, many generated AES keys and IVs end up all-zero—opening the door to a trivial zero-key attack.

**IV Endianness**

The service treats its 128-bit IV as a native u128 (little-endian) and simply increments it on each request. Your exploit must convert the recovered IV integer back into 16 little-endian bytes to match exactly how the server encrypted the data.

**Error Handling & Caveats**

Real hardware RDSEED failures are uncommon but nonzero; you may need to request multiple batches (or increase the batch size/ putting it in a loop till success) until you encounter enough RNG failures to decrypt a flag with the zero key.

**The flag**

**BtSCTF{0h_n0_s0m5_k5ys_ar3_un1n1tl1z3d-5}**

Moncicak
