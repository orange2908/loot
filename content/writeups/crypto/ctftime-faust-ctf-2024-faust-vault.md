---
title: "FAUST Vault - FAUST CTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "cryptography", "rsa", "aes", "cbc", "prng", "wasm", "proof-of-work", "faust-ctf", "faust-ctf-2024", "2024", "ctf-writeup"]
summary: "The challenge service implements a secure, \"end-to-end encrypted\" key-value store."
source:
  name: "CTFtime writeup #39633"
  url: "https://ctftime.org/writeup/39633"
ctf:
  name: "FAUST CTF 2024"
  year: 2024
  challenge: "FAUST Vault"
---

## Metadata

- **CTF:** FAUST CTF 2024
- **Task:** FAUST Vault
- **Author team:** TeamGeramy
- **CTFtime tags:** cryptography
- **CTFtime:** <https://ctftime.org/writeup/39633>

---
# FAUST Vault

The challenge service implements a secure, "end-to-end encrypted" key-value store. After registering with a username and password, a user can store secrets in the vault, which are encrypted on the client side and then uploaded. The flag checker also has an account with an unknown password, and stores the flag in the vault.

The serverside service `faustvault` is really simple and implements a basic key-value store with no encryption or authentication.  
All of the encryption logic is implemented in the `frontend`, which is built in react, with some parts of the encryption written in Rust and compiled to webassembly. Of particular interest is the `register` function of the `AuthProvider` in `src/providers/AuthProvider.tsx`, which handles the registration of new users:

```js  
const register = async (username: string, password: string, repeatPassword: string): Promise<Result> => {  
if (!enabled) return { severity: 'error', message: 'wasm not initialized' };  
if (password !== repeatPassword) return { severity: 'error', message: 'passwords don\'t match' };  
try {  
const a = new Date().toLocaleTimeString();  
let masterKey = generate_master_key([username, a]);  
const mk = new Uint8Array(29);  
mk.set(new Uint8Array([0, 1, 2, 3, 4]), 0);  
mk.set(masterKey, 5);  
let rsaKeypair = generate_rsa_keys(new TextEncoder().encode(password));  
let encryptedMasterKey = encrypt_master_key(mk, rsaKeypair.e, rsaKeypair.n);  
await store(username, "master-key", buf2hex(encryptedMasterKey));  
await store(username, "e", buf2hex(rsaKeypair.e));  
await store(username, "n", buf2hex(rsaKeypair.n));  
} catch (error) {  
return { severity: 'error', message: error.message };  
}  
return { severity: 'success', message: 'Successfully registered' }  
}  
```

## Vulnerability 1: Bad symmetric key generation  
As we can see above, the master key for a user is generated based on two pieces of information:  
\- The username, which is publicly available via the vault website  
\- The current date and time in string format, which can be estimated

The `generate_master_key` function does not add any more randomness or secrets, it simply takes the two strings, concatenates them, hashes them and seeds a ChaCha PRNG with the hash, which ultimately generates the AES master key. This allows us to search for the master key effectively by trying all possibilities for the registration time - since the output of `toLocaleTimeString()` is accurate to seconds, we can easily try out all possible timestamps with only a few thousand keys. The following rust program implements the attack:

```rs  
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};  
use rand::prelude::*;  
use rand_chacha::ChaCha8Rng;  
use std::env;  
use std::fmt::Write;  
use std::thread::sleep;  
use std::time::Duration;

const NUMBER_OF_BITS_AES: usize = 192;  
const NUMBER_OF_BYTES_AES: usize = NUMBER_OF_BITS_AES / 8;

pub fn generate_master_key(username: &str, password: &str) -> Box<[u8]> {  
let hash_seed: u64 = cityhasher::hash(format!("{username}{password}"));  
Box::new(generate_aes_key(hash_seed))  
}

pub fn decrypt_text(text: Box<[u8]>, master_key: Box<[u8]>) -> Box<[u8]> {  
decrypt_aes(&text, &master_key).into_boxed_slice()  
}

fn decrypt_aes(cipher_text: &[u8], key: &[u8]) -> Vec<u8> {  
let iv = [0x42; 16];  
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;

Aes192CbcDec::new(key.into(), &iv.into())  
.decrypt_padded_vec_mut::<Pkcs7>(cipher_text)  
.unwrap_or_default()  
}

fn generate_aes_key(seed: u64) -> [u8; NUMBER_OF_BYTES_AES] {  
let mut rng: ChaCha8Rng = ChaCha8Rng::seed_from_u64(seed);  
let mut aes_key_bytes: [u8; NUMBER_OF_BYTES_AES] = [0; NUMBER_OF_BYTES_AES];

for byte in 0..NUMBER_OF_BYTES_AES {  
aes_key_bytes[byte] = rng.gen::<u8>();  
}  
aes_key_bytes  
}

fn main() {  
// Get username and encrypted_flag from first and second cli arg  
let encrypted_flag = std::env::args().nth(2).unwrap();  
let username = std::env::args().nth(1).unwrap();

// Decode encrypted_flag  
let encrypted_flag = hex::decode(encrypted_flag).unwrap();  
// Try all combinations of time from 3:10:00 PM to 3:20:00 PM  
  
for i in 0..60 {  
for j in 0..60 {  
for k in 0..12 {  
let date = format!("{}:{:02}:{:02} PM", k, i, j);  
//let date = format!("28.9.2024, 15:{:02}:{:02}",i ,j );  
//println!("{}", date);  
let mut key = generate_master_key(  
&username,  
&date,  
);

// Decrypt  
let decrypted_flag = decrypt_text(  
encrypted_flag.clone().into_boxed_slice(),  
key.clone(),  
);  
if let Ok(flag) = String::from_utf8(decrypted_flag.to_vec()) {  
if flag.len() > 0 {  
println!("Flag: {}", flag);  
}  
}  
}  
}  
}  
}  
```

## Vulnerability 2: Shared RSA private keys  
The master key is stored on the server as well, encrypted by an RSA keypair generated during registration. Interestingly, the RSA private key is never stored, instead it is derived from the user password every time the vault is accessed.

Generating secure RSA keypairs from passwords is non-trivial, so we decided to look into the RSA key generation. This was implemented in a wasm module without source code.

After executing the function for a few different passwords (using the chrome debugger), we noticed that the resulting values for `n` were always the same. Therefore, the value for `n`, and with it the secret primes `p` and `q` needed for private key generation are likely stored in the webassembly program.

To find the key, we used the chrome debugger to analyze the RSA key generator dynamically, by stepping through the execution and looking at potentially interesting values in the memory inspector.  
Ultimately, we found the `p` value by breaking at `$num_bigint::biguint::convert::<impl num_traits::Num for num_bigint::biguint::BigUint>::from_str_radix::haf4967c8f49dfe13` at offset 0x7a65 and observing the memory location pointed to by the `var3` local variable. It contains a decimal number as a string, we confirm that it is indeed one of the primes by testing that `n % p == 0`.

Now, we can obtain the other prime `q = n // p` and compute `phi_n = (p-1)*(q-1)`. Since all keys by the other users use the same `n` (should be the case as long as they registered using the same clientside javascript), we can generate the corresponding private keys to their public keys by taking `d = pow(e,-1,phi_n)`, get the master key, and decrypt the flag.

The following script was used by us to carry out the attack for decrypting the flag stored as a secret.  
```python  
#!/usr/bin/env python3

import os  
import json  
import time  
import random  
import string  
import requests

HOST = os.getenv('TARGET_IP')  
EXTRA = json.loads(os.getenv('TARGET_EXTRA', '[]'))

TEAM_ID = HOST[9:].split(':')[0]  
data = requests.get(f"<https://2024.faustctf.net/competition/teams.json>").json()

if TEAM_ID not in data['flag_ids']['FAUST Vault'].keys():  
print("No info for team")  
exit()

team_data = data["flag_ids"]["FAUST Vault"][TEAM_ID]

def get_value(username, key):  
url = f"http://[{HOST}]:5555/api/store/{username}/{key}"  
#print(url)  
response = requests.get(url)  
try:  
return response.json()['value']  
except json.decoder.JSONDecodeError:  
print("Cannot parse as JSON")  
exit()

n = 639785392362364325840735300516102952407709601788025843355549040225033781937010686068001365584048493582012374003897347365988864714595358273816842674651024890473508988812527426697362711634177550774463085481074840854209909357576434339074455396409128131886683778778879601731372893318306326170697987372056405019502226179838414519087414158890244451770937018042518993603357781007806214023844644748325008015899580943796427524257615900131014745336953490669169181576867445749691941177707596714149072956657588657391908275241642449727114671325622279028448868176318144935735784036924029596456204925481298400484375469792750493962453138384211020440271658436709444471429825395019444706437933745742237632768873029372248208416265937898060000529710067577266357215328028154895943686445836922988283641757303819080070916118685596290835966859229407350379300828640392351853524347881373092183794082647101631504950384306541654598684913237924099759935615070233735684983702054595718753345918766974275286546948846673085066665932107564687650247206906536822319739409044207700640864012707101173569835106925815501500586944978738969867625455422084508178511903862308614848730889026374905600101997404605281922281691922816867032371341087973945677513622910204607748732189  
p = 28530411238587450979597746812505405623042559153825967096062902071674547882698832463515493128928248005168350209357963517257974091918829784942999833651069511729482755784164328136827985008248258974405092403882411146708956128217104013752515990906361088592884575166889480686101648757454071613588626123716907367497369091850209554652465152721639885451450005069477412641200507190933137328276610813589531786216305459848336011749274452068299468696604543972688598503426504930248663420407071697238703002111592388800284301493500051430210145782363009295979458800593194416314276882169669165818507569076677967385557091689851429664731  
q = n // p

phi = (p-1) * (q-1)

import sys  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad  
def decode(val):  
return int.from_bytes(bytes.fromhex(val), 'little')

for username in team_data:  
try:  
masterkey_hex = get_value(username, 'master-key')  
rsa_e_hex = get_value(username, 'e')  
rsa_n_hex = get_value(username, 'n')  
flag = get_value(username, 'flag')

rsa_n = decode(rsa_n_hex)  
rsa_e = decode(rsa_e_hex)  
masterkey_enc = decode(masterkey_hex)

if rsa_n != n:  
print(f'rsa key mismatch: {rsa_n} != {n}')

rsa_d = pow(rsa_e, -1, phi)

masterkey = pow(masterkey_enc, rsa_d, rsa_n)

masterkey_b = masterkey.to_bytes(4096 // 8, 'little')

# masterkey contains padding, which we have to strip away  
aeskey = masterkey_b[5:5+192//8]

# Assuming the flag is hex-encoded  
flag_bytes = bytes.fromhex(flag)

cipher = AES.new(aeskey, AES.MODE_CBC, b'\x42' * 16)  
decrypted_flag = cipher.decrypt(flag_bytes)

print(decrypted_flag.decode().strip())

#print(masterkey_b)

except:  
raise  
```
