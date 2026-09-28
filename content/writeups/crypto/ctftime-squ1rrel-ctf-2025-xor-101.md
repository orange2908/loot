---
title: "XOR 101 - squ1rrel CTF 2025"
category: "crypto"
subcategory: "golang"
type: "writeup"
tags: ["crypto", "xor", "golang", "sprintf", "squ1rrel-ctf", "squ1rrel-ctf-2025", "2025", "ctf-writeup"]
summary: "My bike lock has 13 digits, you might have to dig around!"
source:
  name: "CTFtime writeup #40146"
  url: "https://ctftime.org/writeup/40146"
ctf:
  name: "squ1rrel CTF 2025"
  year: 2025
  challenge: "XOR 101"
---

## Metadata

- **CTF:** squ1rrel CTF 2025
- **Task:** XOR 101
- **Author team:** Raccoon Byte
- **CTFtime tags:** crypto, xor
- **CTFtime:** <https://ctftime.org/writeup/40146>

---
# Description  
My bike lock has 13 digits, you might have to dig around! 434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348

The flag format is squ1rrel{inner_flag_contents}. hint: the inner flag contents only include letters, digits, or underscores.

# Solution  
## Observation  
1\. This has something to do with `XOR` from the title.  
2\. The key is `13 digits` between `0000000000000` to `9999999999999` inclusively.  
3\. The flag is `118 characters hex encoded` or `59 characters when decoded`.  
4\. The flag format is `squ1rrel{...}` with inner flag contents `only include letters, digits, or underscores`.

From these informations we could assume this is XOR encryption.  
One of the property of XOR is that: `A XOR B = C is equivalent to A XOR C = B is equivalent to B XOR C = A`.  
In this case: `Plaintext XOR Key = Ciphertext is equivalent to Plaintext XOR Ciphertext = Key is equivalent to Key XOR Ciphertext = Plaintext`.  
Since we know the flag starts with `squ1rrel{` we could get the key with `Plaintext XOR Ciphertext = Key`.  
The plaintext would be `squ1rrel{` and the ciphertext would be `434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348`.

To XOR it we pair each ASCII value of the plaintext and each ASCII value of the ciphertext.

## Example  
1\. ASCII value of `s` would be `115` and ASCII value of `hex 43` is `67` and `115 XOR 67 = 48`. `48 is ASCII of 0`  
2\. ASCII value of `q` would be `113` and ASCII value of `hex 45` is `69` and `113 XOR 69 = 52`. `52 is ASCII of 4`  
3\. ASCII value of `u` would be `117` and ASCII value of `hex 42` is `66` and `117 XOR 66 = 55`. `55 is ASCII of 7`

After all the XOR process we get `047284567` as the first 9 digits of our key.  
The remaining would be 4 digits between `0000` to `9999` inclusively.  
We could now do `Key XOR Ciphertext = Plaintext`.  
But how do we get the complete 13 digits key?  
We just brute force it and add condition for the inner flag contents `only include letters, digits, or underscores`.

## Golang Program to Brute Force  
```  
package main

import (  
"fmt"  
"strconv"  
)

func main() {  
enc := "434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348"

// convert from hex to decimal  
var chars []byte  
for i := 0; i < len(enc); i += 2 {  
value, _ := strconv.ParseInt(enc[i:i+2], 16, 64)  
chars = append(chars, byte(value))  
}

// brute force key  
p1 := "047284567"  
for i := 0; i < 9999; i++ {  
p2 := fmt.Sprintf("%04d", i)  
key := p1 + p2  
index := 0  
dec := ""  
for i := range chars {  
c := byte(chars[i] ^ key[index])

// validate inner flag only include letters, digits, or underscores.  
if !(i < len(p1) || i == len(chars)-1 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {  
break  
}

dec += string(c)  
index++  
index %= len(key)  
}

if len(dec) != len(chars) {  
continue  
}

fmt.Println(key, dec)  
}  
}  
```

## Brute Force Result  
```  
0472845678903 squ1rrel{iSZmy_l0ck_pA25r0rd_t0o_5h0rQ_oR_mY_fl4g_q0o_LoNg}  
0472845678904 squ1rrel{iSZjy_l0ck_pA25r7rd_t0o_5h0rQXoR_mY_fl4g_q7o_LoNg}  
0472845678905 squ1rrel{iSZky_l0ck_pA25r6rd_t0o_5h0rQYoR_mY_fl4g_q6o_LoNg}  
0472845678906 squ1rrel{iSZhy_l0ck_pA25r5rd_t0o_5h0rQZoR_mY_fl4g_q5o_LoNg}  
0472845678923 squ1rrel{iSXmy_l0ck_pA25p0rd_t0o_5h0rS_oR_mY_fl4g_s0o_LoNg}  
0472845678924 squ1rrel{iSXjy_l0ck_pA25p7rd_t0o_5h0rSXoR_mY_fl4g_s7o_LoNg}  
0472845678925 squ1rrel{iSXky_l0ck_pA25p6rd_t0o_5h0rSYoR_mY_fl4g_s6o_LoNg}  
0472845678926 squ1rrel{iSXhy_l0ck_pA25p5rd_t0o_5h0rSZoR_mY_fl4g_s5o_LoNg}  
0472845678933 squ1rrel{iSYmy_l0ck_pA25q0rd_t0o_5h0rR_oR_mY_fl4g_r0o_LoNg}  
0472845678934 squ1rrel{iSYjy_l0ck_pA25q7rd_t0o_5h0rRXoR_mY_fl4g_r7o_LoNg}  
0472845678935 squ1rrel{iSYky_l0ck_pA25q6rd_t0o_5h0rRYoR_mY_fl4g_r6o_LoNg}  
0472845678936 squ1rrel{iSYhy_l0ck_pA25q5rd_t0o_5h0rRZoR_mY_fl4g_r5o_LoNg}  
0472845678953 squ1rrel{iS_my_l0ck_pA25w0rd_t0o_5h0rT_oR_mY_fl4g_t0o_LoNg}  
0472845678954 squ1rrel{iS_jy_l0ck_pA25w7rd_t0o_5h0rTXoR_mY_fl4g_t7o_LoNg}  
0472845678955 squ1rrel{iS_ky_l0ck_pA25w6rd_t0o_5h0rTYoR_mY_fl4g_t6o_LoNg}  
0472845678956 squ1rrel{iS_hy_l0ck_pA25w5rd_t0o_5h0rTZoR_mY_fl4g_t5o_LoNg}  
0472845678983 squ1rrel{iSRmy_l0ck_pA25z0rd_t0o_5h0rY_oR_mY_fl4g_y0o_LoNg}  
0472845678984 squ1rrel{iSRjy_l0ck_pA25z7rd_t0o_5h0rYXoR_mY_fl4g_y7o_LoNg}  
0472845678985 squ1rrel{iSRky_l0ck_pA25z6rd_t0o_5h0rYYoR_mY_fl4g_y6o_LoNg}  
0472845678986 squ1rrel{iSRhy_l0ck_pA25z5rd_t0o_5h0rYZoR_mY_fl4g_y5o_LoNg}  
0472845679903 squ1rrel{hSZmy_l0ck_pA35r0rd_t0o_5h1rQ_oR_mY_fl4f_q0o_LoNg}  
0472845679904 squ1rrel{hSZjy_l0ck_pA35r7rd_t0o_5h1rQXoR_mY_fl4f_q7o_LoNg}  
0472845679905 squ1rrel{hSZky_l0ck_pA35r6rd_t0o_5h1rQYoR_mY_fl4f_q6o_LoNg}  
0472845679906 squ1rrel{hSZhy_l0ck_pA35r5rd_t0o_5h1rQZoR_mY_fl4f_q5o_LoNg}  
0472845679923 squ1rrel{hSXmy_l0ck_pA35p0rd_t0o_5h1rS_oR_mY_fl4f_s0o_LoNg}  
0472845679924 squ1rrel{hSXjy_l0ck_pA35p7rd_t0o_5h1rSXoR_mY_fl4f_s7o_LoNg}  
0472845679925 squ1rrel{hSXky_l0ck_pA35p6rd_t0o_5h1rSYoR_mY_fl4f_s6o_LoNg}  
0472845679926 squ1rrel{hSXhy_l0ck_pA35p5rd_t0o_5h1rSZoR_mY_fl4f_s5o_LoNg}  
0472845679933 squ1rrel{hSYmy_l0ck_pA35q0rd_t0o_5h1rR_oR_mY_fl4f_r0o_LoNg}  
0472845679934 squ1rrel{hSYjy_l0ck_pA35q7rd_t0o_5h1rRXoR_mY_fl4f_r7o_LoNg}  
0472845679935 squ1rrel{hSYky_l0ck_pA35q6rd_t0o_5h1rRYoR_mY_fl4f_r6o_LoNg}  
0472845679936 squ1rrel{hSYhy_l0ck_pA35q5rd_t0o_5h1rRZoR_mY_fl4f_r5o_LoNg}  
0472845679953 squ1rrel{hS_my_l0ck_pA35w0rd_t0o_5h1rT_oR_mY_fl4f_t0o_LoNg}  
0472845679954 squ1rrel{hS_jy_l0ck_pA35w7rd_t0o_5h1rTXoR_mY_fl4f_t7o_LoNg}  
0472845679955 squ1rrel{hS_ky_l0ck_pA35w6rd_t0o_5h1rTYoR_mY_fl4f_t6o_LoNg}  
0472845679956 squ1rrel{hS_hy_l0ck_pA35w5rd_t0o_5h1rTZoR_mY_fl4f_t5o_LoNg}  
0472845679983 squ1rrel{hSRmy_l0ck_pA35z0rd_t0o_5h1rY_oR_mY_fl4f_y0o_LoNg}  
0472845679984 squ1rrel{hSRjy_l0ck_pA35z7rd_t0o_5h1rYXoR_mY_fl4f_y7o_LoNg}  
0472845679985 squ1rrel{hSRky_l0ck_pA35z6rd_t0o_5h1rYYoR_mY_fl4f_y6o_LoNg}  
0472845679986 squ1rrel{hSRhy_l0ck_pA35z5rd_t0o_5h1rYZoR_mY_fl4f_y5o_LoNg}  
```

Now we have 40 possible flags.  
Skim it and the most likely inner flag contents prefix is `iS_my`.  
Finally we get the key is `0472845678953` and the flag (^<^)b

# Flag  
`squ1rrel{iS_my_l0ck_pA25w0rd_t0o_5h0rT_oR_mY_fl4g_t0o_LoNg}`
