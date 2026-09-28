---
title: "Budget SoC - justCTF 2024 teaser"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "ecb", "cbc", "ghidra", "budget", "soc", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "Given flashdump.bin, parse the executable using <https://github.com/tenable/esp32imageparser>."
source:
  name: "CTFtime writeup #39250"
  url: "https://ctftime.org/writeup/39250"
original_source: "https://hackmd.io/@vidner/just-sksd-2024#Budget-SoC"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Budget SoC"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Budget SoC
- **Author team:** SKSD
- **CTFtime:** <https://ctftime.org/writeup/39250>
- **Original writeup:** <https://hackmd.io/@vidner/just-sksd-2024#Budget-SoC>

---
## Budget SoC

Given flashdump.bin, parse the executable using <https://github.com/tenable/esp32_image_parser>. There will be issue if we use the newer version of esptool library, use this patch to solve the issue <https://github.com/tenable/esp32_image_parser/issues/14#issuecomment-2041247535>.   
![image](<https://hackmd.io/_uploads/BkOMByFUC.png>)  
![image](<https://hackmd.io/_uploads/BJdVH1FL0.png>)  
Open 32-bit Tensilica Xtensa file using ghidra. Looking at string "flag" we will found reference to the function that will produce flag like in previous SOC challenge.  
![image](<https://hackmd.io/_uploads/Bk23ByYUC.png>)  
![image](<https://hackmd.io/_uploads/SJRyIkKL0.png>)  
Rename some variable and function to make it easier to analyze.  
```c  
\---snippet---   
// FUN_400d29b  
memw();  
memw();  
iStack_24 = _DAT_3ffc4120;  
FUN_400d88c4(0x3ffc3eec,&DAT_3f400120);  
memcpy_(auStack_94,s___<html>_<head>_<_3f400125);  
if (DAT_3ffc3ca8 != '\0') {  
FUN_400d88c4(0x3ffc3eec,s_here2_3f4002d0);  
if (0x83 < _DAT_3ffc3e3c) {  
allocation_(ciphertext,_DAT_3ffc3e38 + 100,0x20);  
}  
FUN_400d296c(ciphertext,decrypted,0x20);  
memcpy_(auStack_84,decrypted);  
memcpy_(auStack_74,s_<h2>Flag:_3f4002d6);  
uVar2 = FUN_400d8fa8(auStack_74,auStack_84);  
uVar2 = FUN_400d8fd8(uVar2,s_</h2>_3f4002e1);  
FUN_400d8ec4(auStack_94,uVar2);  
FUN_400d8a98(auStack_74);  
FUN_400d88ac(0x3ffc3eec,auStack_84);  
FUN_400d8a98(auStack_84);  
}  
\---snippet---  
```  
So the ciphertext are processed on function FUN_400d296c, next take a look on function FUN_400d296c. There are some constant in the function so it nice to search it on github.  
![image](<https://hackmd.io/_uploads/BkilwJF80.png>)

Search for the constant in 4 bytes format, [https://github.com/search?q=0x52096ad5&type=code](https://github.com/search?q=0x52096ad5&type=code) and found <https://github.com/defanator/mcespi/blob/800d492838ca56dde29e6c56df28249131fda3d4/mcespi.c#L339>. From above code we can see that the constant is actually from aes decrypt process. Looking at another function looks like it is same like in the app0.elf function. So the last step is basically finding the key and the ciphertext used by the function in app0.elf. Rename some variable and function to make it easier to trace.  
```c  
undefined4  
FUN_400d82e4(int instance,undefined4 ciphertext,int param_3,undefined4 param_4,undefined4 key,  
undefined2 length,undefined4 param_7)

{  
undefined4 uVar1;  
int iVar2;  
  
*(instance + 0xfc) = param_3;  
aes_key_expand(instance,key,length);  
iVar2 = param_3 + 0xf;  
if (-1 < param_3) {  
iVar2 = param_3;  
}  
aes_(instance,ciphertext,param_4,iVar2 >> 4,param_7);  
uVar1 = FUN_40173bc4(instance,param_4,param_3);  
return uVar1;  
}  
```  
From the caller function we get the key, which is on the fifth argument (DAT_3ffbdb68). The ciphertext is on second argument and it allocated from function allocation_ that we assume the data is from `_DAT_3ffc3e38`.  
```c  
FUN_400d831c(auStack_134,ciphertext,param_3,output,&DAT_3ffbdb68,0x10,uVar1);  
```  
Looking at ELF file, we know that `_DAT_3ffc3e38` is not stored on it.  
![image](<https://hackmd.io/_uploads/B1pItyKI0.png>)  
So we assume that the data is maybe on runtime memory. Because we have the flashdump.bin we try to directly find the ciphertext by bruteforcing all 32 bytes value in the flashdump.bin. Below is our script to do bruteforce.  
```python  
from Crypto.Cipher import AES

f = open("flashdump.bin", "rb").read()  
key = [0x33,0xBD,0xFB,0x72,0x4C,0x22,0x87,0x33,0x62,0xFF,0x75,0x41,0xD5,0x14,0xF6,0xFD]  
bytes_key = bytes(key)

for i in range(0, len(f) - 32):  
cipher = AES.new(bytes_key, AES.MODE_ECB)  
tmp = f[i:i+32]  
res = cipher.decrypt(tmp)  
if b"just" in res:  
print(i, res)  
```  
![image](<https://hackmd.io/_uploads/B1rVq1K80.png>)  
Looks like we got partial flag, so the mode should be not ECB. The next step we do is trying to use AES CBC with iv null bytes, because the first block is already correct plaintext.  
```python  
from Crypto.Cipher import AES

f = open("flashdump.bin", "rb").read()  
key = [0x33,0xBD,0xFB,0x72,0x4C,0x22,0x87,0x33,0x62,0xFF,0x75,0x41,0xD5,0x14,0xF6,0xFD]  
bytes_key = bytes(key)  
iv = b"\x00"*16  
i = 42308  
cipher = AES.new(bytes_key, AES.MODE_CBC, iv)  
tmp = f[i:i+32]  
print(cipher.decrypt(tmp))  
```  
![image](<https://hackmd.io/_uploads/rkCi5kYUA.png>)

> justCTF{dUmp3d_r3v3rs3d_h4ck3d}
