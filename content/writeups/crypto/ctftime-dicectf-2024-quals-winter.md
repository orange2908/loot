---
title: "Winter - DiceCTF 2024 Quals"
category: "crypto"
type: "writeup"
tags: ["crypto", "winter", "dicectf-2024-quals", "2024", "ctf-writeup"]
summary: "A simple implementation of the Winternitz signature scheme."
source:
  name: "CTFtime writeup #39285"
  url: "https://ctftime.org/writeup/39285"
original_source: "https://gist.github.com/Fasnon/2dc75e531f20b2215ed7a29d67bd662c"
ctf:
  name: "DiceCTF 2024 Quals"
  year: 2024
  challenge: "Winter"
---

## Metadata

- **CTF:** DiceCTF 2024 Quals
- **Task:** Winter
- **Author team:** TOP PROGRAMMER 2005 DATABASE MAESTRO
- **CTFtime:** <https://ctftime.org/writeup/39285>
- **Original writeup:** <https://gist.github.com/Fasnon/2dc75e531f20b2215ed7a29d67bd662c>

---
## winter  
### DiceCTF 2024 Quals  
### Topic: Crypto, 169 solves / 116 points  
### Idea/Concepts: Hash Based Encryption Algorithms, Reuse of private keys

Chall description:

A simple implementation of the Winternitz signature scheme.  
nc [mc.ax](https://mc.ax) 31001

### Background Information  
This is a post-quantum hashing signature scheme. The sender uses the secret key, and this is used to generate signatures and calculate the public key. The receiver will then receive the signature, the message, and use the two to verify that the message indeed comes from the sender.

Here are some diagrams to explain how this works.

Diagram of Key Generation:  
![Frame 3](<https://gist.github.com/assets/64513649/a1b638f7-c768-421a-9573-323cddfbc3d9>)

Diagram of Signature Generation:  
![Frame 1(1)](<https://gist.github.com/assets/64513649/4a6bbe02-3637-4af3-a22c-a3925b13336b>)

Diagram of Signature Verification:  
![Frame 2](<https://gist.github.com/assets/64513649/c45a156f-2955-4c65-9d0c-41e5e0bb7c61>)

### Notice that in [server.py](http://server.py) we are reusing the secret key.  
If we can find 2 hex digests where each of the 32 8-bit values are larger in one than the other, we can forge signatures!

Here's a general idea on how this works:  
![Frame 4](<https://gist.github.com/assets/64513649/563fbed8-cd65-473a-89f5-51616e3ba79a>)

We create a simple script to do this.

```  
import secrets  
found=False  
while not found:  
msg1 = secrets.token_hex(99)  
msg2 = secrets.token_hex(99)  
has1 = [a for a in hash(bytes.fromhex(msg1),1) ]  
has2 = [a for a in hash(bytes.fromhex(msg2),1) ]  
bruh = True  
for i in range(len(has1)):  
if(has1[i] < has2[i]):  
bruh = False  
if bruh:  
print(msg1)  
print(msg2)  
if (msg1 != msg2):  
found = True

```  
After a while, really a long time, of this running, we get 

```  
msg1 = 18315eb278b2949c39e1dc5e1b06d002ae16b9af6c70aa0b226921c2cf4bc1cb5a13387e71a83f31bb68d456351549256c39c14855fce9687c1a7e3368784e77a2115add2e3e5253a073aa805ee04d96336d0eb0d41b124002880554e84cd47e8d0b35,  
msg2 = e16a660eaab5f4f1d414580e24bd65340bb29aa2b8f819f838cf4eb18fc757b7168731bfb2f9e8822bef99fcff733d214c5e07d0ad140f66985cc73c01db17e5404b779a7ff624912c534d4ba29d0688e736eb06d5c5835a2820b0745441f719aeecf7  
```

We can find how many more times the file needs to be hexed by using:

```  
has3 = []  
for m in range(len(has1)):  
has3 += [has1[m] - has2[m]]  
has3

has3 = [115, 84, 81, 132, 178, 65, 96, 185, 54, 47, 171, 123, 134, 61, 87, 23, 158, 59, 47, 23, 78, 139, 72, 67, 128, 71, 20, 174, 4, 159, 102, 75]  
```

Great! Now we can use msg1 to get a signature, which we then split into 8-bit values which are then hashed with the corresponding value in has3.  
![](https://gist.github.com/assets/64513649/8f347ec5-e5b7-4d31-bccd-a476add86565)

Copying this in and running the remaining hashes.  
```  
import binascii  
sig = bytes.fromhex("6d0160416694fd3a4e072779ef2519c380670c1d3afbe9935770967fdf1cd619aba6315d42942295fa8850ead796498344ba0fd5d0267887bc770dfaa59913ae881ac1e8bdf90499f6537a40e822da8e7062b1e1f0cb8da77e930776e564daea850a59182a7b8202fed190759f6c1dea087e0a13d84ea72f5aa1a827572b14818ba49ec8e9b5f8e8d8fd0d2bee6713ea3ea2e2b443e507d132456162d1a40db9f808c4192c7ece895dc34e3d654305749606ba9fb88907fb3467dc3ee7316049c975cfaf317ad232a25a6d8853b25dfa5ec1c790eca4bf490ea2213c4a4645ef8db5855921015d50bc920d1cda1435cd9100f6a1ea8f1c0fb90243dc06f90d718c6f4224144e17b57bcda366bef535938386d2d2a0ca5cdfbb837809f0f89d9df51debdc3299cdfb32a25dccee8b93374d4c0feddf68d7b428b29095e2cbfc26d5d4a8327423998fde6fd71ba79b1ec0f0a98c02b465bfd78a733087910ef056d83d951c056982e66d6190aa9019c9101ef7f556a5c905a48381de725560493f5fb5128f974e6fb0bda943320c8ea79ce2b207a6626cea8a26776326fd0add1f9072e9d51a22426aebe882c577901381d682112093d379c2ca4d46be3b1fbd30079a8e5709d036170af9f3d90f23516a86f244799d6db3dbac20890ff85bfacc80504952d53c59529ced186ba661e72a9e20af31d353072fafd25978c61087fdb2179eef0f67ea3916bc2cc8ec13be92a0b249a4983b38b8ffe913fc3831af1c0091f55135178ba4adbc2d7586da8b1245465f2b62695616ebef77bbc5989def144235c605c9972fb4afafdabd01691249a0aa1b758c2b81671654058defb038ba5464be3e7e4f48935e4b024d3e03d897c90bc1deda456bfeb9d7d1716608d7294ef02b255e32aaf8b8151807bb5d4df0cbf9b6001799e3d36cd64739ac01f01f8b90d455cb3397b131def7e600b9f4f4df4800a4543535320b5fb480e999c7b0540c8efc6c10d4a676d8ee35893581e360b294e45653807e15eeac735a1b95eb29e5a65252ffcd719dcd4b2667ca66bf6c82d108312e035d4e0294b09a8249bb988e3c2ee17f345a343644c33f513cf1519bc62b2eb32136a85b5d57d288f883e70065afbc13165cdb69ea238bcb91cf7bde3bc6aea68213d18faab2e4bfae1a213140c3a087b458a6c2629face543442f0c919ba47478df9602a591fcc019267a4a1ff108c23a950f289323777f742e24931cadd01a261a8e7947a6bc1b1525d26a44d857a3b49e3f151a8b6189514f12a8976135bacf74bdb4c782c00b62a78fb335db2bbd2b05b7ae2b85709d1295e29ce7b0c28268f73180253dbd65a7955417714602e9fd928512cdf3e261034c888049eb5d870f3d179f03ecbe33a1077ee9541e6d3161af6d6fff8529365eb7cc934150c28c3c247900a3a9c429b4") # pasting the signature we got  
chunks = [sig[i:i+32] for i in range(0, len(sig), 32)]  
vk = [hash(x, n) for x, n in zip(chunks, has3)]  
binascii.hexlify(b"".join(vk))  
```  
We get our forged signature. Pasting this into the terminal...

![](https://gist.github.com/assets/64513649/e07916b0-efd2-436d-a145-96224fbb9e58)

Boom, out comes the flag. `dice{according_to_geeksforgeeks}`

### Extension: How can we make it secure.  
We can implement an (inverse) checksum!

We generate it and append it to the hashed message. 

The length of the secret key, and public key will increase in order to accomodate additional two 8-bit numbers of the checksum, and they will still be generated same as before.

The signature generation will be modified as follows:

![Frame 5(1)](<https://gist.github.com/assets/64513649/83426788-5fea-49a3-8415-f3c021d2c5da>)

Our attack fails since by ensuring that one of the hashes is 'strictly' greater than the other, the checksum of the first message will have to be smaller.

Here's a visualisation on why:

![Frame 6](<https://gist.github.com/assets/64513649/6fc564a9-2c61-403e-812f-3746b1aa30d8>)

However, it should be noted this is still possible to be cracked (i.e. forge more signatures) if we're allowed to generate 2 signatures from 2 known messages...

### References:  
<https://www.geeksforgeeks.org/winternitz-one-time-signature-scheme/> (lol)  
  
<https://sphere10.com/articles/cryptography/pqc/wots>

<https://csrc.nist.gov/csrc/media/Presentations/2022/crclub-2022-10-19a/20221020-crypto-club-kelsey-slides-MD-hash-sigs.pdf>
