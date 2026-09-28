---
title: "THE NAUGHTY FRIEND - VishwaCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "ecb", "xor", "base64", "naughty", "friend", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Firstly, Decrypt the key using any ROT-47 decoder:"
source:
  name: "CTFtime writeup #39536"
  url: "https://ctftime.org/writeup/39536"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/The%20Naughty%20friend.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "THE NAUGHTY FRIEND"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** THE NAUGHTY FRIEND
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39536>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/The%20Naughty%20friend.pdf>

---
### Solution: 

Step 1: 

Firstly, Decrypt the key using any ROT-47 decoder: 

You will get the text: YEK EHT FO STRAP "tnatropmI tsoM eht era dnE dna gninnigeB ehT"   
You can notice that the text has been reversed, so you can use any text reverser online to   
get the original text which is : "The Beginning and End are the Most Important" PARTS OF   
THE KEY 

From this you can interpret that we have to take the beginning and the end letters of   
"The Beginning and End are the Most Important" . 

So the key would be: 

TeBgadEdaeteMtIt 

Step 2: 

Firstly we have to fix the code by importing java.security , java.crypto.Cipher and catch   
exception. 

The Fixed code will be like: 

```  
import javax.crypto.Cipher;   
import javax.crypto.spec.*;   
import java.util.Base64;   
import java.util.Scanner;   
import javax.crypto.SecretKey; 

public class fixed {   
public static void main(String[] args) {   
Scanner myObj = new Scanner([System.in](http://System.in));   
String plaintext = "mF1b8dUwdPVhc/0Hfu1ONep6V6oTH-  
nRqhEMEgtCsge+GncFq9YbX1eCkYwmrHTvajsiyj/vd4IV0BbZI1Obq3/uD7nDyAJ/FxZJNAFRAU-  
uGm3LLXf4vn3zKWsZATypBkkgEQLWfIpg0tP13wJRhk6JUVPi17AaKHrodTt-  
WOq54FqKIaT1DoifMjtJ4TCG3IXmjEo+6ZsBokIjxeCjamGBwNAqFaqIik-  
kHJo7L1PiCFds/lAaB38KqHGL/E2pfw0CK3XYzKV8gBdwhnrUq1UN1Q";   
String keyString = "TeBgadEdaeteMtIt";   
byte[] ct = Base64.getDecoder().decode(plaintext);   
myObj.close(); 

try {   
byte[] keyData = keyString.getBytes();   
SecretKey secretKey = new SecretKeySpec(keyData, "Blowfish");   
String decryptedText = decrypt(ct, secretKey);   
System.out.println("Decrypted Text: "+ decryptedText);   
} catch (Exception e) {   
System.out.println("Encryption failed: " + e.getMessage());   
}   
} 

private static String decrypt(byte[] ct, SecretKey secretKey) throws Exception {   
Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");   
cipher.init(Cipher.DECRYPT_MODE, secretKey);   
byte[] decryptedBytes = cipher.doFinal(ct);   
return new String(decryptedBytes);   
}   
}   
```

Step 3: 

From the given Output we get the hints that encryption used is XOR encryption and the   
key lies between 0 to 100. Also the text will start with “Vml”. 

Encrypted Bytes Would be: 

b'mVWAZs_Sj\ni|^\nyzX\x08u\x08vsq~c\nqWulmnali]qsmQb\tmAaUnCvcW\x02' 

The encrypted bytes can be decrypted using a simple python code for brute forcing XOR   
encryption. 

Code:   
```

from pwn import xor   
import base64 

#DECRYPTION   
#Given encrypted byte string   
encrypted_bytes = b'mVWAZs_Sj\ni|^\nyzX\x08u\x08vsq~c\nqWulmnali]qsmQb\tmAaUnCvcW\x02' 

#Brute-force decryption using XOR cipher for keys 1 to 100   
for key in range(1, 101):   
decrypted_bytes = bytearray()   
for byte in encrypted_bytes:   
decrypted_byte = byte ^ key   
decrypted_bytes.append(decrypted_byte) 

decrypted_string = decrypted_bytes.decode() 

if 'Vml' in decrypted_string:   
print("Decrypted String: "+decrypted_string)   
decoded_string = base64.b64decode(decrypted_string).decode()   
print("Decoded String: " + decoded_string)   
break   
```

Output:   
```  
Flag:   
VishwaCTF{P@ssw0rD_Re5eTed_$uccesfu11y}  
```
