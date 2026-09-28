---
title: "THEY-ARE-COMING - VishwaCTF 2024"
category: "web"
subcategory: "aes"
type: "writeup"
tags: ["web", "web-exploitation", "aes", "cbc", "base64", "they-are-coming", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "1\\. robots.txt Directory:"
source:
  name: "CTFtime writeup #39508"
  url: "https://ctftime.org/writeup/39508"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/They%20are%20coming.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "THEY-ARE-COMING"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** THEY-ARE-COMING
- **Author team:** CyberCellVIIT
- **CTFtime tags:** web_exploitation
- **CTFtime:** <https://ctftime.org/writeup/39508>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Web/They%20are%20coming.pdf>

---
Solution:  
1\. robots.txt Directory:

The homepage hints towards checking the /robots.txt directory. Upon accessing it, we find an encrypted text and a decryption key.  
2\. Decoding the Cipher:

Using a Base64 decoder, the cipher text from the /robots.txt leads us to the URL /secret-location.  
3\. Analyzing /secret-location:

On this page, there is a statement with important keywords hinting at the encryption type: AES128 CBC.  
This hint is also present in the HTML source code.  
4\. Decrypting the Cipher Text:

In the browser's local storage, there is a flag field containing cipher text. To decrypt it, we already know the encryption type (AES128 CBC) and the decryption key from /robots.txt.  
Use an online tool like AES-128-CBC Decryption to decrypt the text.  
5\. Get the Flag:

After decrypting the cipher, the flag is revealed.  
`Flag: VishwaRecruits{g0_Su8m1t_1t_Qu14kl7}`
