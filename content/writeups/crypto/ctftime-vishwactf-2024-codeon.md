---
title: "CODEON - VishwaCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "codeon", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "RSC BGT FFH HFT TPD WMA OCZ CCD DCZ ZVA"
source:
  name: "CTFtime writeup #39530"
  url: "https://ctftime.org/writeup/39530"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/CODEON.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "CODEON"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** CODEON
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39530>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/CODEON.pdf>

---
### Solution:  
RSC BGT FFH HFT TPD WMA OCZ CCD DCZ ZVA

He gave me some instructions related to it:

He told me he saw some names in call logs; those are: Felix Delastelle, Dmitri Mendeleev.  
He also gave me 2 matrices A and B and told to perform the same operation on matrix A and B as performed on matrix P and Q. Find something related to biochemistry to crack my phone password.  
```  
Matrix A:

45 35 93 95 24 65   
25 15 55 64 36 45   
15 65 62 16 65 38   
19 64 35 69 65 63   
47 67 48 60 39 27   
66 48 77 22 10 69   
```  
```  
Matrix B:

33 25 30 11 68 65   
83 36 19 33 55 51   
20 16 48 63 41 71   
30 42 12 25 31 37   
51 03 44 23 43 85   
20 39 28 41 01 70   
```  
```  
Matrix P:

13 81 60   
40 99 88   
39 87 92   
Matrix Q:

50 52 36   
90 75 28   
80 9 18   
```  
```  
Result Matrix:

60 82 36   
60 109 104   
52 75 4   
```  
Solution:  
BIFID CIPHER encoded:  
RSC BGT FFH HFT TPD WMA OCZ CCD DCZ ZVA  
* For key:  
To find the key, multiply elements of matrix A (A[i][j]) with elements of matrix B (B[i][j]), then take mod of matrix elements of the result matrix, compare numbers of result matrix with the periodic table, then replace numbers with element notation and try to find a key related to biochemistry.

```  
Matrix A (repeated):

45 35 93 95 24 65   
25 15 55 64 36 45   
15 65 62 16 65 38   
19 64 35 69 65 63   
47 67 48 60 39 27   
66 48 77 22 10 69   
```  
```  
Matrix B (repeated):

33 25 30 11 68 65   
83 36 19 33 55 51   
20 16 48 63 41 71   
30 42 12 25 31 37   
51 03 44 23 43 85   
20 39 28 41 01 70   
```  
```

#include <iostream>

using namespace std;

int main() {  
int a[6][6] = {  
{45, 35, 93, 95, 24, 65},  
{25, 15, 55, 64, 36, 45},  
{15, 65, 62, 16, 65, 38},  
{19, 64, 35, 69, 65, 63},  
{47, 67, 48, 60, 39, 27},  
{66, 48, 77, 22, 10, 69}  
};

int b[6][6] = {  
{33, 25, 30, 11, 68, 65},  
{83, 36, 19, 33, 55, 51},  
{20, 16, 48, 63, 41, 71},  
{30, 42, 12, 25, 31, 37},  
{51, 03, 44, 23, 43, 85},  
{20, 39, 28, 41, 01, 70}  
};

for (int i = 0; i < 6; i++) {  
for (int j = 0; j < 6; j++) {  
cout << (a[i][j] * b[i][j]) % 118 << " ";  
}  
cout << endl;  
}  
}  
```  
```  
Result Matrix:

69 49 76 101 98 95   
69 68 101 106 92 53   
64 96 26 64 69 102   
98 92 66 73 9 89   
37 83 106 82 25 53   
22 102 32 76 10 110   
```  
Corresponding Element:

Tm In Os Md Cf Am   
Tm Er Md Sg U I   
Gd Cm Fe Gd Tm No   
Cf U Dy Ta F Ac   
Rb Bi Sg Pb Mn I   
Ti No Ge Os Ne Ds   
Key: “aminoacids”

> DECODED CODON SEQUENCE:

UGC GCA CUG CUU GAG AGG GGG AUU UUU ACC   
C A L L E R G I F T   
(RESP. SEQUENCE WITH ACID NOTATION)

`Flag: VishwaCTF{CALLERGIFT}`
