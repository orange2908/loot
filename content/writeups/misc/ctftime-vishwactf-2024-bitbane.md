---
title: "BITBANE - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "bitbane", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Suppose the initial character is 'R', and its ASCII value is"
source:
  name: "CTFtime writeup #39529"
  url: "https://ctftime.org/writeup/39529"
original_source: "https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/BitBane%20-%20Cryptic%20Chaos.pdf"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "BITBANE"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** BITBANE
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39529>
- **Original writeup:** <https://github.com/CyberCell-Viit/VishwaCTF-24-Writeups/blob/main/VishwaCTF&#39;24/Cryptography/BitBane%20-%20Cryptic%20Chaos.pdf>

---
* let me walk you through the logic used for encryption .  
Suppose the initial character is 'R', and its ASCII value is  
'82'. According to the code written in the encode function,  
the value of the variable 'idx' will come out to be '(0 % 8) +  
2', which evaluates to '2'. (There's a reason behind  
restricting the index value between 2 and 9; try if you could  
figure it out.) Now both this ASCII value and the 'idx' we  
just calculated are passed to the 'create' function, which  
does the real work.  
* The create function, as seen, is divided into three parts: one  
is to create the topping, the next is to create the base, and  
finally, to put the topping on the base. (I've taken complete  
care to ensure that no data is lost in this bitwise OR  
operation).  
* The createTopping function takes three parameters: the  
ASCII value of the current character, the calculated idx, and  
the reference of the variable named 'not_remainder' (which  
actually isn't any remainder) to store the value inside it.  
Inside this function, two local variables are used: 'temp'  
(just a dummy for 'not_remainder') and 'num', which is  
CHALLENGE NAME : [ BITBANE]  
finally returned. (If you observe carefully, initially it's '1',  
and also while returning, it's ORed with '1'. This is just to  
enable you to differentiate between the base and the  
topping at the time of decryption.) The image below  
explains how things are happening..  
* Now, in the next step, the value inside 'not_remainder' (if  
present) is converted into bits from behind, so it gets  
reversed. Then, the additional bits are appended at the  
end.  
* Finally, the topping is ORed with the base to get the  
encrypted number. Later, this number is passed into  
functions like 'applyKey ' and 'extraSecurity ', which can be  
easily reversed by applying the same functions again.  
Note: In the 'checkValidity ' function, if you think it's  
checking for a prime number, then you are wrong. Upon  
careful observation, you will find that it will return true for  
'4 ', which isn't prime!  
I will be providing the code to get the flag using brute  
force. However, I would suggest you try to solve this  
challenge without brute forcing—it would really test your  
minds. After this thorough explanation of how this  
encryption works, I don't think it would be difficult to code.  
```

int main()  
{  
fstream file;  
file.open("Encrypted.txt");  
if (!file)  
{  
cout << "Error opening file!";  
return 1;  
}  
vector<int> encryptedText;  
int number;  
while (file >> number)  
{  
encryptedText.push_back(number);  
}  
file.close();  
string key = "VishwaCTF";  
extraSecurity(encryptedText);  
applyKey(encryptedText, key);  
string temp =  
"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_";  
int n = temp.size();  
int len = encryptedText.size();  
for (int i = 0; i < len; ++i)  
{  
int idx = (i % 8) + 2;  
for (int j = 0; j < n; ++j)  
{  
int curr = temp[j];  
int num = create(curr, idx);  
if (num == encryptedText[i])  
{  
cout << temp[j];  
break;  
}  
}  
}  
return 0;  
}  
```  
FLAG :-  
`VishwaCTF{BIT5_3NCRYPT3D_D3CRYPTED_M1ND5_D33PLY_TE5T3D}`
