---
title: "simple calc - TSG CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "meet-in-the-middle", "simple", "calc", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "The operation symbols are unnecessary."
source:
  name: "CTFtime writeup #39755"
  url: "https://ctftime.org/writeup/39755"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "simple calc"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** simple calc
- **Author team:** blue-lotus
- **CTFtime:** <https://ctftime.org/writeup/39755>

---
The operation symbols are unnecessary. Instead, directly iterate through all two-digit and three-digit numbers, then combine them together. When searching for five-digit numbers, use the meet-in-the-middle algorithm.

```  
12345678 4Lys8JCEqeC8sPCSkLPjiZg=  
12345679 4Lys8JCEqeC8sPCSkLPjiZk=  
12345680 44me4Lyv8JCErOGbr/CesqE=  
12345681 4Lys8JCEqeC8sPCSkLPjiZs=  
12345682 4Lys8JCEqeC8sPCSkLPjiZw=  
12345683 4Lys8JCEqeKFmvCSkLPwkISe  
12345684 4Lys8JCEqeC8sPCSkLPjiZ4=  
12345685 4Ke044mV8JCEsvCSkLPhjbc=  
12345686 4Lys8JCEqeC8sPCSkLPjirE=  
12345687 4Lys8JCEqeKFnvCSkLPwkISe  
12345688 4Lys8JCEqeC8sPCSkLPjirM=  
12345689 4Lys8JCEqeC8sPCSkLPjirQ=  
12345690 44me4Lyv8JCErOGbsPCesqE=  
12345691 4Lys8JCEqfCQprzwkpCz8JCEng==  
12345692 4Lys8JCEqeC8sPCSkLPjirc=  
12345693 4Lys8JCEqeC8sPCSkLPjirg=  
12345694 4Lys8JCEqeC8sPCSkLPjirk=  
12345695 4Ke044mV8JCEsvCSkLPhjbg=  
12345696 4Lys8JCEqeC8sPCSkLPjirs=  
12345697 4Lys8JCEqeC8sPCSkLPjirw=  
12345698 4Lys8JCEqeC8sPCSkLPjir0=  
12345699 4Lys8JCEqeC8sPCSkLPjir4=  
12345700 4Ke544mR44q88JKQsvCesqE=  
12345701 4Lys8JCEqfCRv4LwkpCz8JCEnw==  
12345702 4Lys8JCEqeC1mfCSkLPwkISf  
12345703 4Lys8JCEqfCRv4XwkpCz8JCEnw==  
12345704 4Lys8JCEqfCRv4fwkpCz8JCEnw==  
12345705 4Lys8JCEqeC1m/CSkLPwkISf  
12345706 4Lys4LWY8JCEsvCSkLPwkISf  
12345707 4Lys4oWU8JCEsvCSkLPjirY=  
12345708 4Lys8JCEqfCQp7bwkpCz8JCEnw==  
12345709 4Lys4oWU8JCEsvCSkLPjirg=  
12345710 44me4Lyv8JCErOOJkfCesqE=  
12345711 4oWR8JCEqeOKu/CSkLPwkISs  
12345712 4Lys8JCEqeCntfCSkLPwkISf  
12345713 4Lys4oWU8JCEsvCSkLPjirw=  
12345714 4Lys8JCEqeKFkPCSkLPwkISf  
12345715 4Lys8JCEqeC1nfCSkLPwkISf  
12345716 4Zuv8JCmvOOKvfCSkLLwnrKh  
12345717 4Lys8JCEqTfwkpCz4Zuu  
12345718 4Lys8JCEqeCntvCSkLPwkISf  
12345719 4Lys8JCEqTfwkpCz4Zuw  
12345720 44me4Lyv8JCErOOJkvCesqE=  
12345721 4Lys8JCEqTfwkpCz44mR  
12345722 4Lys8JCEqTfwkpCz44mS  
12345723 4Lys8JCEqTfwkpCz44mT  
12345724 4Lys8JCEqTfwkpCz44mU  
12345725 4Lys4LWZ8JCEsvCSkLPwkISf  
12345726 4Lys4oWU8JCEsvCSkLPhjbc=  
12345727 4Lys8JCEqTfwkpCz44mX  
12345728 4oWQ8JCEqeOKuPCSkLPwkISs  
12345729 4Lys8JCEqTfwkpCz44mZ  
12345730 44me4Lyv8JCErOOJk/CesqE=  
```
