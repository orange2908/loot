---
title: "shiny-shells - DEF CON CTF Qualifier 2024"
category: "crypto"
subcategory: "asymmetric"
type: "writeup"
tags: ["crypto", "paillier", "homomorphic", "ghidra", "proof-of-work", "shiny-shells", "asymmetric", "def-con-ctf-qualifier", "def-con-ctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "2024-05-05  2026-03-29  About 600 words  3 minutes"
source:
  name: "CTFtime writeup #39141"
  url: "https://ctftime.org/writeup/39141"
original_source: "https://sylvainpelissier.gitlab.io/posts/2024-05-04-defcon-shiny-shells/"
ctf:
  name: "DEF CON CTF Qualifier 2024"
  year: 2024
  challenge: "shiny-shells"
---

## Metadata

- **CTF:** DEF CON CTF Qualifier 2024
- **Task:** shiny-shells
- **Author team:** Soudure au beurre
- **CTFtime tags:** paillier, homomorphic
- **CTFtime:** <https://ctftime.org/writeup/39141>
- **Original writeup:** <https://sylvainpelissier.gitlab.io/posts/2024-05-04-defcon-shiny-shells/>

---
# DEF CON CTF Qualifiers - Shiny-Shells 

[__Sylvain](https://github.com/sylvainpelissier "Author")

 __2024-05-05  __2026-03-29  __About 600 words  __3 minutes

Contents __

_This is the solution of the first LiveCTF Challenge “shiny-shells” of[DEF CON CTF Qualifiers](https://quals.2024.nautilus.institute/). A Paillier cryptosystem allowing, thanks to multiplicative homomorphic multiplication, to change the executed command._

### Details

Points: 50

Category: Crypto

### Description

This is a LiveCTF challenge. You have 33 minutes (until 2024-05-04 17:00:00 UTC) left to solve it. After that time, the challenge will no longer be worth any points for new solves.

The amount of points you received for solving this challenge depended on how quickly you solved it compared to other teams. This challenge is currently depreciating by 1 point every 6 minutes. Better solve it fast! This challenge has been unlocked for about 3 hours (starting at 2024-05-04 13:00:00 UTC) and 36 team(s) have solved it… See LiveCTF rules for more details and current challenge point value.

Download Link: [Download](https://sylvainpelissier.gitlab.io/resources/2024/defcon/shiny_shells/shiny-shells.tar)

### Solution

In the archive we are given a binary which is not doing much:

__________

```
     1
     2
     3
     4
     5
     6
     7
     8
     9
    10
    11
    12
    13
    14
    15
    16
    17
    18
    19
    20
```

| 

```
    Welcome to Shiny Shell Hut!
    1. View wares
    2. Get a shiny shell
    3. Leave
    > 1
    Stock:
      1. A shiny shell
      2. A shiny shell
      3. A shiny shell
    Welcome to Shiny Shell Hut!
    1. View wares
    2. Get a shiny shell
    3. Leave
    > 2
    Sorry, our shells are not for sale :(
    Welcome to Shiny Shell Hut!
    1. View wares
    2. Get a shiny shell
    3. Leave
    > 3
```  
  
---|---  
  
 __

A quick analyis in Ghidra shows that there is two hidden menus: ![ghidra](https://sylvainpelissier.gitlab.io/resources/2024/defcon/shiny_shells/ghidra.png)

Menu `5` launches the script `backdoor.py` and menu `4` launch the same script with an argument. Without any argument, the Python script hashes the string `"ls"`, encrypts it with Paillier cryptosystem, prints the result. decrypts the result, verify if the resulting hash match the previous hash and finally if it matches the command is runned:

__________

```
     1
    2
    3
```

| 

```
    $ python backdoor.py
    {"hash": 90332780745442119779253857231558597566447620910226630319466684469499960556217, "ctxt": 106120616919326949705109513622463846660649172043198899950064581580958184641297822119197204594417731389199975224894131929323804784150221826195085489708565544529410644975229759207518761223969920399932854037177535355351389140005112575585391978960239893398554552756330864646285804948731937035776153060440197456757451814288374891572622355456854544276440238899393652618463751710583984205519441329671184895063728718540013973599875880125865367521733108328937367337701452818218383287858548427273994297536604661789353632388281522283435386848767461195175817516100595476714127635727543851642402987709490247868132530273145872019127588549335368675024936127018802995899637307722697917318051371873010968949329294007616361709954633999708002780341543338552278216644296837391427317536038804561136751145932588977162300830517747387030533444446713817168757616303111940016416546372658550282322249901496522592843648182903430468492742036519301703054663962901188799583472560397759465710265333303665119633643072134746009025712504961564507603736236875075176951523488537015712776135228034228044279896988732285514786891110210662852350201910331715069572553823711508139573525445431198622130614265738586675852707518450877669775333272106187687849280209649194291858132, "n": 20848448396122242024407711036805827569545259421307356767461283885549769600091718753227229095509414042321058125258322121523097438398618572790825339546379886213166841034888056384587291493835315104882937586557381703065083313433405844513448229453435377124742172644489103094019137141908897130533197468961794807279255898317896008234759208823579839231905498622598956342071586173090841881483630835385665962077903735829108600948248176935651695725339360855964691968031392635064044923918043852366215366430740050840885773796023923630976155090021956553165576932128197722336249274783532465070327202178837019941312987342992870974343}
    backdoor.py  challenge	config.toml  Dockerfile  gen.py  key.json
```  
  
---|---  
  
If an argument is given to the script, it is decrypted and the command sent is runned if the two hashes match. The goal for the LiveCTF challenges is to launch the command `./submitter` which displays the flag.

Paillier cryptosystem has a multiplicative homomorphic multiplication. It means that for to message $m_1$ and $m_2$ we have: 

$$ D(E(m_1, r_1)^{m_2}\bmod n^2) = m_1 m_2 \bmod n$$

Note that Paillier cryptosystem has other homomorphic properties but they require either to have the generator $g$ or another ciphertext but we don’t have those values. We have only the value of the ciphertext, the hash and $n$.

So the idea is to build $m_2$ such that $m_1 m_2 \bmod n$ results in `"./submitter"` with $m_1$ being `"ls"`. This is simply done by inverting $m_1 \bmod n$ and multiplying by the desired command:

__________

```
     1
    2
    3
    4
    5
    6
    7
```

| 

```
    # New ciphertext
    cmd1 = int.from_bytes(b"ls", 'big')
    cmd2 = int.from_bytes(b"./submitter", 'big')
    n_2 = n*n
    m2 = (pow(cmd1, -1, n) * cmd2) % n
    c = pow(c,m2,n_2)
    hash_int = int(hashlib.sha256(b"./submitter").hexdigest(), 16)
```  
  
---|---  
  
We also have to adjust the hash to match the desired command. The full script is available [here](https://sylvainpelissier.gitlab.io/resources/2024/defcon/shiny_shells/solve.py). Hopefully it runs well on the server and display the flag:

![flag](https://sylvainpelissier.gitlab.io/resources/2024/defcon/shiny_shells/flag.png)

Updated on 2026-03-29 

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

[Read Markdown](https://sylvainpelissier.gitlab.io/posts/2024-05-04-defcon-shiny-shells/index.md "Read Markdown")

[__](javascript:void\(0\); "Share on X")[__](javascript:void\(0\); "Share on Facebook")[__](javascript:void\(0\); "Share on 微博")

[Back](javascript:void\(0\);) | [Home](https://sylvainpelissier.gitlab.io/)

[__DiceCTF 2024 - Winter](https://sylvainpelissier.gitlab.io/posts/2024-02-04-dicectf-winter/ "DiceCTF 2024  - Winter
")[Black Alps 2024 CTF - BBS __](https://sylvainpelissier.gitlab.io/posts/2024-11-08-black-alps-bbs/ "Black Alps 2024 CTF - BBS ")
