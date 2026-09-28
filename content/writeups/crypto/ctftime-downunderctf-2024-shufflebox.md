---
title: "shufflebox - DownUnderCTF 2024"
category: "crypto"
type: "writeup"
tags: ["crypto", "begginer", "permutation", "shufflebox", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "full version is here <https://cybersecctf.github.io/blog/?q=shufflebox%20downunderctf2024>"
source:
  name: "CTFtime writeup #39320"
  url: "https://ctftime.org/writeup/39320"
original_source: "https://cybersecctf.github.io/blog/?q=shufflebox%20downunderctf2024"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "shufflebox"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** shufflebox
- **Author team:** Hopper's Roppers
- **CTFtime tags:** crypto, begginer, permutation
- **CTFtime:** <https://ctftime.org/writeup/39320>
- **Original writeup:** <https://cybersecctf.github.io/blog/?q=shufflebox%20downunderctf2024>

---
full version is here <https://cybersecctf.github.io/blog/?q=shufflebox%20downunderctf2024>

we see provided py coded it create random 16 length permutation that change s1 and s2 and s3 to t1 and t2 and t3 on base of txt provided file but   
s3 is not known and should find it with this code so use this code   


```
    #python  
    import itertools
    
    
    
    def find_all(string, char):  
        return [i for i, x in enumerate(string) if x == char]
    
    
    
    
    
    def solve(s1, t1, s2, t2, t3=None):  
        # Collect positions for each character  
        positions = {}  
        for char in 'abcd':  
            positions[char] = find_all(t1, char)
    
    
    
    
    
        # Generate all possible permutations of positions  
        pos = [p1 + p2 + p3 + p4 for p1 in itertools.permutations(positions['a'])  
                                    for p2 in itertools.permutations(positions['b'])  
                                    for p3 in itertools.permutations(positions['c'])  
                                    for p4 in itertools.permutations(positions['d'])]
    
    
    
    
    
        # Check if permutation that works for s1 works for s2  
        valid_perms = []  
        for perm in pos:  
            if ''.join(t2[perm[i]] for i in range(16)) == s2:  
                valid_perms.append(perm)
    
    
    
    
    
        assert len(valid_perms) == 1
    
    
    
    
    
        # Reverse permutation for t3 or s3  
        if t3 is not None:  
            result = ''.join(t3[valid_perms[0][i]] for i in range(16))  
        elif s3 is not None:  
            result = ''.join(s3[valid_perms[0][i]] for i in range(16))  
        else:  
            raise ValueError("Either t3 or s3 must be provided.")
    
    
    
    
    
        return result
    
    
    
    
    
    # Example usage:   
    s1 = "aaaabbbbccccdddd"  
    t1 = "ccaccdabdbdbbada"  
    s2 = "abcdabcdabcdabcd"  
    t2 = "bcaadbdcdbcdacab"  
    t3 = "owuwspdgrtejiiud"  
    print( solve(s1, t1, s2, t2, t3))
```

  
and get flag after run it and wrap it with ductf
