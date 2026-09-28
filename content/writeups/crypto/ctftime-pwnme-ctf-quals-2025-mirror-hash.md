---
title: "Mirror Hash - PwnMe CTF Quals 2025"
category: "crypto"
subcategory: "hash"
type: "writeup"
tags: ["crypto", "hash-collision", "cryptography", "birthday-attack", "mirror", "hash", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "I participated to the PwnMe CTF 2025 this weekend (02/03/2025), and I thought it would be fun to write about one of its CRYPTO challenges that confused many: Mirror Hash."
source:
  name: "CTFtime writeup #40064"
  url: "https://ctftime.org/writeup/40064"
original_source: "https://gniot.fr/2025/03/03/ctf-writeup.html"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "Mirror Hash"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** Mirror Hash
- **Author team:** Les Stagiaires
- **CTFtime tags:** hash-collision, cryptography
- **CTFtime:** <https://ctftime.org/writeup/40064>
- **Original writeup:** <https://gniot.fr/2025/03/03/ctf-writeup.html>

---
I participated to the PwnMe CTF 2025 this weekend (02/03/2025), and I thought it would be fun to write about one of its CRYPTO challenges that confused many: Mirror Hash. It was rated as a Hard challenge and was worth 500 points during the competition.

Before all, you can retrieve the sources of this challenge below:

[challenge.py](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/challenge.py) [Hack.zip](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/Hack.zip)

  


#### The challenge: finding a collision for a custom hash

In this challenge, we are provided with the python script _challenge.py_ that is used on the PwnMe server and an archive _Hack.zip_. The goal is to interact appropriately with the script to retrieve a flag.

Having a first glance at _challenge.py_ , we observe that it implements a custom hash function that is used to hash byte strings of arbitrary length, i.e. it deterministically derives a value from them, (hopefully) with cryptographic guarantees. However, hash functions are known to be hard to design… In this case, looking further in the script, we are asked to break the collision resistance of this hash function in order to get the flag. In more concrete terms, we have to come up with a new file for which the custom hash provides the same value as for the provided file _Hack.zip_.

The first thing to do now is to understand in detail the custom hash function provided to see if we notice any weakness.

#### How does the provided custom hash works?

Let’s look at how the hash function is implemented!

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
    21
    22
    23
    24
    25
    26
    27
    28
    29
    30
    31
    32
    33
    34
    35
    36
    37
    38
    39
    40
```

| 

```
    import hashlib
    import struct
    from secret import FLAG
    
    class CustomSHA:
        def __init__(self, data: bytes):
            self.data: bytes = data
    
        def process(self) -> str:
            h0 = 0x674523EFCD.to_bytes(5, byteorder='big')
            h = h0
            data = self.preprocess()
    
            for i in range(0, len(data), 8):
                chunk = data[i:i+8]
    
                h = hashlib.sha256(chunk + h).digest()[:5]
    
            return f'{h.hex()}'
    
        def preprocess(self) -> bytes:
            data = self.data
            data = bytearray(data)
    
            data.append(0x80)
            while len(data) % 8 != 0:
                data.append(0x00)
    
            data += struct.pack('>Q', 8 * len(self.data))
    
            return bytes(data)
    
    
        def sha_custom(self):
            return self.process()
    
    with open("Hack.zip", "rb") as f:
        data_hack = f.read()
        CustomSHA(data_hack)
        sha_custom_hack = CustomSHA(data_hack).sha_custom()
```  
  
---|---  
`
```

It takes as input an array of bytes, and it first preprocesses it:

  1. It adds a special character and padding at the end to extend the array of bytes to a length multiple of 8.
  2. It also encodes the size of the original bytearray at the end. We will see later that this plays a crucial role in preventing trivial attacks.


Then, the actual hashing starts. It starts from a fixed initial hash \(h_0\), and then it derives sequentially a new hash for each block of 8 bytes \(c\) of the input by computing \(\mathsf{SHA256}(c || h)\) assuming \(h\) was the hash of the previous iteration. Crucially, at each iteration, it only keeps 5 bytes of the \(\mathsf{SHA256}\) output.

Eventually the final file hash is the last \(h\). Note that although it includes only the last \(h\), the inclusion of the previous \(h\) in each iteration ensures a dependency on every byte of the input.

Here’s a simplified visualization of the hashing of _Hack.zip_ , splitting its (preprocessed) content in blocks \(c_i\).

![](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/draw0.svg)

#### Can we find a weakness?

A pretty straightforward weakness we can notice is the fact that only 5 bytes of \(\mathsf{SHA256}\) are used… This means there are \(2^{5\cdot 8} = 2^{40}\) possible values for the final hash.

A possible strategy to solve this challenge could be to try random files until we get the same final hash. Assuming that \(\mathsf{SHA256}\) outputs random looking bits, this would require on average \(2^{40}\) attempts. With enough computation power and time this actually could work. However, in the context of this challenge we had limited time and wanted a faster solution.

Another strategy we could think of is to exploit the [Birthday paradox](https://en.wikipedia.org/wiki/Birthday_problem), and also attack intermediate values of \(h\). Consider a space of dimension \(2^n\). The birthday paradox states that if you sample uniformly \(2^{n/2}\) elements in that space, there’s a good chance that two will be equal. Applied to hash functions, it implies that for a hash function with \(n\) bits in output, you can find a collision (two inputs with same output) after roughly \(2^{n/2}\) random samples.

For our case, we could for instance try to sample random bytes \(c’\), concatenate them with \(h_0\) to compute \(h’ = \mathsf{SHA256}(c || h_0)\) until there exists an \(h_k = h’\) that was also computed during the hashing of _Hack.zip_. Then, the hope would be to simply replace by \(c’\) the bytes of _Hack.zip_ used until \(h_k\) was derived. _Hack.zip_ having \(1,927,317\approx 2^{21}\) blocks, this technique will very quickly find such \(h’\).

![](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/draw1.svg)

Sadly, recall from ealier that the custom hash function includes the size of the file at the end of the buffer used to derive the \(h\)… Since this technique will produce a file of lower size than _Hack.zip_ , the last bytes of the sequence will also change and the final hash will differ.

#### Hmmm…

At this point, we may feel a bit sad that our initial attempts failed.

But not all is lost… We can realized that the above strategy would have worked had we been able to preserve the same file size!

In the above example, we looked for a collision with a single \(c’\) and starting at the hash \(h_0\). But, we can realize that we could have started at any hash \(h_i\) in the chain of hashes of _Hack.zip_ , and we could have used several blocks.

Could we for instance extend the file instead of reducing it? Sure! Just pick some random blocks before looking for a collision.

Wait… what if we combine file extensions and file reductions? Is it possible?? In fact, we just need to find successive collisions in the chain either reducing or extending the file with the above strategy. Say we found a collision between the blocks \(h_i\) and \(h_{i’}\), then we can look for a new collision starting from hash \(h_{i’+1}\) ensuring that we can safely combine them.

![](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/draw2.svg)

Once, we get enough of these independent extension/reduction buffers, it suffices to find a subset of these modifications such that the length of the file is not affected. We can see this as an instance of the [Subset sum problem](https://en.wikipedia.org/wiki/Subset_sum_problem): we are looking for a set of indexes \(S\) such that \(\sum_{i\in S}\delta_i = 0\). While this problem is NP-hard, for small dimensions we can simply solve it with dynamic programming.

And that’s it! Once we have such a subset, we can just apply the corresponding updates to _Hack.zip_ to obtain a file with the same chain of \(h_i\), and of same size ensuring that the last block also does not change and the final hash is identical to _Hack.zip_.

#### Let’s program it!

First, we program a function that computes all the \(h_i\) given a byte string.

```
    # Compute all the h_i for a given data string
    def compute_chain_h(data):
        data = bytearray(data)
        hs = []
    
        h0 = 0x674523EFCD.to_bytes(5, byteorder='big')
        h = h0
        hs.append(h0)
    
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
    
            h = hashlib.sha256(chunk + h).digest()[:5]
            hs.append(h)
    
        return hs
    
    hshack = compute_chain_h(data_hack)
```

Then, we program a function that can find a collision as we described before for a target buffer of a given size. We simply sample random buffers until we find a hash \(h\) that is present in an input array hs.

```
    """
    Finds a buffer of size length, such that it hashes to one
    of the values in hs (starting from hstart).
    """
    def find_collision(hstart, hs, length = 1):
        buf = bytearray()
        hset = set(hs)
    
        h = hstart
        i = 0
        for i in range(length-1):
            chunk = bytearray(8)
            buf += chunk
            i += 1
            h = hashlib.sha256(chunk + h).digest()[:5]
    
        i=0
        while True:
            chunk = bytearray(i.to_bytes(8, byteorder='big'))
            i += 1
            h2 = hashlib.sha256(chunk + h).digest()[:5]
            if h2 in hset:
                buf += chunk
                return buf, hs.index(h2)
```

Now we have what we need to find the collisions we talked so much about! Let’s say we will always look for collisions only among the next 20,000 blocks, and we will consider new buffers of 10000 blocks. Then, we can hope that we will obtain both buffers that will reduce the file size, and buffers that will increase it.

```
    intervals = []
    index0 = 0
    for j in range(18):
        buf, index = find_collision(hshack[index0], hshack[index0:index0+20000], length=10000)
        intervals.append((index0, index0+index, buf))
        index0 += index
        print(10000-index)
    
    # produces [-3367, -2767, 3435, -4605, -7649, -7345, 245,
    # -5974, -8524, -689, 7603, 4968, -8475, -8854, 2893, 
    # -9943, -4385, -779]
```

We now simply need to solve the Subset sum problem with dynamic programming! We can do so by computing all the sums of \(k+1\) integers from the sums of \(k\) integers, plus eventually the last one.

```
    diffs = []
    for (i0, i1, buf) in intervals:
        diffs.append(len(buf)//8 - (i1-i0))
    
    sums = set()
    sols = dict()
    for i, v in enumerate(diffs):
        for u in list(sums):
            sums.add(u+v)
            sols[u+v] = sols[u].copy()
            sols[u+v].add(i)
        sums.add(v)
        sols[v] = set([i])
        
    sol = list(sols[0])
    sol.sort()
    print(sol)
    # outputs [1, 2, 10, 11, 13, 16]
```

Eventually, it just remains to apply the subset of modifications we found to _Hack.zip_ to find a new file with the same hash. We also encode the output in json to satisfy the format used in _challenge.py_

```
    def replace_chain(data, v):
        (i0, i1, buf) = v
        databis = data[:i0*8] + buf + data[i1*8:]
        return databis
    
    data_final = data_hack[:]
    for i in sol[::-1]:
        data_final = replace_chain(data_final, intervals[i])
    
    data_final = bytes(data_final)
    
    import json
    
    j = {
        "action":"hash",
        "data": data_final.hex(),
    }
    
    # Serializing json
    json_object = json.dumps(j)
    with open("response.json", "w") as outfile:
        outfile.write(json_object)
```

And that is it! I hope you also had fun solving this challenge :)

You can also download a step-by-step Jupyter Notebook below:

[Jupyter Notebook solution](https://gniot.fr/assets/ctf/2025-PwnMe-MirrorHash/solve.ipynb)
