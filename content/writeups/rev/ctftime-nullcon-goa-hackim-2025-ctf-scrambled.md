---
title: "scrambled - Nullcon Goa HackIM 2025 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "reversing", "xor", "scrambled", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "SPECT3RR  / Writeups-of-CTFs-  Public"
source:
  name: "CTFtime writeup #39843"
  url: "https://ctftime.org/writeup/39843"
original_source: "https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-Scrambled-(REV)"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "scrambled"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** scrambled
- **Author team:** ODYNSEC
- **CTFtime tags:** reversing, xor
- **CTFtime:** <https://ctftime.org/writeup/39843>
- **Original writeup:** <https://github.com/SPECT3R0/Writeups-of-CTFs-/wiki/NULLCON:-Scrambled-(REV)>

---
[ SPECT3RR ](https://github.com/SPECT3RR) / **[Writeups-of-CTFs-](https://github.com/SPECT3RR/Writeups-of-CTFs-) ** Public

  * [ Notifications ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-) You must be signed in to change notification settings
  * [ Fork 0 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)
  * [ Star  2 ](https://github.com/login?return_to=%2FSPECT3RR%2FWriteups-of-CTFs-)


# NULLCON: Scrambled (REV)

Jump to bottom

Junaid Arshad Malik edited this page Feb 2, 2025 · [1 revision](https://github.com/SPECT3RR/Writeups-of-CTFs-/wiki/NULLCON:-Scrambled-\(REV\)/_history)

**Reversing Challenge Write-up: Deciphering the Scrambled Flag**

## Challenge Overview

The challenge involves reversing an encoding function to retrieve the original flag. The encoding process involves XOR encryption, chunking, and shuffling, making it necessary to reverse each step methodically.

### Key Details:

  * The flag starts with `"ENO"` (a given hint).
  * The encoding function XORs the flag with a single-byte key.
  * The result is divided into 4-byte chunks.
  * These chunks are shuffled using a random seed between 0 and 10.
  * The shuffled chunks are flattened into a single scrambled list.
  * The scrambled result is provided in hexadecimal format.


## Understanding the Encoding Process

  1. XOR operation is performed on each character of the flag with a given key.
  2. The result is split into chunks of 4 bytes.
  3. These chunks are shuffled using a random seed.
  4. The shuffled data is then flattened and provided in hexadecimal format.


## Reversing the Encoding Process

To retrieve the original flag, we need to:

  1. Convert the scrambled result back into a list of integers.
  2. Identify the correct seed used for shuffling.
  3. Unshuffle the chunks to their original order.
  4. XOR the unshuffled data with the key to reconstruct the flag.
  5. Since the key is unknown, brute-force all possible values (0-255) to find the correct one.


### Python Code to Decode the Flag

```
    import random
    
    def decode_flag(scrambled_result, key):
        # Convert the scrambled result back into a list of integers
        scrambled_list = [int(scrambled_result[i:i+2], 16) for i in range(0, len(scrambled_result), 2)]
        
        # Determine the correct seed used for shuffling
        for seed in range(0, 11):
            random.seed(seed)
            
            # Create a list of chunk indices and shuffle them
            chunk_size = 4
            num_chunks = len(scrambled_list) // chunk_size
            chunk_indices = list(range(num_chunks))
            random.shuffle(chunk_indices)
            
            # Unshuffle the chunks
            unshuffled_chunks = [None] * num_chunks
            for i, chunk_index in enumerate(chunk_indices):
                unshuffled_chunks[chunk_index] = scrambled_list[i*chunk_size:(i+1)*chunk_size]
            
            # Flatten the unshuffled chunks
            unshuffled_list = [item for chunk in unshuffled_chunks for item in chunk]
            
            # XOR the result with the key to get the original flag
            flag = ''.join([chr(c ^ key) for c in unshuffled_list])
            
            # Check if the flag starts with "ENO"
            if flag.startswith("ENO"):
                return flag
        
        return None
    
    def main():
        scrambled_result = "1e78197567121966196e757e1f69781e1e1f7e736d6d1f75196e75191b646e196f6465510b0b0b57"
        
        # Brute-force the key since it's unknown
        for key in range(256):
            flag = decode_flag(scrambled_result, key)
            if flag:
                print(f"Key: {key}, Flag: {flag}")
                break
    
    if __name__ == "__main__":
        main()
```

## Explanation of the Solution

  1. **Convert Hexadecimal to Integer List**
     * The provided scrambled result is converted back into a list of integers.
  2. **Find the Correct Seed**
     * We iterate over possible seeds (0 to 10) to find the one that correctly unshuffles the chunks.
  3. **Unshuffle the Chunks**
     * Using the determined seed, the chunks are rearranged into their original order.
  4. **XOR with Key**
     * The unshuffled data is XORed with the key to reconstruct the original flag.
  5. **Brute-force the Key**
     * Since the key is not given, we try all possible values (0-255) to find the correct one.


## Expected Output

When the correct key and seed are found, the output displays the decrypted flag.

## Lessons Learned

  * **XOR Encryption** : Understanding how XOR can be used for encryption and decryption.
  * **Shuffling and Unshuffling** : Reversing a shuffled structure using known seeds.
  * **Brute-force Approach** : When an encryption key is unknown, brute-force can be an effective method.
  * **CTF Reversing Techniques** : Breaking down an encoding function to reconstruct the original data.


## Conclusion

By following this approach, we successfully reversed the encoding function and retrieved the original flag. This challenge highlights the importance of understanding bitwise operations, shuffling mechanisms, and brute-force decryption techniques in CTF challenges.

* * *

**Author: SPECT3R**  
**Event: NullCon CTF**

### Clone this wiki locally
