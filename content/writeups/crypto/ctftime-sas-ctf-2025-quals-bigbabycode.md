---
title: "bigbabycode - SAS CTF 2025 Quals"
category: "crypto"
type: "writeup"
tags: ["crypto", "xor", "bigbabycode", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "This was a fun crypto challenge involving a McEliece-like scheme where a specific parameter choice made it vulnerable to a practical attack, bypassing the need to recover the full private key."
source:
  name: "CTFtime writeup #40251"
  url: "https://ctftime.org/writeup/40251"
original_source: "https://github.com/Romm31/CTFWriteUp/tree/main/Capture%20The%20Flag/2025/SASCTF2025/bigbabycode"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "bigbabycode"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** bigbabycode
- **Author team:** Tenesys
- **CTFtime:** <https://ctftime.org/writeup/40251>
- **Original writeup:** <https://github.com/Romm31/CTFWriteUp/tree/main/Capture%20The%20Flag/2025/SASCTF2025/bigbabycode>

---
**Challenge: bigbabycode**

**Category: Crypto**

This was a fun crypto challenge involving a McEliece-like scheme where a specific parameter choice made it vulnerable to a practical attack, bypassing the need to recover the full private key.

\---  
Understanding the Challenge: `[task.py](http://task.py)` Insights

The provided `[task.py](http://task.py)` script revealed the core mechanics of the cryptosystem:

1\. Code Basis: A standard `(N, K) = (63, 57)` Hamming code generator matrix, `G_h`, was used. Hamming codes are perfect codes and the `(63,57)` variant has a minimum distance `d_min = 3`, meaning it can uniquely correct `t = floor((d_min-1)/2) = 1` error.  
2\. Key Obfuscation:  
* A `KxK` (57x57) scrambling matrix `S` was generated. It started as an identity matrix and then had `K` random elementary row operations (row swaps or XORing one row into another) applied to it. This makes `S` invertible but non-trivial.  
* A random column permutation `perm` (length `N=63`) was generated.  
* The public key `G_pub` was constructed as `(S @ G_h) % 2`, with its columns then permuted according to `perm`. This makes `G_pub` appear like a random linear code's generator matrix.  
3\. Encryption Process:  
* The message, after conversion to bits and specific padding (`...data...100...0` to make blocks of `K=57` bits), was processed block by block.  
* For each `K`-bit message block `m`, a preliminary codeword `c0 = (m @ G_pub) % 2` was computed.  
* **The Crucial Step**: An error vector `e` of length `N=63` containing exactly one '1' (i.e., Hamming weight `t=1`) was generated with the '1' at a random position.  
* The final ciphertext block `c` was `c0 XOR e`.  
4\. Output: Concatenated ciphertext blocks were converted to a hex string and provided in `output.txt`.

The lyrics provided with the challenge ("They whisper I need (S, perm)... That's not straight stuff, my man ain't doin it") hinted that while `(S, perm)` is the standard private key, directly recovering it might be hard or not the intended path. An initial check (by counting unit vectors in the provided `alice_pub.npy`) confirmed that `G_pub` was not a simple permutation of `G_h`, meaning `S` was indeed not the identity matrix.

\---  
The Exploitable Characteristic: `t=1` Error Rate

The problem's design explicitly states that exactly one error (`t=1`) is introduced into each block. Since the underlying `(63,57)` Hamming code (which `G_pub` is cryptographically equivalent to) can correct one error, we don't need to attack the McEliece structure by finding `S` and `perm`. Instead, we can perform a more direct decoding by "guessing" the location of that single error.

\---  
Decoding Strategy: Iterative Error Correction

The strategy relies on the fact that if we flip the correct (erroneous) bit in a received ciphertext block, we will recover the original error-free codeword `m @ G_pub`.

1\. Ciphertext Preparation:  
* The hex string in `output.txt` (158 characters long) was determined to represent `10 * 63 = 630` bits of actual data, not `158 * 4 = 632`. This requires careful parsing to ensure the total bitstream length is correct before block splitting.  
* The 630-bit stream was then divided into ten 63-bit ciphertext blocks.

2\. Per-Block Decoding via Error Guessing:  
For each 63-bit ciphertext block `c_block`:  
* Iterate through all `N=63` possible error positions (`err_idx` from 0 to 62).  
* For each `err_idx`, create a candidate corrected codeword `c_candidate` by flipping the bit at `err_idx` in `c_block`. ( `c_candidate = c_block XOR e_err_idx`, where `e_err_idx` has a '1' only at `err_idx`).  
* Now, assume `c_candidate` is a valid codeword. We need to find the `K=57` bit message `m_candidate` such that `m_candidate @ G_pub = c_candidate \pmod 2`.  
* To solve this system of linear equations over GF(2):  
* **Basis Selection**: From `G_pub` (a 57x63 matrix), we select 57 column indices (`basis_indices`) such that the corresponding columns form an invertible 57x57 matrix, `G_pub_sq = G_pub[:, basis_indices]`. This can be done by finding pivot columns during Gaussian elimination (RREF) of `G_pub`.  
* **Precompute Inverse**: Calculate `G_pub_sq_inv = inv(G_pub_sq) \pmod 2`. This matrix inverse is computed once using `sympy` and reused for all blocks and all error guesses.  
* **Solve for `m`**: Extract the bits from `c_candidate` corresponding to `basis_indices` to get `c_candidate_sq` (a 1x57 vector). Then, `m_candidate = (c_candidate_sq @ G_pub_sq_inv) % 2`.  
* **Verification**: To confirm that `m_candidate` is correct (i.e., that we guessed the right `err_idx`), re-encode `m_candidate`: `test_codeword = (m_candidate @ G_pub) % 2`.  
* If `test_codeword` is identical to `c_candidate`, then our `err_idx` was correct, and `m_candidate` is the decoded message block for this `c_block`. We then move to the next `c_block`.

3\. Message Reconstruction:  
* After decoding all ten blocks, concatenate the resulting 57-bit `m_candidate` blocks.  
* **Unpadding**: The `[task.py](http://task.py)` script appends a '1' bit to the original message bits, then pads with '0's to make the total length a multiple of `K=57`. To reverse this, find the last '1' in the concatenated decoded bits and take all bits that precede it.  
* **Final Conversion**: Convert the unpadded bitstream to an ASCII string to reveal the flag.

\---  
Solver Script Explanation

The `[solver.py](http://solver.py)` script automates the entire decoding process.

**Core Functionality:**

* **Parameter Definition**: Sets up constants like `N_const = 63` (block length) and `K_const = 57` (message length per block).  
* **Utility Functions**:  
* `load_G_pub()`: Loads `alice_pub.npy`, ensures data is integer and performs modulo 2.  
* `hex_string_to_bit_list(hex_s, num_expected_bits)`: Converts the input hex string into a list of binary integers (0s or 1s). Critically, it ensures the output list has exactly `num_expected_bits` (which is 630 for this challenge), correctly handling the conversion from the 158-character hex string.  
* `unpad_message_bits(all_m_bits_list)`: Reverses the padding scheme from `[task.py](http://task.py)` by locating the final '1' bit and returning all preceding bits.  
* `bits_to_string(b_list)`: Converts a list of binary bits into an ASCII string.  
* **Matrix Preprocessing (`get_G_inv_basis`)**:  
* This function takes the loaded `G_pub` matrix (57x63).  
* It uses `sympy.Matrix().rref()` to find 57 pivot column indices. These indices correspond to a set of linearly independent columns in `G_pub`.  
* A 57x57 square matrix `G_pub_sq` is formed using these basis columns from `G_pub`.  
* `sympy.Matrix().inv_mod(2)` is then used to calculate the inverse of `G_pub_sq` over GF(2).  
* This function returns the `G_pub_sq_inv` (as a NumPy array) and the `basis_indices` (list of column indices). This is a one-time setup.  
* **Block Decoding (`decode_block_by_error_guessing`)**:  
* This function takes a 63-bit ciphertext block (`c_block_arr`), the full `G_pub`, the precomputed `G_pub_sq_inv`, and `basis_indices`.  
* It iterates `err_idx` from 0 to 62 (all possible single error positions).  
* In each iteration:  
* It creates `c_candidate` by flipping the bit in `c_block_arr` at `err_idx`.  
* It extracts `c_candidate_sq` from `c_candidate` using `basis_indices`.  
* It calculates `m_candidate = (c_candidate_sq @ G_pub_sq_inv) % 2`.  
* It verifies the solution by computing `reconstructed_c = (m_candidate @ G_pub) % 2`.  
* If `reconstructed_c` equals `c_candidate`, `m_candidate` is returned as the decoded message fragment.  
* If no error position yields a valid decoding, it returns `None`.  
* **Main Execution Flow**:  
1\. Loads `G_pub`.  
2\. Calls `get_G_inv_basis` to get `G_pub_sq_inv` and `basis_indices`.  
3\. Hardcodes the contest's hex ciphertext string.  
4\. Calculates `total_actual_data_bits = 630`.  
5\. Uses `hex_string_to_bit_list` to convert the hex string to 630 bits.  
6\. Splits the 630 bits into ten 63-bit blocks.  
7\. Loops through each block, calling `decode_block_by_error_guessing` to get the 57-bit message fragment.  
8\. Concatenates all message fragments.  
9\. Calls `unpad_message_bits`.  
10\. Calls `bits_to_string` to get the final flag.  
11\. Prints the flag.

\---  
Solver Script (`[solver.py](http://solver.py)`)  
```python  
import numpy as np  
import itertools  
import sympy # For GF(2) matrix operations

# --- Parameters ---  
R_const = 6  
N_const = 2**R_const - 1  
K_const = N_const - R_const # 57

# --- Utility Functions (from previous attempt) ---  
def string_to_bits(s):  
bits = []  
for ch in s:  
bits.extend(int(b) for b in format(ord(ch), '08b'))  
return bits

def bits_to_string(b_list):  
s = ""  
num_full_bytes = len(b_list) // 8  
for i in range(num_full_bytes):  
byte_bits = b_list[i*8 : (i+1)*8]  
s += chr(int("".join(map(str, byte_bits)), 2))  
if len(b_list) % 8 != 0:  
# This should ideally not happen if unpadding + message content is byte-aligned  
print(f"Warning: {len(b_list) % 8} trailing bits were not converted to characters.")  
return s

def unpad_message_bits(all_m_bits_list):  
try:  
last_one_index = len(all_m_bits_list) - 1 - all_m_bits_list[::-1].index(1)  
return all_m_bits_list[:last_one_index]  
except ValueError:  
print("Error: No '1' terminator found in combined message bits during unpadding.")  
return None

def hex_string_to_bit_list(hex_s, num_expected_bits):  
"""  
Converts a hexadecimal string to a list of bits, ensuring the output  
has exactly num_expected_bits by appropriate zfill.  
"""  
val = int(hex_s, 16)  
bit_s_raw = bin(val)[2:] # Raw binary string from the integer value

# Pad with leading zeros to meet the num_expected_bits requirement  
# If bit_s_raw is longer than num_expected_bits, it means the hex value  
# is too large for the expected number of bits. This indicates an issue  
# if hex_s was supposed to be a minimal representation of num_expected_bits.  
if len(bit_s_raw) > num_expected_bits:  
print(f"Warning: Hex value {hex_s[:10]}... results in {len(bit_s_raw)} bits, but expected {num_expected_bits}. Taking last {num_expected_bits} bits.")  
# This might happen if num_expected_bits was underestimated.  
# For this problem, num_expected_bits (630) is derived to be consistent with  
# hex length (158) and N_const (63), implying len(bit_s_raw) <= 630.  
bit_s_final = bit_s_raw[len(bit_s_raw) - num_expected_bits:]  
else:  
bit_s_final = bit_s_raw.zfill(num_expected_bits)  
  
return [int(b) for b in bit_s_final]

def load_G_pub(filename="alice_pub.npy"):  
G_pub_loaded = np.load(filename)  
return G_pub_loaded.astype(int) % 2

# --- GF(2) Matrix Helper for Preprocessing G_pub ---  
def get_G_inv_basis(G_matrix_np):  
K, N = G_matrix_np.shape  
G_sympy = sympy.Matrix(G_matrix_np.tolist())  
rref_matrix, pivot_cols = G_sympy.rref(iszerofunc=lambda x: x % 2 == 0)

if len(pivot_cols) < K:  
print(f"Error: G_pub matrix does not have rank K={K}. Found rank {len(pivot_cols)}.")  
return None, None  
basis_indices = sorted(list(pivot_cols)[:K])  
G_sq_np = G_matrix_np[:, basis_indices]  
G_sq_sympy = sympy.Matrix(G_sq_np.tolist())  
try:  
G_sq_inv_sympy = G_sq_sympy.inv_mod(2)  
G_sq_inv_np = np.array(G_sq_inv_sympy.tolist(), dtype=int)  
return G_sq_inv_np, basis_indices  
except sympy.matrices.common.NonInvertibleMatrixError:  
print(f"Error: Submatrix G_sq formed by columns {basis_indices} is not invertible over GF(2).")  
return None, None

# --- Main Decoding Function for a Single Block ---  
def decode_block_by_error_guessing(c_block_arr_1xN, G_pub_np_KxN, G_pub_sq_inv_np_KxK, basis_indices_list_K):  
N = G_pub_np_KxN.shape[1]  
for err_idx in range(N):  
c_candidate_arr = c_block_arr_1xN.copy()  
c_candidate_arr[err_idx] = 1 - c_candidate_arr[err_idx]  
c_candidate_sq_arr = c_candidate_arr[basis_indices_list_K]  
m_candidate_arr = (c_candidate_sq_arr @ G_pub_sq_inv_np_KxK) % 2  
reconstructed_c_arr = (m_candidate_arr @ G_pub_np_KxN) % 2  
if np.array_equal(reconstructed_c_arr, c_candidate_arr):  
return m_candidate_arr.tolist()  
  
# Fallback: Check original block (t=0 scenario)  
# Problem implies t=1 error is always added, so this path is unlikely to be the solution.  
c_candidate_sq_arr_orig = c_block_arr_1xN[basis_indices_list_K]  
m_candidate_arr_orig = (c_candidate_sq_arr_orig @ G_pub_sq_inv_np_KxK) % 2  
reconstructed_c_arr_orig = (m_candidate_arr_orig @ G_pub_np_KxN) % 2  
if np.array_equal(reconstructed_c_arr_orig, c_block_arr_1xN):  
print(f"Warning: Original block decoded without flipping. Error might have been effectively null for this block.")  
return m_candidate_arr_orig.tolist()

print(f"Error: Could not decode block starting with {c_block_arr_1xN[:10].tolist()}...")  
return None

# --- Main Execution ---  
if __name__ == "__main__":  
G_pub = load_G_pub()  
if G_pub.shape != (K_const, N_const):  
print(f"Error: Loaded G_pub has incorrect shape {G_pub.shape}. Expected ({K_const}, {N_const})")  
exit()

print("Preprocessing G_pub to find invertible submatrix and its inverse...")  
G_pub_sq_inv, basis_indices = get_G_inv_basis(G_pub)

if G_pub_sq_inv is None:  
print("Failed to preprocess G_pub. Exiting.")  
exit()  
print(f"Using basis columns (first 5 shown): {basis_indices[:5]}... (total {len(basis_indices)})")

hex_ciphertext = "33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5"  
  
# Determine the actual number of bits based on hex length and N_const  
L_H = len(hex_ciphertext)  
# We derived L_data = 630 for L_H = 158 and N_const = 63  
total_actual_bits = 0  
min_bits_for_hex = (L_H - 1) * 4 + 1  
max_bits_for_hex = L_H * 4  
  
found_l_data = False  
for num_potential_blocks in range(1, (max_bits_for_hex // N_const) + 2):  
l_data_candidate = num_potential_blocks * N_const  
if min_bits_for_hex <= l_data_candidate <= max_bits_for_hex:  
if L_H == (l_data_candidate + 3) // 4: # Check if L_H is ceil(l_data_candidate/4)  
total_actual_bits = l_data_candidate  
found_l_data = True  
break  
  
if not found_l_data:  
print(f"Error: Could not consistently determine total_actual_bits from hex length {L_H} and N_const {N_const}.")  
# Defaulting to a common derivation if unique one not found above.  
# For L_H=158, N_const=63, we expect 630 bits.  
if L_H == 158 and N_const == 63: # Specific values from this problem  
total_actual_bits = 630  
print(f"Defaulting total_actual_bits to {total_actual_bits} based on known problem parameters.")  
else:  
exit()  
else:  
print(f"Determined total actual bits from hex string: {total_actual_bits}")

all_cipher_bits_list = hex_string_to_bit_list(hex_ciphertext, total_actual_bits)  
  
if len(all_cipher_bits_list) % N_const != 0: # This check should now pass  
print(f"Critical Error: Total ciphertext bits {len(all_cipher_bits_list)} after correction is still not a multiple of N={N_const}.")  
exit()  
  
num_blocks = len(all_cipher_bits_list) // N_const  
print(f"Ciphertext contains {num_blocks} block(s) of {N_const} bits each.")  
  
cipher_blocks_np_list = [  
np.array(all_cipher_bits_list[i:i+N_const], dtype=int)  
for i in range(0, len(all_cipher_bits_list), N_const)  
]

all_decrypted_msg_bits = []  
all_blocks_successfully_decoded = True

for i, c_block_np in enumerate(cipher_blocks_np_list):  
print(f"Decoding block {i+1}/{num_blocks}...")  
m_block_bits = decode_block_by_error_guessing(c_block_np, G_pub, G_pub_sq_inv, basis_indices)  
  
if m_block_bits is None:  
print(f"Failed to decode block {i+1}.")  
all_blocks_successfully_decoded = False  
break  
all_decrypted_msg_bits.extend(m_block_bits)

if all_blocks_successfully_decoded:  
print("All blocks decoded. Unpadding message...")  
final_message_bits = unpad_message_bits(all_decrypted_msg_bits)  
  
if final_message_bits is not None:  
print("Converting bits to string...")  
recovered_message = bits_to_string(final_message_bits)  
print("\n? Successfully Decrypted Message: ?")  
print(recovered_message)  
else:  
print("Failed to unpad the message.")  
else:  
print("One or more blocks could not be decoded. Full message not recovered.")

```

To run the solver (as detailed in [solver.py](http://solver.py)):

Dependencies: Ensure numpy and sympy are installed.

```bash  
pip install numpy sympy  
```

Files: Place `alice_pub.npy` in the same directory as your `[solver.py](http://solver.py)`. The hex ciphertext is hardcoded in the solver.

Execute:

```bash  
python3 [solver.py](http://solver.py)  
```

The script will then perform the steps outlined above and print the decrypted flag.

```Flag  
SAS{y0u_d0nt_r3ally_n33d_S_perm_t0_d3c0d3_Mc_3l1ec3_w1th_H4mm1ng_c0d3s}  
```
