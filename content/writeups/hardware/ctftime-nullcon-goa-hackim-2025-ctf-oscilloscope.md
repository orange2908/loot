---
title: "oscilloscope - Nullcon Goa HackIM 2025 CTF"
category: "hardware"
subcategory: "deserialization"
type: "writeup"
tags: ["hardware", "deserialization", "oscilloscope", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "![ Sign in via Google  ](https://hackmd.io/auth/google)  ![ Sign in via Facebook  ](https://hackmd.io/auth/facebook)  ![ Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter)  ![ Sign in via GitHu"
source:
  name: "CTFtime writeup #40002"
  url: "https://ctftime.org/writeup/40002"
original_source: "https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/S1x_nkLK1l"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "oscilloscope"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** oscilloscope
- **Author team:** volticks_fanClub
- **CTFtime:** <https://ctftime.org/writeup/40002>
- **Original writeup:** <https://hackmd.io/@MnZaZUYBR32K0Fourl72wA/S1x_nkLK1l>

---
```python import pickle import matplotlib.pyplot as plt def load_pickle_data(path): """Read and load data from a pickle file.""" with open(path, "rb") as f: return pickle.load(f) def adjust_indices_based_on_condition(data, start_idx, end_idx): """Modify start and end indices until the data at those points satisfies specific conditions.""" while data[1][start_idx] > 1: start_idx += 1 while data[1][end_idx] > 1: end_idx -= 1 return start_idx, end_idx def analyze_data_segments(data, start_idx, end_idx, window_size): """Process segments of data and construct a result string based on the sum conditions.""" current_idx = start_idx + window_size previous_idx = current_idx result_string = "" while current_idx < end_idx: # Find segment start where sum exceeds threshold while sum(data[1][current_idx - window_size:current_idx]) > window_size: current_idx += 1 segment_start = current_idx # Find segment end where sum drops below threshold while sum(data[1][current_idx - window_size:current_idx]) < window_size: current_idx += 1 segment_end = current_idx middle_idx = (segment_start + segment_end) // 2 # Evaluate the average for data[2] in the segment and check if it exceeds threshold avg_value = sum(data[2][previous_idx:middle_idx]) // (middle_idx - previous_idx) result_string += "1" if avg_value > 1 else "0" previous_idx = middle_idx return result_string[1:], data[1][start_idx:end_idx], data[2][start_idx:end_idx], data[0][start_idx:end_idx] def binary_to_bytes(binary_string): """Convert the binary string into a bytes object.""" byte_data = b"" for i in range(0, len(binary_string), 9): byte_chunk = int(binary_string[i:i + 8], 2).to_bytes(1, byteorder='big') byte_data += byte_chunk return byte_data def main(): file_path = "trace.pckl" data = load_pickle_data(file_path) start_index = 68000 end_index = 240000 window_size = 20 # Adjust indices based on the conditions start_index, end_index = adjust_indices_based_on_condition(data, start_index, end_index) # Process the data and get the result string result_string, data_segment1, data_segment2, x_values = analyze_data_segments(data, start_index, end_index, window_size) # Convert the result string to bytes and print the decoded output byte_data = binary_to_bytes(result_string) print(byte_data.split(b'\xa1')[1].decode()) if __name__ == "__main__": main() ```

×

### Sign in

or

[ ![](https://hackmd.io/social/google.svg) Sign in via Google  ](https://hackmd.io/auth/google) [ ![](https://hackmd.io/social/facebook.svg) Sign in via Facebook  ](https://hackmd.io/auth/facebook) [ ![](https://hackmd.io/social/x.svg) Sign in via X(Twitter)  ](https://hackmd.io/auth/twitter) [ ![](https://hackmd.io/social/github.svg) Sign in via GitHub  ](https://hackmd.io/auth/github) [ ![](https://hackmd.io/social/dropbox.svg) Sign in via Dropbox  ](https://hackmd.io/auth/dropbox) ![](https://hackmd.io/images/wallet.svg) Sign in with Wallet  Wallet (  )  __ Connect another wallet  Continue with a different method 

New to HackMD? [Sign up](https://hackmd.io/join)

By signing in, you agree to our [terms of service](https://hackmd.io/s/terms).
