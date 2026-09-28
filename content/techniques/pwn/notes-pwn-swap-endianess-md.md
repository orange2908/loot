---
title: "Swap Endianess (pwn)"
category: "pwn"
type: "technique"
tags: ["my-notes", "personal", "swap", "endianess", "pwn"]
summary: "Personal note: Swap Endianess (pwn)."
source:
  name: "Personal notes"
origin_path: "pwn/swap endianess.md"
---

```python
input_str = "0x402118.(nil).0x7fcc27eb5a00.(nil).0x1ec5880.0xa347834.0x7ffcc5ad67e0.0x7fcc27ca6e60.0x7fcc27ecb4d0.0x1.0x7ffcc5ad68b0.(nil).(nil).0x7b4654436f636970.0x355f31346d316e34.0x3478345f33317937.0x35625f673431665f.0x7d663839623764.0x7.0x7fcc27ecd8d8.0x2300000007.0x206e693374307250.0xa336c797453.0x9.0x7fcc27edede9.0x7fcc27caf098.0x7fcc27ecb4d0.(nil).0x7ffcc5ad68c0.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e"

addresses = input_str.split('.')

def swap_endianness(hex_str):
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    swapped = "".join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
    return "0x" + swapped

for addr in addresses:
    if addr.startswith("0x"):
        print(swap_endianness(addr))
    else:
        print(addr)
```

---

*From your own notes: `pwn/swap endianess.md`*
