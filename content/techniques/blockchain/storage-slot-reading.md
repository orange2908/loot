---
title: "EVM Storage - Reading 'private' Variables and Slot Math"
category: blockchain
subcategory: storage
type: technique
tags: [blockchain, evm, solidity, storage, eth-getstorageat, private-variable, slot, keccak256, mapping, dynamic-array, packing, cast, web3py, foundry, storage-layout, eip1967, proxy]
difficulty: easy
summary: "private only hides a getter, not the bytes. Compute the slot, call eth_getStorageAt, decode."
when_to_use:
  - "A contract stores a password/secret/seed in a private variable"
  - "You need a mapping value but there is no getter"
  - "You must find the implementation address behind a proxy"
  - "You want to diff storage before/after a transaction to understand a contract"
tools: [cast, web3py, foundry, forge-inspect]
related: [setup-and-workflow, delegatecall-storage-collision, storage-dumper, bad-randomness]
---

## TL;DR

`private`/`internal` are compile-time visibility only. Every value lives in a 32-byte slot of a
public key-value store you can read with `eth_getStorageAt`. The whole skill is computing *which*
slot, which is fully deterministic from the declaration order and the type.

## Recognise it

- `bytes32 private password;`, `uint256 private seed;`, `mapping(address => uint) private balances;`
- A challenge whose only unknown is a value the contract already holds.
- A `require(input == secret)` where `secret` is never emitted in a log or returned.
- Proxy contracts: you need the implementation address at EIP-1967 slot.

## Theory

### The layout rules

State variables are assigned slots starting at 0, **in declaration order**, with packing:

- Each slot is 32 bytes (256 bits).
- Types smaller than 32 bytes are packed right-to-left into the *current* slot if they fit;
  otherwise a new slot starts. `address` = 20 bytes, `bool`/`uint8` = 1 byte, `bytes32` = 32.
- `constant` and `immutable` take **no storage** - they are baked into the bytecode. Read them with
  `cast code` + a getter call, not `getStorageAt`.
- Structs and fixed arrays start on a fresh slot and occupy consecutive slots.
- Inherited variables come first, base-most contract first (C3-linearised order).

Example:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Layout {
    uint256 private a;          // slot 0
    address private owner;      // slot 1, bytes [0..19]
    bool    private locked;     // slot 1, byte  [20]
    uint8   private level;      // slot 1, byte  [21]
    bytes32 private password;   // slot 2 (32 bytes -> needs its own slot)
    uint128 private x;          // slot 3, low 16 bytes
    uint128 private y;          // slot 3, high 16 bytes
    uint256[3] private fixedArr;// slots 4,5,6
    uint256[] private dynArr;   // slot 7 holds LENGTH
    mapping(address => uint256) private bal;   // slot 8 holds NOTHING
    mapping(address => mapping(uint => uint)) private nested; // slot 9
    string private name;        // slot 10
}
```

### Derived locations

- **Dynamic array** declared at slot `p`: slot `p` stores the length; element `i` lives at
  `keccak256(abi.encode(p)) + i`. (Element type smaller than 32 bytes packs several per slot.)
- **Mapping** declared at slot `p`: value for key `k` lives at `keccak256(abi.encode(k, p))`,
  i.e. `keccak256(pad32(k) || pad32(p))`.
- **Nested mapping** `m[k1][k2]` at slot `p`:
  `keccak256(abi.encode(k2, keccak256(abi.encode(k1, p))))`.
- **Array of structs** at slot `p`, struct size `S` slots: element `i` field `j` at
  `keccak256(abi.encode(p)) + i*S + j`.
- **`string`/`bytes`** at slot `p`: if length <= 31, the data and `2*len` are packed into slot `p`
  itself (low byte = `2*len`). If longer, slot `p` holds `2*len+1` and the data starts at
  `keccak256(abi.encode(p))`.
- **EIP-1967 proxy implementation**:
  `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
  (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`).
  Admin slot: `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`.
- **EIP-1822 (UUPS legacy)**: `keccak256("PROXIABLE")`.

## Attack

1. Get the declaration order - from source, or from `forge inspect <Contract> storageLayout`.
2. Compute the slot (plain index, or keccak for mapping/array).
3. `cast storage <addr> <slot> --rpc-url $RPC`.
4. Decode: the raw word is big-endian. An `address` is the low 20 bytes; a packed `bool` is one
   byte at a known offset; a `bytes32` password is often ASCII - try `cast --to-ascii`.
5. If you do not know the layout, **dump slots 0..64 and eyeball** - see `storage-dumper`.

## Code

```bash
# slot 0 of a contract, raw 32-byte word
cast storage 0xTARGET 0 --rpc-url "$RPC_URL"

# same via raw JSON-RPC (works with any node, no foundry)
cast rpc eth_getStorageAt 0xTARGET 0x0 latest --rpc-url "$RPC_URL"

# full layout straight from source (needs the contract compiled locally)
forge inspect src/Vault.sol:Vault storageLayout --pretty

# mapping bal[0xdead...] where `bal` is declared at slot 8
SLOT=$(cast keccak $(cast abi-encode "f(address,uint256)" 0x000000000000000000000000000000000000dEaD 8))
cast storage 0xTARGET "$SLOT" --rpc-url "$RPC_URL"

# dynamic array element 3 where the array is declared at slot 7
BASE=$(cast keccak $(cast abi-encode "f(uint256)" 7))
cast storage 0xTARGET $(cast --to-hex $(( $(cast --to-dec $BASE) + 3 ))) --rpc-url "$RPC_URL"

# proxy implementation (EIP-1967)
cast storage 0xPROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$RPC_URL"

# decode a slot as ascii / as address / as uint
cast --to-ascii 0x6d7973656372657400000000000000000000000000000000000000000000000
cast parse-bytes32-address 0x000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045
cast --to-dec 0x0000000000000000000000000000000000000000000000000de0b6b3a7640000
```

Python (web3.py) slot math and reader:

```python
#!/usr/bin/env python3
"""Compute EVM storage slots and read them. Requires: pip install web3 eth-utils"""
import os
import sys

from eth_utils import keccak, to_bytes, to_checksum_address
from web3 import Web3


def pad32(value) -> bytes:
    """Left-pad any int/address/bytes to a 32-byte big-endian word."""
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    if isinstance(value, str) and value.startswith("0x"):
        raw = to_bytes(hexstr=value)
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise TypeError(f"unsupported key type: {type(value)}")
    return raw.rjust(32, b"\x00")


def mapping_slot(key, declared_slot: int) -> int:
    """slot of mapping[key] where the mapping itself is declared at `declared_slot`."""
    return int.from_bytes(keccak(pad32(key) + pad32(declared_slot)), "big")


def nested_mapping_slot(key1, key2, declared_slot: int) -> int:
    """slot of m[key1][key2]."""
    outer = keccak(pad32(key1) + pad32(declared_slot))
    return int.from_bytes(keccak(pad32(key2) + outer), "big")


def array_slot(index: int, declared_slot: int, items_per_slot: int = 1) -> int:
    """slot holding element `index` of a dynamic array declared at `declared_slot`."""
    base = int.from_bytes(keccak(pad32(declared_slot)), "big")
    return base + index // items_per_slot


EIP1967_IMPL = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
EIP1967_ADMIN = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103


def read_slot(w3: Web3, address: str, slot: int) -> bytes:
    return w3.eth.get_storage_at(to_checksum_address(address), slot)


def describe(word: bytes) -> str:
    n = int.from_bytes(word, "big")
    addr = to_checksum_address(word[-20:]) if n >> 160 == 0 else "-"
    printable = bytes(b for b in word if 32 <= b < 127).decode("ascii", "ignore")
    return f"uint={n} addr={addr} ascii={printable!r}"


if __name__ == "__main__":
    # self-test of the slot math against values you can verify with `cast keccak`
    assert mapping_slot(0, 0) == int.from_bytes(keccak(b"\x00" * 64), "big")
    assert array_slot(0, 7) == int.from_bytes(keccak(pad32(7)), "big")
    assert array_slot(3, 7) == array_slot(0, 7) + 3
    print("[+] slot math self-test ok")

    rpc = os.environ.get("RPC_URL")
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET")
    if not (rpc and target):
        print("usage: RPC_URL=... python3 slots.py <address>")
        raise SystemExit(0)

    w3 = Web3(Web3.HTTPProvider(rpc))
    for slot in range(8):
        print(f"slot {slot}: {read_slot(w3, target, slot).hex()}  {describe(read_slot(w3, target, slot))}")
    impl = read_slot(w3, target, EIP1967_IMPL)
    if int.from_bytes(impl, "big"):
        print("EIP-1967 implementation:", to_checksum_address(impl[-20:]))
```

## Variants & pitfalls

- **`immutable`/`constant` are not in storage.** If slot 0 reads as zero but the variable clearly
  has a value, it is immutable - grab it from a getter, or find it inline in `cast code` output.
- **Packing offsets**: for `address owner; bool locked;` in one slot, `locked` is byte 20 counted
  from the *right* of the 32-byte word, i.e. `word[31-20] == word[11]`.
- **Optimiser reordering does not happen** for storage; declaration order is guaranteed by the
  Solidity spec. Inheritance order does matter though.
- **Vyper** uses the same slot 0..n scheme but different rules for mappings in old versions.
- **Transient storage (`TSTORE`, EIP-1153)** is *not* readable with `eth_getStorageAt` - it is wiped
  at end of transaction. If a value vanishes, look for `tstore`/`tload` in the bytecode.
- **Diffing** is often faster than reasoning: dump all slots, send the tx on a fork, dump again, diff.
  `cast run --trace <txhash>` also shows `SSTORE`s.
- **`eth_getStorageAt` at an old block**: pass a block number to see historical secrets that were
  later overwritten. `cast storage 0xT 0 --block 1234 --rpc-url $RPC`.

## Tools

- `cast storage`, `cast rpc eth_getStorageAt`, `forge inspect ... storageLayout`
- `web3.py` `w3.eth.get_storage_at(addr, slot, block_identifier=...)`
- `slither-read-storage` (from the Slither suite) automates layout-aware dumps.

## References

- Solidity docs: "Layout of State Variables in Storage".
- EIP-1967: Standard Proxy Storage Slots.
