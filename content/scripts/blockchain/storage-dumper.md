---
title: "EVM Storage Dumper - Slot Scanner and Mapping/Array Resolver"
category: blockchain
subcategory: storage
type: script
tags: [blockchain, storage, eth-getstorageat, web3py, python, slot, mapping, dynamic-array, keccak, private-variable, eip1967, proxy, decoder, dumper, evm, script]
summary: "Dumps the first N storage slots of a contract, resolves mapping/array slots, and decodes each word as int, address, bool, bytes and string."
tools: [web3py, python, cast]
related: [storage-slot-reading, solve-template, web3py-cheatsheet, delegatecall-storage-collision]
---

## Usage

```bash
pip install "web3>=6.15" eth-utils

# dump the first 32 slots
RPC_URL=http://chal:8545/uuid python3 storage_dumper.py 0xTARGET

# dump 128 slots, only non-zero
RPC_URL=... python3 storage_dumper.py 0xTARGET --slots 128 --nonzero

# resolve a mapping value: balances declared at slot 2, key = an address
RPC_URL=... python3 storage_dumper.py 0xTARGET --map 2:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# resolve a nested mapping: allowance[owner][spender] with the mapping at slot 3
RPC_URL=... python3 storage_dumper.py 0xTARGET --map2 3:0xOWNER:0xSPENDER

# resolve dynamic array elements 0..9 for an array declared at slot 5
RPC_URL=... python3 storage_dumper.py 0xTARGET --array 5:10

# read a string/bytes variable at slot 7 (handles short and long encodings)
RPC_URL=... python3 storage_dumper.py 0xTARGET --string 7

# proxy slots (EIP-1967 implementation/admin/beacon)
RPC_URL=... python3 storage_dumper.py 0xTARGET --proxy

# historical: what was in slot 0 at block 500?
RPC_URL=... python3 storage_dumper.py 0xTARGET --slots 4 --block 500

# diff storage before and after a transaction
RPC_URL=... python3 storage_dumper.py 0xTARGET --diff 1200 1201 --slots 64

# offline maths self-test, no RPC
python3 storage_dumper.py --self-test
```

## Script

```python
#!/usr/bin/env python3
"""EVM storage dumper and slot resolver.

Reads contract storage over JSON-RPC and pretty-prints every word as the types it
could plausibly be. Also computes mapping, nested-mapping and dynamic-array slots.

Requires: pip install "web3>=6.15" eth-utils

Layout rules implemented here (Solidity):
  - plain variable at declaration index p           -> slot p
  - mapping m at slot p, key k                      -> keccak256(pad32(k) || pad32(p))
  - nested m[k1][k2] at slot p                      -> keccak256(pad32(k2) || keccak256(pad32(k1) || pad32(p)))
  - dynamic array at slot p                         -> length at p, element i at keccak256(pad32(p)) + i
  - string/bytes at slot p, length <= 31            -> data in slot p, low byte = 2*len
  - string/bytes at slot p, length >= 32            -> slot p = 2*len+1, data at keccak256(pad32(p))+
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Iterable, Optional

from eth_utils import keccak, to_checksum_address

try:
    from web3 import Web3
except ImportError:  # allow --self-test without web3 installed
    Web3 = None  # type: ignore[assignment]

# EIP-1967 pseudo-random slots
EIP1967_IMPLEMENTATION = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
EIP1967_ADMIN = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
EIP1967_BEACON = 0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50
EIP1822_PROXIABLE = int.from_bytes(keccak(text="PROXIABLE"), "big")

WELL_KNOWN_SLOTS = {
    EIP1967_IMPLEMENTATION: "EIP-1967 implementation",
    EIP1967_ADMIN: "EIP-1967 admin",
    EIP1967_BEACON: "EIP-1967 beacon",
    EIP1822_PROXIABLE: "EIP-1822 proxiable (keccak('PROXIABLE'))",
}


# ---------------------------------------------------------------------------
# slot arithmetic (pure, testable offline)
# ---------------------------------------------------------------------------
def pad32(value: Any) -> bytes:
    """Left-pad an int, hex string, or bytes into a 32-byte big-endian word."""
    if isinstance(value, bool):
        return (1 if value else 0).to_bytes(32, "big")
    if isinstance(value, int):
        if value < 0:
            value += 1 << 256
        return value.to_bytes(32, "big")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).rjust(32, b"\x00")
    if isinstance(value, str):
        s = value.strip()
        if s.startswith("0x") or s.startswith("0X"):
            raw = bytes.fromhex(s[2:])
        else:
            try:
                return int(s).to_bytes(32, "big")
            except ValueError:
                raw = s.encode()
        return raw.rjust(32, b"\x00")
    raise TypeError(f"cannot pad {type(value)}")


def mapping_slot(key: Any, declared_slot: int) -> int:
    """Slot of mapping[key] for a mapping declared at `declared_slot`."""
    return int.from_bytes(keccak(pad32(key) + pad32(declared_slot)), "big")


def nested_mapping_slot(key1: Any, key2: Any, declared_slot: int) -> int:
    """Slot of m[key1][key2] for a mapping declared at `declared_slot`."""
    outer = keccak(pad32(key1) + pad32(declared_slot))
    return int.from_bytes(keccak(pad32(key2) + outer), "big")


def array_base_slot(declared_slot: int) -> int:
    """First element slot of a dynamic array declared at `declared_slot`."""
    return int.from_bytes(keccak(pad32(declared_slot)), "big")


def array_element_slot(declared_slot: int, index: int, items_per_slot: int = 1) -> int:
    """Slot holding element `index`; items_per_slot > 1 for packed small types."""
    return array_base_slot(declared_slot) + index // items_per_slot


def struct_array_element_slot(declared_slot: int, index: int, struct_slots: int, field: int = 0) -> int:
    """Slot of field `field` of struct element `index` in a dynamic array of structs."""
    return array_base_slot(declared_slot) + index * struct_slots + field


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------
def looks_like_address(word: bytes) -> bool:
    """Non-zero low 20 bytes, zero high 12 bytes."""
    return any(word[12:]) and not any(word[:12])


def printable_ascii(word: bytes) -> str:
    chunk = bytes(b for b in word if b != 0)
    if not chunk:
        return ""
    if all(32 <= b < 127 for b in chunk):
        return chunk.decode("ascii")
    return ""


def describe(word: bytes) -> str:
    """Render one 32-byte storage word as every plausible interpretation."""
    n = int.from_bytes(word, "big")
    parts = [f"hex=0x{word.hex()}"]
    parts.append(f"uint={n}")
    if n and n < (1 << 64):
        parts.append(f"small={n}")
    if looks_like_address(word):
        parts.append(f"addr={to_checksum_address(word[12:])}")
    if n in (0, 1):
        parts.append(f"bool={bool(n)}")
    txt = printable_ascii(word)
    if txt:
        parts.append(f"ascii={txt!r}")
    # short string/bytes encoding: low byte is 2*len, data left-aligned
    low = word[31]
    if low % 2 == 0 and 0 < low // 2 <= 31:
        candidate = word[: low // 2]
        if all(32 <= b < 127 for b in candidate):
            parts.append(f"shortstr={candidate.decode('ascii')!r} (len={low // 2})")
    elif low % 2 == 1 and n > 1:
        parts.append(f"longstr_len={(n - 1) // 2}")
    # timestamps in a plausible range
    if 1_000_000_000 < n < 4_000_000_000:
        parts.append("maybe_timestamp")
    # 1e18-scaled amounts
    if n >= 10**15:
        parts.append(f"ether={n / 10**18:.6f}")
    return "  ".join(parts)


# ---------------------------------------------------------------------------
# rpc access
# ---------------------------------------------------------------------------
class StorageReader:
    def __init__(self, rpc_url: str, address: str, block: Any = "latest"):
        if Web3 is None:
            raise RuntimeError("web3 is not installed: pip install web3")
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not self.w3.is_connected():
            raise RuntimeError(f"cannot reach {rpc_url}")
        self.address = Web3.to_checksum_address(address)
        self.block = block

    def read(self, slot: int, block: Any = None) -> bytes:
        return bytes(
            self.w3.eth.get_storage_at(
                self.address, slot, block_identifier=block if block is not None else self.block
            )
        )

    def code_size(self) -> int:
        return len(self.w3.eth.get_code(self.address))

    def balance(self) -> int:
        return self.w3.eth.get_balance(self.address)

    def read_string(self, declared_slot: int) -> str:
        """Read a Solidity string/bytes, handling both short and long encodings."""
        head = self.read(declared_slot)
        n = int.from_bytes(head, "big")
        if n % 2 == 0:  # short: data in the slot itself
            length = (n % 256) // 2
            return head[:length].decode("utf-8", "replace")
        length = (n - 1) // 2
        base = array_base_slot(declared_slot)
        out = bytearray()
        for i in range((length + 31) // 32):
            out += self.read(base + i)
        return bytes(out[:length]).decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_dump(reader: StorageReader, count: int, nonzero_only: bool) -> None:
    print(f"# contract {reader.address}")
    print(f"# code {reader.code_size()} bytes, balance {reader.balance()} wei")
    print(f"# dumping slots 0..{count - 1} at block {reader.block}")
    shown = 0
    for slot in range(count):
        word = reader.read(slot)
        if nonzero_only and not any(word):
            continue
        shown += 1
        print(f"slot {slot:>4}: {describe(word)}")
    if nonzero_only:
        print(f"# {shown} non-zero slots of {count}")


def cmd_proxy(reader: StorageReader) -> None:
    print(f"# proxy slots for {reader.address}")
    for slot, name in WELL_KNOWN_SLOTS.items():
        word = reader.read(slot)
        if any(word):
            print(f"{name}:")
            print(f"    {describe(word)}")
    if not any(reader.read(EIP1967_IMPLEMENTATION)):
        print("(no EIP-1967 implementation set; this may not be a proxy)")


def cmd_map(reader: StorageReader, spec: str) -> None:
    declared, key = spec.split(":", 1)
    slot = mapping_slot(key, int(declared, 0))
    print(f"mapping at slot {declared}, key {key}")
    print(f"  -> slot 0x{slot:064x}")
    print(f"  -> {describe(reader.read(slot))}")


def cmd_map2(reader: StorageReader, spec: str) -> None:
    declared, k1, k2 = spec.split(":", 2)
    slot = nested_mapping_slot(k1, k2, int(declared, 0))
    print(f"nested mapping at slot {declared}, keys {k1} / {k2}")
    print(f"  -> slot 0x{slot:064x}")
    print(f"  -> {describe(reader.read(slot))}")


def cmd_array(reader: StorageReader, spec: str) -> None:
    declared_s, count_s = spec.split(":", 1)
    declared = int(declared_s, 0)
    count = int(count_s, 0)
    length = int.from_bytes(reader.read(declared), "big")
    print(f"dynamic array declared at slot {declared}, on-chain length = {length}")
    base = array_base_slot(declared)
    print(f"base slot = 0x{base:064x}")
    for i in range(min(count, max(length, count))):
        print(f"  [{i}] {describe(reader.read(base + i))}")


def cmd_string(reader: StorageReader, declared_slot: int) -> None:
    print(f"string/bytes at slot {declared_slot}: {reader.read_string(declared_slot)!r}")


def cmd_diff(reader: StorageReader, block_a: int, block_b: int, count: int) -> None:
    print(f"# storage diff of {reader.address} between blocks {block_a} and {block_b}")
    changed = 0
    for slot in range(count):
        a = reader.read(slot, block=block_a)
        b = reader.read(slot, block=block_b)
        if a != b:
            changed += 1
            print(f"slot {slot:>4}:")
            print(f"    - {describe(a)}")
            print(f"    + {describe(b)}")
    print(f"# {changed} slot(s) changed")


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
def self_test() -> None:
    # pad32 handles ints, hex strings and bytes identically where they agree
    assert pad32(0) == b"\x00" * 32
    assert pad32(1)[-1] == 1
    assert pad32("0x" + "00" * 20) == b"\x00" * 32
    assert pad32(b"\xff") == b"\x00" * 31 + b"\xff"

    # mapping slot matches the documented formula
    expected = int.from_bytes(keccak(b"\x00" * 32 + (2).to_bytes(32, "big")), "big")
    assert mapping_slot(0, 2) == expected
    assert mapping_slot("0x0000000000000000000000000000000000000000", 2) == expected

    # a different key gives a different slot
    assert mapping_slot(1, 2) != mapping_slot(0, 2)
    # a different declaration slot gives a different slot
    assert mapping_slot(0, 3) != mapping_slot(0, 2)

    # nested mapping composes
    inner = keccak(pad32(7) + pad32(3))
    assert nested_mapping_slot(7, 9, 3) == int.from_bytes(keccak(pad32(9) + inner), "big")

    # array element offsets are contiguous
    assert array_element_slot(5, 0) == array_base_slot(5)
    assert array_element_slot(5, 4) == array_base_slot(5) + 4
    assert struct_array_element_slot(5, 2, 3, 1) == array_base_slot(5) + 7

    # packed small types share slots
    assert array_element_slot(5, 0, items_per_slot=2) == array_element_slot(5, 1, items_per_slot=2)
    assert array_element_slot(5, 2, items_per_slot=2) == array_base_slot(5) + 1

    # decoder recognises an address-shaped word
    addr_word = bytes(12) + bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045")
    assert "addr=" in describe(addr_word)
    assert looks_like_address(addr_word)
    assert not looks_like_address(b"\xff" * 32)

    # decoder recognises a short string
    payload = b"hello"
    short = payload + bytes(31 - len(payload)) + bytes([len(payload) * 2])
    assert "shortstr=" in describe(short)

    # well-known slot constant is right
    assert EIP1967_IMPLEMENTATION == (
        int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1
    )
    assert EIP1967_ADMIN == int.from_bytes(keccak(text="eip1967.proxy.admin"), "big") - 1

    print("[+] all storage-dumper self-tests passed")


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="EVM storage dumper and slot resolver")
    p.add_argument("address", nargs="?", help="contract address")
    p.add_argument("--rpc", default=os.environ.get("RPC_URL"), help="RPC url (or $RPC_URL)")
    p.add_argument("--slots", type=int, default=32, help="how many sequential slots to dump")
    p.add_argument("--nonzero", action="store_true", help="only print non-zero slots")
    p.add_argument("--block", default="latest", help="block number or tag")
    p.add_argument("--proxy", action="store_true", help="read the EIP-1967/1822 proxy slots")
    p.add_argument("--map", dest="map_spec", help="SLOT:KEY  resolve mapping[key]")
    p.add_argument("--map2", dest="map2_spec", help="SLOT:KEY1:KEY2  resolve m[k1][k2]")
    p.add_argument("--array", dest="array_spec", help="SLOT:COUNT  resolve dynamic array elements")
    p.add_argument("--string", dest="string_slot", type=int, help="read a string/bytes at SLOT")
    p.add_argument("--diff", nargs=2, metavar=("BLOCK_A", "BLOCK_B"), help="diff storage between blocks")
    p.add_argument("--self-test", action="store_true", help="run offline maths checks and exit")
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        self_test()
        return 0

    if not args.address:
        print("error: address is required (or pass --self-test)", file=sys.stderr)
        return 1
    if not args.rpc:
        print("error: set --rpc or $RPC_URL", file=sys.stderr)
        return 1

    block: Any = args.block
    if isinstance(block, str) and block not in ("latest", "earliest", "pending", "safe", "finalized"):
        block = int(block, 0)

    reader = StorageReader(args.rpc, args.address, block)

    did_something = False
    if args.proxy:
        cmd_proxy(reader)
        did_something = True
    if args.map_spec:
        cmd_map(reader, args.map_spec)
        did_something = True
    if args.map2_spec:
        cmd_map2(reader, args.map2_spec)
        did_something = True
    if args.array_spec:
        cmd_array(reader, args.array_spec)
        did_something = True
    if args.string_slot is not None:
        cmd_string(reader, args.string_slot)
        did_something = True
    if args.diff:
        cmd_diff(reader, int(args.diff[0], 0), int(args.diff[1], 0), args.slots)
        did_something = True

    if not did_something:
        cmd_dump(reader, args.slots, args.nonzero)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Equivalent `cast` one-liners

```bash
# dump 32 slots
for i in $(seq 0 31); do printf "%3d: " "$i"; cast storage "$TARGET" "$i" --rpc-url "$RPC_URL"; done

# mapping at slot 2 for an address key
cast storage "$TARGET" "$(cast keccak "$(cast abi-encode 'f(address,uint256)' "$ME" 2)")" \
  --rpc-url "$RPC_URL"

# dynamic array base slot for an array declared at slot 5
cast keccak "$(cast abi-encode 'f(uint256)' 5)"

# EIP-1967 implementation
cast storage "$TARGET" \
  0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$RPC_URL"

# decode a word as ascii
cast --to-ascii "$(cast storage "$TARGET" 3 --rpc-url "$RPC_URL")"
```

## Notes

- `immutable` and `constant` variables are **not** in storage; they are compiled into the runtime
  bytecode. If every slot is zero but the contract clearly holds values, disassemble the code and
  look for `PUSH32`/`PUSH20` literals.
- Transient storage (`TSTORE`/`TLOAD`, EIP-1153) is invisible to `eth_getStorageAt`.
- The `--diff` mode against the blocks either side of a transaction is the fastest way to reverse
  an unknown layout: send the transaction on a fork, then diff.
- Packing means one slot can hold several variables. `describe()` prints the whole word; slice it
  from the right: byte offset `k` of a variable is `word[31 - k]`.
