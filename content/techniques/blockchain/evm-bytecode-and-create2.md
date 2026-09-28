---
title: "EVM Bytecode Puzzles - Disassembly, Decompilation and CREATE2 Address Prediction"
category: blockchain
subcategory: evm
type: technique
tags: [blockchain, evm, bytecode, opcodes, disassembly, decompiler, heimdall, panoramix, ethervm, create2, create, metamorphic, init-code, runtime-code, extcodehash, selector, 4byte, foundry, cast, salt-mining]
difficulty: hard
summary: "No source: disassemble the runtime code, recover selectors, decompile; plus CREATE/CREATE2 address maths and metamorphic contracts."
when_to_use:
  - "The challenge gives you only a deployed address or a hex blob"
  - "You need to find hidden functions / magic constants in a contract"
  - "You must deploy to a specific address, or predict one before deployment"
  - "A contract changes its code at the same address (metamorphic)"
tools: [cast, heimdall, panoramix, evm, foundry, pyevmasm]
related: [attacker-contract-patterns, storage-slot-reading, access-control, bad-randomness]
---

## TL;DR

A contract's runtime bytecode is public. Get it with `eth_getCode`, disassemble it, find the
4-byte selector dispatcher at the top, and work out the path to the state change you want.
Separately, `CREATE`/`CREATE2` addresses are pure functions of known inputs - you can predict them,
mine them, and (pre-Cancun) re-deploy different code at the same address.

## Recognise it

- The challenge provides only an address and "find the password".
- A `constructor` that returns hand-written runtime bytecode (`assembly { return(...) }`).
- `require(msg.sender == <a specific address>)` where that address is not yet deployed.
- A factory using `CREATE2` with a caller-supplied salt.
- `extcodehash` or `extcodesize` checks used as an "is this the expected contract" guard.
- A "vanity address" requirement: the attacker contract must start with `0x0000` or similar.

## Theory

### Init code vs runtime code

Deployment executes the **init code** (the constructor). Whatever bytes it `RETURN`s become the
**runtime code** stored at the address. So:

- `cast code <addr>` gives you the *runtime* code.
- The constructor's own logic is *not* in the runtime code. Find it in the deployment transaction's
  `input` field (`cast tx <deployTx> input`), or in the `forge build` artifact's `bytecode` field.
- Constructor arguments are ABI-encoded and appended to the init code; immutables are patched into
  the runtime code during deployment.

### The dispatcher

Solidity's runtime code begins with a standard preamble:

```
PUSH1 0x80  PUSH1 0x40  MSTORE        ; free memory pointer = 0x80
CALLVALUE DUP1 ISZERO PUSH2 ... JUMPI ; revert if msg.value != 0 (non-payable)
POP
PUSH1 0x04 CALLDATASIZE LT PUSH2 ... JUMPI  ; fall through to fallback if calldata < 4
PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR      ; selector = calldata[0:4]
DUP1 PUSH4 0x12345678 EQ PUSH2 0x0080 JUMPI ; compare against each selector
DUP1 PUSH4 0x9abcdef0 EQ PUSH2 0x00a0 JUMPI
...
```

So: **every `PUSH4` immediately before an `EQ` is a function selector.** Extract them all, then look
each up in a 4-byte database. Long dispatchers use a binary search over sorted selectors (`GT`/`LT`
instead of a flat `EQ` chain) - same idea, more `PUSH4`s.

### Useful opcode landmarks

| Opcode | Meaning when you see it |
|---|---|
| `SLOAD`/`SSTORE` with a `PUSH1 0x..` | direct storage slot access |
| `KECCAK256` after two `MSTORE`s | mapping/array slot computation |
| `CALLER` | `msg.sender` |
| `ORIGIN` | `tx.origin` - an auth smell |
| `EXTCODESIZE` | contract-vs-EOA check |
| `TIMESTAMP`/`NUMBER`/`PREVRANDAO`/`BLOCKHASH` | randomness source |
| `DELEGATECALL` | proxy/library |
| `CREATE`/`CREATE2` | factory |
| `REVERT` right after a comparison | a `require` |
| `INVALID` (`0xfe`) | an `assert` (pre-0.8) or a padding byte |
| `LOG1..LOG4` with a `PUSH32` | an event; the `PUSH32` is the topic0 hash |

### Address derivation

**CREATE**: `address = keccak256(rlp([sender, nonce]))[12:]`
Nonce 0 for a fresh EOA/contract; a contract's nonce starts at 1.

**CREATE2**: `address = keccak256(0xff || deployer || salt || keccak256(init_code))[12:]`
- `0xff` is a single byte, `deployer` is 20 bytes, `salt` is 32 bytes, the init-code hash is 32
  bytes; the preimage is exactly 85 bytes.
- The address depends on the **init code**, which includes constructor arguments. Change an
  argument, change the address.

**Metamorphic contracts** (pre-Cancun): deploy via `CREATE2` a factory whose init code `delegatecall`s
an "implementation registry" and returns whatever bytecode it reports. `selfdestruct` the deployed
contract, then `CREATE2` again with the same salt and factory but a different registry answer ->
**different runtime code at the same address**. EIP-6780 (Cancun) broke this on modern chains by only
deleting code when the destruct happens in the creation transaction - but a CTF pinning
`evm_version = "shanghai"` or earlier still allows it, and the "destroy and redeploy in the same tx"
variant still works everywhere.

**`extcodehash` as a guard is weak**: `EXTCODEHASH` of an address with no code returns `0x0`;
of an account that never existed, also `0x0` (EIP-1052). And any check done *before* your metamorphic
redeploy is worthless.

## Attack

1. `cast code <addr> > runtime.bin`
2. Disassemble: `cast disassemble $(cat runtime.bin)` or `evm disasm`.
3. Extract `PUSH4` constants -> candidate selectors -> `cast 4byte` each.
4. Look for `PUSH32` constants: event topics, keccak'd passwords, EIP-712 typehashes.
5. Decompile for structure: `heimdall decompile`, or paste into a web decompiler.
6. Trace an actual call: `cast run <txhash> --trace --debug` steps the EVM.
7. If you need a specific address: mine a `CREATE2` salt.

## Code

### Getting and disassembling code

```bash
# runtime bytecode of a deployed contract
cast code "$TARGET" --rpc-url "$RPC_URL" > runtime.hex

# disassemble (foundry)
cast disassemble "$(cat runtime.hex)" | head -60

# the code hash, and the size (a size of 0 means EOA or destroyed)
cast codesize "$TARGET" --rpc-url "$RPC_URL"
cast keccak "$(cat runtime.hex)"

# the INIT code: find the creation transaction, read its input
cast tx "$CREATION_TX" input --rpc-url "$RPC_URL" > init.hex

# constructor args: the tail of init.hex after the runtime blob; decode once you guess the types
cast abi-decode "constructor(address,uint256)" "0x$(tail -c 128 init.hex)" --input
```

### Extracting selectors from bytecode

```python
#!/usr/bin/env python3
"""Pull 4-byte selectors and 32-byte constants out of EVM runtime bytecode.

Pure stdlib. Usage:
    python3 selectors.py 0x6080604052...
    cast code $TARGET --rpc-url $RPC | python3 selectors.py
"""
import sys

PUSH1 = 0x60
PUSH32 = 0x7F
EQ = 0x14
STOP_AT = {0x00}  # not used for control flow here, kept for clarity


def parse_pushes(code: bytes):
    """Yield (pc, push_size, value_bytes, next_opcode) walking the code linearly."""
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]
        if PUSH1 <= op <= PUSH32:
            size = op - PUSH1 + 1
            value = code[pc + 1 : pc + 1 + size]
            nxt = code[pc + 1 + size] if pc + 1 + size < n else None
            yield pc, size, value, nxt
            pc += 1 + size
        else:
            pc += 1


def selectors(code: bytes):
    """PUSH4 values that are compared with EQ are almost always function selectors."""
    out = []
    pushes = list(parse_pushes(code))
    for i, (pc, size, value, nxt) in enumerate(pushes):
        if size != 4:
            continue
        # direct `PUSH4 x EQ`, or `PUSH4 x DUPn EQ` / `PUSH4 x GT|LT` in a binary-search dispatcher
        window = code[pc + 5 : pc + 9]
        if nxt == EQ or EQ in window or (nxt is not None and nxt in (0x10, 0x11, 0x80, 0x81)):
            out.append((pc, "0x" + value.hex()))
    # dedupe, keep order
    seen, uniq = set(), []
    for pc, sel in out:
        if sel not in seen:
            seen.add(sel)
            uniq.append((pc, sel))
    return uniq


def big_constants(code: bytes):
    """PUSH32 values: event topics, keccak'd secrets, typehashes, magic numbers."""
    return [(pc, "0x" + v.hex()) for pc, size, v, _ in parse_pushes(code) if size == 32]


def read_code(argv) -> bytes:
    raw = argv[1] if len(argv) > 1 else sys.stdin.read()
    raw = raw.strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    return bytes.fromhex(raw)


if __name__ == "__main__":
    if len(sys.argv) == 1 and sys.stdin.isatty():
        # self-test on a hand-built dispatcher: PUSH4 0x12345678 EQ PUSH2 0x0042 JUMPI
        demo = bytes.fromhex("6380604052") + bytes.fromhex("63") + bytes.fromhex("12345678") \
            + bytes([EQ]) + bytes.fromhex("610042") + bytes([0x57])
        sels = selectors(demo)
        assert ("0x12345678" in [s for _, s in sels]), sels
        print("[+] self-test ok:", sels)
        print("usage: python3 selectors.py <0x-bytecode>   (or pipe it on stdin)")
        raise SystemExit(0)

    code = read_code(sys.argv)
    print(f"# {len(code)} bytes of runtime code")
    print("## selectors")
    for pc, sel in selectors(code):
        print(f"  pc={pc:#06x}  {sel}      # cast 4byte {sel}")
    print("## PUSH32 constants")
    for pc, const in big_constants(code):
        print(f"  pc={pc:#06x}  {const}")
```

```bash
# resolve the selectors you found against the public 4byte database (needs network)
cast 4byte 0x12345678
# decode a full calldata blob
cast 4byte-decode 0xa9059cbb000000000000000000000000dead...
# decompile properly
heimdall decompile "$TARGET" --rpc-url "$RPC_URL" --include-solidity
```

### CREATE / CREATE2 address prediction

```bash
# CREATE: deployer + nonce
cast compute-address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --nonce 0

# CREATE2: factory + salt + init code hash
INIT_CODE=$(forge inspect src/Attacker.sol:Attacker bytecode)
INIT_HASH=$(cast keccak "$INIT_CODE")
cast create2 --deployer "$FACTORY" --salt 0x0000000000000000000000000000000000000000000000000000000000000001 \
  --init-code-hash "$INIT_HASH"

# mine a salt for a vanity prefix (foundry does the grinding)
cast create2 --starts-with 000000 --deployer "$FACTORY" --init-code-hash "$INIT_HASH"
```

Python version (no foundry needed):

```python
#!/usr/bin/env python3
"""CREATE and CREATE2 address derivation, plus a salt miner. pip install eth-utils rlp"""
import rlp
from eth_utils import keccak, to_checksum_address


def create_address(sender: str, nonce: int) -> str:
    sender_bytes = bytes.fromhex(sender[2:] if sender.startswith("0x") else sender)
    return to_checksum_address(keccak(rlp.encode([sender_bytes, nonce]))[12:])


def create2_address(deployer: str, salt: bytes, init_code_hash: bytes) -> str:
    deployer_bytes = bytes.fromhex(deployer[2:] if deployer.startswith("0x") else deployer)
    assert len(deployer_bytes) == 20 and len(salt) == 32 and len(init_code_hash) == 32
    pre = b"\xff" + deployer_bytes + salt + init_code_hash
    assert len(pre) == 85
    return to_checksum_address(keccak(pre)[12:])


def mine_salt(deployer: str, init_code_hash: bytes, prefix: str, max_tries: int = 5_000_000):
    """Find a salt whose CREATE2 address starts with `prefix` (hex, no 0x)."""
    prefix = prefix.lower()
    for i in range(max_tries):
        salt = i.to_bytes(32, "big")
        addr = create2_address(deployer, salt, init_code_hash)
        if addr[2:].lower().startswith(prefix):
            return salt, addr
    raise RuntimeError("no salt found")


if __name__ == "__main__":
    # Known-good vector: the canonical deterministic-deployment proxy is deployed by
    # a CREATE from a presigned transaction; here we just self-check determinism.
    d = "0x4e59b44847b379578588920cA78FbF26c0B4956C"
    h = keccak(b"\x60\x80\x60\x40\x52")
    a1 = create2_address(d, b"\x00" * 32, h)
    a2 = create2_address(d, b"\x00" * 32, h)
    assert a1 == a2 and a1.startswith("0x") and len(a1) == 42
    assert create2_address(d, b"\x00" * 31 + b"\x01", h) != a1
    assert create_address("0x0000000000000000000000000000000000000000", 0) != a1
    salt, addr = mine_salt(d, h, "0", max_tries=100000)
    assert addr[2:].lower().startswith("0")
    print(f"[+] self-test ok")
    print(f"    create2(salt=0)  = {a1}")
    print(f"    mined salt {salt.hex()} -> {addr}")
```

### Deploying raw bytecode

```bash
# deploy a hand-written runtime blob: wrap it in minimal init code that RETURNs it.
# init code for an N-byte runtime R:
#   PUSH1 N PUSH1 0x0c PUSH1 0x00 CODECOPY PUSH1 N PUSH1 0x00 RETURN <R>
#   = 60 N 60 0c 60 00 39 60 N 60 00 f3 || R
RUNTIME=600160005260206000f3            # example: return 1
LEN=$(printf '%02x' $(( ${#RUNTIME} / 2 )))
INIT="60${LEN}600c60003960${LEN}6000f3${RUNTIME}"
cast send --create "0x$INIT" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

### Metamorphic factory (pre-Cancun EVM)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// The init code is CONSTANT (it just asks the factory what to deploy), so the
/// CREATE2 address is stable while the resulting runtime code can change.
contract MetamorphicFactory {
    bytes public nextRuntime;

    /// 0x5860208158601c335a63aaf10f428752fa158151803b80938091923cf3
    /// is the well-known 28-byte metamorphic init code: it STATICCALLs back into
    /// its creator, gets an implementation address, EXTCODECOPYs it and returns it.
    bytes private constant METAMORPHIC_INIT =
        hex"5860208158601c335a63aaf10f428752fa158151803b80938091923cf3";

    address public implementation;

    /// selector 0xaaf10f42 == "getImplementation()"
    function getImplementation() external view returns (address) {
        return implementation;
    }

    function deploy(bytes32 salt, address impl) external returns (address addr) {
        implementation = impl;
        bytes memory init = METAMORPHIC_INIT;
        assembly {
            addr := create2(0, add(init, 0x20), mload(init), salt)
        }
        require(addr != address(0), "create2 failed");
    }

    function predict(bytes32 salt) external view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, keccak256(METAMORPHIC_INIT)
        )))));
    }
}
```

## Variants & pitfalls

- **Vyper / Huff / raw-assembly contracts** have no Solidity dispatcher preamble. Vyper uses a
  different but still `PUSH4`-based dispatch; Huff can be anything.
- **Metadata hash**: Solidity appends a CBOR-encoded IPFS/bzzr hash at the end of the runtime code.
  It is not executable - ignore the last ~50 bytes when disassembling. It also means two builds
  with identical logic have different code hashes.
- **Immutables** appear in the runtime code as literal `PUSH32`/`PUSH20` values patched at deploy
  time. This is how you read an "unreadable" immutable secret.
- **`extcodesize(addr) == 0` guards** are bypassed from a constructor (code size is 0 while the
  constructor runs) - see `attacker-contract-patterns`.
- **`CREATE2` collision with an existing contract reverts**; if there is only a *balance* at the
  address (no code, nonce 0), deployment still succeeds and you inherit the balance.
- **Nonce accounting for `CREATE`**: a contract's nonce starts at 1 (EIP-161), an EOA's at 0.
- **Salt is 32 bytes** and is *not* hashed with the sender in `CREATE2` - if the factory uses
  `keccak256(abi.encodePacked(msg.sender, userSalt))` you cannot front-run someone's address;
  if it uses the raw user salt, you can.
- **`cast run --debug`** gives you an interactive stepper on any historical transaction; it is far
  faster than reading disassembly for control-flow questions.

## Tools

- `cast disassemble`, `cast run --trace --debug`, `cast 4byte`, `cast create2`, `cast compute-address`
- `heimdall-rs` (`heimdall decompile`, `heimdall disassemble`, `heimdall cfg`)
- `panoramix` (the decompiler behind several web UIs)
- `pyevmasm` (`evmasm -d`), `evm disasm` from go-ethereum
- `ethersplay` / `Ghidra EVM plugin` for graph views

## References

- Ethereum Yellow Paper, appendix H (opcode list) and section on contract creation.
- EIP-1014 (`CREATE2`), EIP-1052 (`EXTCODEHASH`), EIP-6780 (`SELFDESTRUCT` semantics).
