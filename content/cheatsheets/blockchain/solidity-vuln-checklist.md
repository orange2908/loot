---
title: "Solidity Vulnerability Checklist - Ordered by CTF Win Rate"
category: blockchain
subcategory: audit
type: cheatsheet
tags: [blockchain, solidity, checklist, audit, reentrancy, delegatecall, access-control, tx-origin, integer-overflow, unchecked, randomness, oracle, signature, ecrecover, erc20, erc721, proxy, slither, code-smell, evm]
summary: "Review order for an EVM CTF contract: the exact grep and the exact code smell for each bug class, most-likely first."
tools: [slither, foundry, cast, grep]
related: [reentrancy, access-control, delegatecall-storage-collision, integer-overflow, bad-randomness, signature-replay-malleability, gas-and-dos]
---

## 0. Read this first

```bash
# the 60-second pass on any challenge source
grep -rn "pragma solidity" .                          # version -> which bug classes apply
grep -rn "delegatecall\|selfdestruct\|assembly" .     # instant-win primitives
grep -rn "tx.origin" .
grep -rn "unchecked" .
grep -rn "block.timestamp\|blockhash\|prevrandao\|block.difficulty" .
grep -rn "ecrecover" .
grep -rn "\.call{value" .
grep -rn "public\|external" . | grep -v "view\|pure" | grep -v "only"   # unguarded mutators
slither . --exclude-informational
```

---

## 1. Missing access control  (highest hit rate)

**Smell**
```solidity
function setOwner(address o) public { owner = o; }          // no modifier
function mint(address to, uint a) external { _mint(to, a); } // no modifier
modifier onlyOwner() { emit Check(msg.sender); _; }          // modifier that never reverts
modifier onlyOwner() { require(msg.sender == owner); }       // missing `_;` -> body never runs
function _internalHelper(...) public { ... }                 // should have been internal
```
**Grep** `grep -nE "function .*(public|external)" -A2 | grep -v "only|require|view|pure"`
**Check** every state-mutating function has a guard, and the guard actually `require`s.
**See** `access-control`.

---

## 2. Reentrancy

**Smell**
```solidity
(bool ok,) = msg.sender.call{value: bal}("");
balances[msg.sender] = 0;                     // effect AFTER interaction
```
Also: `nonReentrant` on some functions but not their siblings; `safeTransferFrom`/`_safeMint`
(ERC721 hook); any ERC777 token; a `view` function used by another protocol as a price.
**Grep** `grep -n "call{value\|\.transfer(\|\.send(\|safeTransfer\|_safeMint\|safeMint"`
**Check** state writes before every external call; a *shared* mutex across all mutators.
**See** `reentrancy`.

---

## 3. delegatecall / storage collision / proxy

**Smell**
```solidity
target.delegatecall(data);                  // target from a parameter
fallback() external { impl.delegatecall(msg.data); }
address public implementation;              // slot 0 of the proxy vs slot 0 of the logic
function initialize(address o) public { owner = o; }   // no initializer guard
```
**Grep** `grep -n "delegatecall\|Proxy\|upgradeTo\|initialize\|Initializable\|_disableInitializers"`
**Check** `forge inspect Proxy storageLayout` vs `forge inspect Logic storageLayout`; EIP-1967
slots; whether `initialize()` is callable on the *implementation* as well as the proxy.
**See** `delegatecall-storage-collision`, `access-control`.

---

## 4. Bad randomness

**Smell**
```solidity
uint r = uint(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
uint r = uint(blockhash(block.number));       // ALWAYS 0
if (block.timestamp % 15 == 0) { ... }
```
**Grep** `grep -n "blockhash\|block.timestamp\|block.number\|block.prevrandao\|block.difficulty\|block.coinbase\|gasleft"`
**Check** can you compute the same value in the same block? Usually yes.
**See** `bad-randomness`.

---

## 5. tx.origin authentication

**Smell** `require(tx.origin == owner);` / `if (tx.origin != msg.sender) revert();`
**Grep** `grep -n "tx.origin"`
**Check** used for auth -> forward the call from a contract the owner touches.
Used as an EOA check -> bypass from a constructor, or it is there to *stop* you.
**See** `access-control`, `attacker-contract-patterns`.

---

## 6. Arithmetic: overflow, underflow, truncation

**Smell**
```solidity
pragma solidity ^0.7.6;                 // no built-in checks
unchecked { balance[msg.sender] -= amount; }
uint8 total = uint8(a + b);             // explicit cast NEVER checks, any version
require(balance - amount >= 0);         // always true for uint
uint total = n * value;                 // wraps to 0 with value = 2**255, n = 2
```
**Grep** `grep -nE "unchecked|uint(8|16|32|64|128)\(|int(8|16|32|64|128)\(|SafeMath"`
**Check** pragma version; every `unchecked` block; every explicit downcast on user input.
**See** `integer-overflow`.

---

## 7. Oracle / price manipulation

**Smell**
```solidity
(uint112 r0, uint112 r1,) = pair.getReserves(); price = r1 * 1e18 / r0;
uint price = token.balanceOf(address(pool)) * 1e18 / other.balanceOf(address(pool));
uint value = router.getAmountsOut(amount, path)[1];
uint share = totalAssets() / totalSupply();
```
**Grep** `grep -n "getReserves\|getAmountsOut\|balanceOf(address(\|totalAssets\|latestAnswer\|virtual_price"`
**Check** is the price read from a single pool in a single block? Is there a flash-loan source?
Can a plain `transfer` (donation) move `balanceOf`?
**See** `oracle-flashloan-manipulation`.

---

## 8. Signature bugs

**Smell**
```solidity
address signer = ecrecover(hash, v, r, s);
require(signer == owner);                  // no `signer != address(0)` check
// message with no nonce / no chainId / no address(this) / no deadline
mapping(bytes32 => bool) used;             // keyed on the SIGNATURE, not the digest
```
**Grep** `grep -n "ecrecover\|ECDSA.recover\|DOMAIN_SEPARATOR\|permit\|isValidSignature"`
**Check** zero-address guard, nonce, chainId, verifyingContract, deadline, high-`s` rejection.
**See** `signature-replay-malleability`.

---

## 9. Unchecked return values / low-level call

**Smell**
```solidity
token.transfer(to, amount);        // USDT-style tokens return nothing; OZ SafeERC20 exists for this
msg.sender.send(amount);           // returns bool, silently fails
target.call(data);                 // return value ignored
(bool ok,) = target.call(data); // `ok` never checked
```
**Grep** `grep -n "\.call(\|\.send(\|\.transfer(" | grep -v "require\|bool ok"`
**Check** every `.call`/`.send`/ERC20 `transfer`/`approve` result is checked; `delegatecall` to an
address with no code returns `true`.

---

## 10. DoS: unbounded loops, push payments, exact balances

**Smell**
```solidity
for (uint i = 0; i < users.length; i++) { payable(users[i]).transfer(share); }
require(address(this).balance == 7 ether);
```
**Grep** `grep -n "for (\|while (\|address(this).balance"`
**Check** can the array be grown by anyone? can a recipient revert? can ether be force-fed?
**See** `gas-and-dos`.

---

## 11. Uninitialized / default values

**Smell**
```solidity
address public owner;                  // never set -> address(0); ecrecover(0) matches
mapping(address => bool) public isAdmin;  // default false, but `!isBlocked[x]` defaults to allowed
uint256 public price;                  // 0 means free
Struct storage s;                      // uninitialized storage pointer (pre-0.5) -> writes slot 0
```
**Check** every state variable has a setter or a constructor assignment; `address(0)` comparisons.

---

## 12. Visibility and shadowing

**Smell**
```solidity
uint256 private secret;                // "private" is not secret; read it from storage
function f() { }                       // pre-0.5 default visibility is public
address owner;                         // shadowed by a local `address owner` in a function
```
**Grep** `grep -n "private\|internal"` then read the slot anyway (`storage-slot-reading`).

---

## 13. ERC20 / ERC721 / ERC4626 specifics

```solidity
// ERC20
approve race: approve(spender, n) without zeroing first
fee-on-transfer: balanceAfter - balanceBefore != amount
rebasing: balanceOf changes without a transfer
transferFrom with infinite approval combined with a permit
decimals assumed to be 18
// ERC721
_mint vs _safeMint (the latter calls back)
ownerOf reverts for a burned token; balanceOf(0) reverts
approve/setApprovalForAll left dangling after a transfer
tokenURI reading attacker-controlled storage
// ERC4626
first-depositor inflation: shares = assets * supply / totalAssets rounds to 0
donation attack via a direct transfer to the vault
rounding direction: deposit should round DOWN shares, withdraw should round UP
```

---

## 14. Assembly

**Smell**
```solidity
assembly { sstore(slot, value) }            // slot from a parameter -> write anything
assembly { let x := mload(add(data, 0x20)) } // no length check
assembly { return(0, 0x20) }                 // bypasses solidity's return handling
assembly { calldatacopy(...) }               // custom ABI parsing, often mis-sized
```
**Grep** `grep -n "assembly"` and read every line of it.

---

## 15. Timing / front-running / ordering

```solidity
commit-reveal with the reveal in the same block
a deadline of type(uint256).max
an auction that reads block.timestamp with a 15-second window
`require(block.timestamp > start)` where start is settable
```
On a single-player CTF chain front-running rarely matters, but "same block" constraints do.

---

## 16. Compiler version quirks

| Version | Quirk |
|---|---|
| `<0.4.22` | constructors were functions named after the contract; a typo = a public function |
| `<0.5.0` | default function visibility is `public`; uninitialized storage pointers; `var` |
| `<0.6.0` | `array.length--` is writable -> underflow to `2**256-1` -> arbitrary storage write |
| `<0.8.0` | no overflow checks anywhere |
| `>=0.8.0` | `unchecked{}` blocks, explicit casts still truncate |
| `>=0.8.20` | `PUSH0` emitted; breaks on chains without Shanghai -> deploy fails |
| `>=0.8.24` | transient storage (`tstore`/`tload`), `MCOPY` |

---

## 17. Quick triage table

| If you see... | Try first |
|---|---|
| `delegatecall(userInput)` | write slot 0, take ownership |
| `initialize()` with no guard | call it |
| `private` secret | `cast storage` |
| `blockhash(block.number)` | it is 0; guess 0 |
| `unchecked { x -= y }` | underflow to max |
| `call{value:}` then a state write | reentrancy |
| `tx.origin ==` | forward the call |
| `getReserves()` pricing | flash loan |
| `ecrecover` with no zero check | `v=0,r=0,s=0` |
| loop over a public array | grow it / revert in the recipient |
| `address(this).balance ==` | force-feed via `selfdestruct` |
| `msg.sender.code.length == 0` | attack from a constructor |
| a `CREATE2` factory with a user salt | mine the address |
| `abi.encodePacked(a, b)` in a hash | collision with dynamic types |

---

## 18. Static analysis commands

```bash
# the whole slither suite, high/medium only
slither . --exclude-informational --exclude-low
# specific detectors
slither . --detect reentrancy-eth,reentrancy-no-eth,arbitrary-send-eth,suicidal,controlled-delegatecall
slither . --detect tx-origin,unprotected-upgrade,uninitialized-state,unchecked-transfer
slither . --detect divide-before-multiply,incorrect-equality,weak-prng,timestamp
# printers that are faster than reading
slither . --print human-summary
slither . --print function-summary
slither . --print inheritance-graph
slither . --print data-dependency
# storage layout
slither . --print variable-order
# mythril symbolic execution (slow, sometimes finds the path for you)
myth analyze src/Vault.sol --solv 0.8.20
# semgrep rules for solidity
semgrep --config p/smart-contracts .
# fuzz the invariant with foundry
forge test --match-test invariant --fuzz-runs 200000
```
