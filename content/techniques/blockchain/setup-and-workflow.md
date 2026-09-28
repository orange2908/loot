---
title: "Blockchain CTF - Setup, RPC Connection and Solve Workflow"
category: blockchain
subcategory: workflow
type: technique
tags: [blockchain, ethereum, evm, solidity, foundry, cast, forge, anvil, web3py, rpc, setup, issolved, private-key, ctf-infra, paradigm-ctf, ethernaut, damn-vulnerable-defi, anvil-fork]
difficulty: easy
summary: "How EVM CTF infra works: get RPC + key + setup contract, read the source, attack from a script, then prove isSolved() == true."
when_to_use:
  - "A challenge hands you an RPC URL, a private key and a 'Setup' contract address"
  - "You have Solidity source and need a repeatable attack loop"
  - "You need to fork mainnet locally to test an exploit before firing it"
  - "You are told 'make isSolved() return true'"
tools: [foundry, cast, forge, anvil, web3py, solc]
related: [attacker-contract-patterns, storage-slot-reading, solve-template]
---

## TL;DR

Almost every EVM CTF uses the same shape: a TCP/HTTP launcher gives you `(rpc_url, private_key,
setup_contract)`. The `Setup` contract deployed the real challenge in its constructor and exposes
`isSolved()`. You win by making `isSolved()` return `true` from an EOA or attacker contract you
control. Everything else is Solidity bug-hunting.

## Recognise it

- A `nc host port` launcher menu: `1 - launch new instance`, `2 - kill instance`, `3 - flag`.
- Output containing `uuid`, `rpc endpoint`, `private key`, `setup contract`.
- A `Setup.sol` with `constructor() payable`, a public immutable target, and `isSolved()`.
- `public` challenge source in `src/` or `contracts/`, and a `foundry.toml` / `hardhat.config.js`.
- The challenge chain is a private anvil/geth dev chain: chain id is often `31337`, `1337` or random.

## Theory

The `Setup` pattern (popularised by Paradigm CTF and copied everywhere):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Vault} from "./Vault.sol";

contract Setup {
    Vault public immutable TARGET;

    constructor() payable {
        require(msg.value == 50 ether, "need seed funding");
        TARGET = new Vault{value: 50 ether}();
    }

    function isSolved() public view returns (bool) {
        return address(TARGET).balance == 0;
    }
}
```

Key consequences:

1. **The setup contract holds no privilege you need** - it is just a deployer and a scoreboard.
2. **`TARGET` is discoverable on-chain** even without source: `cast call $SETUP "TARGET()(address)"`,
   or read storage slot 0 if the getter name is unknown (immutables live in code, not storage -
   see `storage-slot-reading`).
3. **Your key is pre-funded**, usually with ~10-100 ETH. Check before assuming.
4. **Nothing is secret.** `private` variables, internal functions and "hidden" contracts are all
   readable; the chain is public to you.

## Attack

**Step 0 - capture the environment.** Put it in a `.env` so every tool reads the same thing.

```bash
# .env for the challenge instance
export RPC_URL="http://chal.example.ctf:8545/abcdef-uuid"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export SETUP="0x5FbDB2315678afecb367f032d93F642f64180aa3"
```

**Step 1 - sanity check the chain.**

```bash
# chain id, block number, and your address + balance in one pass
cast chain-id  --rpc-url "$RPC_URL"
cast block-number --rpc-url "$RPC_URL"
export ME=$(cast wallet address --private-key "$PRIVATE_KEY")
cast balance "$ME" --rpc-url "$RPC_URL" --ether
```

**Step 2 - locate the target and confirm you are not already solved.**

```bash
# the immutable getter Setup exposes; name varies: TARGET(), challenge(), instance()
export TARGET=$(cast call "$SETUP" "TARGET()(address)" --rpc-url "$RPC_URL")
cast call "$SETUP" "isSolved()(bool)" --rpc-url "$RPC_URL"
```

If you do not know the getter name, brute the 4-byte selectors you expect, or disassemble:

```bash
# dump runtime bytecode and grep for PUSH4 selectors
cast code "$SETUP" --rpc-url "$RPC_URL" > setup.bin
# selectors of the usual suspects
cast sig "TARGET()"; cast sig "target()"; cast sig "challenge()"; cast sig "instance()"
```

**Step 3 - read the source.** If the source is given, read every line; CTF contracts are short and
the bug is deliberate. If not, see `evm-bytecode-and-create2`.

**Step 4 - reproduce locally on a fork.** Never debug on the remote instance; instances are rate
limited and some auto-expire.

```bash
# fork the live challenge chain locally on :8545 so you can spam transactions
anvil --fork-url "$RPC_URL" --fork-block-number latest
# in another shell, point everything at the fork
export RPC_URL=http://127.0.0.1:8545
```

**Step 5 - write the exploit as a `forge script`.** One file, idempotent, prints `isSolved()` at
the end. See `scripts/blockchain/solve-template`.

**Step 6 - fire at the real instance, then claim the flag** from the launcher menu.

## Code

A minimal but complete Foundry project layout for a challenge:

```bash
#!/usr/bin/env bash
# bootstrap a foundry workspace for an EVM CTF challenge
set -euo pipefail

forge init --no-git --no-commit solve && cd solve

# challenge sources go in src/ so you can import them by type in the script
mkdir -p src script
cp -r ../challenge/src/* src/ 2>/dev/null || true

# foundry.toml: match the challenge's compiler or you will get bytecode mismatches
cat > foundry.toml <<'EOF'
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200
evm_version = "cancun"
via_ir = false

[rpc_endpoints]
chal = "${RPC_URL}"
EOF

forge build
```

The canonical script skeleton:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

interface ISetup {
    function TARGET() external view returns (address);
    function isSolved() external view returns (bool);
}

contract Solve is Script {
    function run() external {
        address setup = vm.envAddress("SETUP");
        uint256 pk = vm.envUint("PRIVATE_KEY");
        ISetup s = ISetup(setup);
        address target = s.TARGET();

        console2.log("me     :", vm.addr(pk));
        console2.log("target :", target);
        console2.log("solved?:", s.isSolved());

        vm.startBroadcast(pk);
        // ---- exploit goes here ----
        // e.g. new Attacker{value: 1 ether}(target).pwn();
        vm.stopBroadcast();

        require(s.isSolved(), "not solved");
        console2.log("SOLVED");
    }
}
```

Run it:

```bash
# --broadcast actually sends; drop it for a dry run against current state
forge script script/Solve.s.sol:Solve \
  --rpc-url "$RPC_URL" \
  --broadcast \
  -vvvv \
  --legacy   # many CTF chains do not support EIP-1559; add if you get 'invalid tx type'
```

## Variants & pitfalls

- **`--legacy`**: private geth/anvil chains sometimes reject type-2 transactions. If `forge` errors
  with `EIP-1559 not activated` or the tx hangs, add `--legacy`.
- **Gas price 0**: some CTF chains need `--gas-price 0` or a fixed `--gas-limit` because
  estimation reverts on a contract that is *supposed* to revert mid-call.
- **`--slow`**: nonce races when broadcasting many txs. `--slow` sends one at a time and waits.
- **`vm.startBroadcast()` vs `new` in `run()`**: anything you `new` while broadcasting is really
  deployed. Anything before it is only simulated. Getting this wrong is the #1 "my exploit worked
  locally" bug.
- **`isSolved()` is `view`** - you cannot "solve" it by calling it. Look for what state it reads.
- **Block-boundary constraints**: `isSolved()` sometimes requires something to be true *in the same
  block* as an action. Then you must do everything from a single contract call, not a script with
  multiple txs.
- **Instance timeouts**: many launchers kill the instance after 10-30 minutes. Develop on a fork,
  then launch a fresh instance and fire the finished script.
- **The flag is not on-chain.** You get it from the launcher after it verifies `isSolved()`.
- **Multiple accounts**: some challenges pre-fund a second key or deploy `Setup` from a different
  EOA. `cast rpc eth_accounts` on a dev chain lists unlocked accounts.

## Tools

- `foundry` (`forge`, `cast`, `anvil`, `chisel`) - install via `foundryup`.
- `web3.py` - when you need loops, string munging or raw RLP that Solidity makes awkward.
- `chisel` - a Solidity REPL; great for checking `keccak256(abi.encode(...))` slot math.
- `cast interface <addr>` / `cast etherscan-source` - only useful on public chains.

## References

- Foundry Book: `forge script`, `cast`, `anvil` (book.getfoundry.sh)
- The `Setup`/`isSolved` convention originates in Paradigm CTF's challenge harness.
