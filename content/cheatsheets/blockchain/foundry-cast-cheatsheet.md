---
title: "Foundry - cast / forge / anvil Cheatsheet"
category: blockchain
subcategory: foundry
type: cheatsheet
tags: [blockchain, foundry, cast, forge, anvil, chisel, evm, solidity, rpc, abi, calldata, storage, create2, keccak, impersonation, fork, cheatcodes, web3, ethereum, selector, 4byte]
summary: "Dense reference of cast/forge/anvil invocations for EVM CTFs: calls, sends, storage, code, ABI, create2, forking, impersonation."
tools: [foundry, cast, forge, anvil, chisel]
related: [setup-and-workflow, storage-slot-reading, evm-bytecode-and-create2, web3py-cheatsheet]
---

## Install / update

```bash
# install the foundry toolchain installer
curl -L https://foundry.paradigm.xyz | bash
# install / update the binaries (forge, cast, anvil, chisel)
foundryup
# pin a specific nightly if a challenge needs older behaviour
foundryup --version nightly-de33b6af53005037b463318d2628b5cfcaf39916
# versions of everything
forge --version; cast --version; anvil --version
```

## Environment

```bash
# the three things every challenge gives you
export RPC_URL="http://chal.example:8545/uuid"
export PRIVATE_KEY="0xac09...ff80"
export SETUP="0x5FbD...0aa3"
# derive your address from the key
export ME=$(cast wallet address --private-key "$PRIVATE_KEY")
# foundry reads ETH_RPC_URL automatically, so you can drop --rpc-url
export ETH_RPC_URL="$RPC_URL"
```

## Wallets and keys

```bash
# address from a private key
cast wallet address --private-key "$PRIVATE_KEY"
# generate a fresh keypair
cast wallet new
# generate a vanity address with a given prefix
cast wallet vanity --starts-with dead
# derive from a mnemonic at a specific index
cast wallet address --mnemonic "test test test test test test test test test test test junk" --mnemonic-index 3
# private key from a mnemonic
cast wallet private-key --mnemonic "test test ... junk" --mnemonic-index 0
# sign an EIP-191 personal message
cast wallet sign --private-key "$PRIVATE_KEY" "hello"
# sign a raw 32-byte digest with NO prefix (what ecrecover expects)
cast wallet sign --private-key "$PRIVATE_KEY" --no-hash 0x1234...32bytes
# recover the signer of a message
cast wallet verify --address "$ME" "hello" 0xsignature
# import a key into the encrypted keystore, then use --account
cast wallet import ctf --interactive
cast send --account ctf --password-file /dev/null "$TARGET" "f()"
```

## Chain / node queries

```bash
# chain id
cast chain-id
# human name of the chain
cast chain
# current block number
cast block-number
# full latest block
cast block latest
# one field of a block
cast block latest --field timestamp
cast block latest --field gasLimit
cast block latest --field baseFeePerGas
# gas price and base fee
cast gas-price
cast base-fee
# your balance (wei, then ether)
cast balance "$ME"
cast balance "$ME" --ether
# nonce of an account
cast nonce "$ME"
# arbitrary JSON-RPC
cast rpc eth_chainId
cast rpc eth_accounts
cast rpc eth_getStorageAt "$TARGET" 0x0 latest
cast rpc eth_getLogs '{"fromBlock":"0x0","address":"'$TARGET'"}'
cast rpc web3_clientVersion
cast rpc txpool_content
```

## Reading contracts

```bash
# call a view function, typed return
cast call "$TARGET" "owner()(address)"
cast call "$TARGET" "balanceOf(address)(uint256)" "$ME"
cast call "$TARGET" "isSolved()(bool)"
cast call "$TARGET" "name()(string)"
cast call "$TARGET" "getReserves()(uint112,uint112,uint32)"
# call at a historical block
cast call "$TARGET" "owner()(address)" --block 1000
# call AS someone else (no signature needed, it is a simulation)
cast call "$TARGET" "adminOnly()" --from "$VICTIM"
# call with value attached (simulation)
cast call "$TARGET" "deposit()" --value 1ether
# raw call with hand-built calldata
cast call "$TARGET" 0xa9059cbb000000000000000000000000dead...
# runtime bytecode
cast code "$TARGET"
# size of the runtime bytecode (0 => EOA or destroyed)
cast codesize "$TARGET"
# keccak of the code (EXTCODEHASH)
cast keccak "$(cast code "$TARGET")"
```

## Storage

```bash
# read slot 0
cast storage "$TARGET" 0
# read slot 0 at an old block (recover an overwritten secret)
cast storage "$TARGET" 0 --block 500
# EIP-1967 implementation slot
cast storage "$TARGET" 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
# EIP-1967 admin slot
cast storage "$TARGET" 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
# EIP-1967 beacon slot
cast storage "$TARGET" 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
# mapping m[key] where m is declared at slot 2
cast storage "$TARGET" "$(cast keccak "$(cast abi-encode 'f(address,uint256)' "$ME" 2)")"
# dynamic array base slot for an array declared at slot 5
cast keccak "$(cast abi-encode 'f(uint256)' 5)"
# storage layout of a locally compiled contract
forge inspect src/Vault.sol:Vault storageLayout --pretty
```

## Sending transactions

```bash
# plain transfer
cast send "$TO" --value 1ether --private-key "$PRIVATE_KEY"
# call a function
cast send "$TARGET" "deposit()" --value 1ether --private-key "$PRIVATE_KEY"
cast send "$TARGET" "transfer(address,uint256)" "$TO" 1000000000000000000 --private-key "$PRIVATE_KEY"
# arrays and tuples as arguments
cast send "$TARGET" "batch(address[],uint256[])" "[$A,$B]" "[1,2]" --private-key "$PRIVATE_KEY"
cast send "$TARGET" "run((address,uint256,bytes)[])" "[($A,0,0x1234)]" --private-key "$PRIVATE_KEY"
# bytes / bytes32 arguments
cast send "$TARGET" "unlock(bytes32)" 0x0000...0001 --private-key "$PRIVATE_KEY"
# raw calldata, no signature parsing
cast send "$TARGET" 0xdeadbeef --private-key "$PRIVATE_KEY"
# legacy (type 0) transaction -- needed on many private CTF chains
cast send "$TARGET" "f()" --legacy --private-key "$PRIVATE_KEY"
# fix gas manually when estimation reverts
cast send "$TARGET" "f()" --gas-limit 3000000 --gas-price 1gwei --private-key "$PRIVATE_KEY"
# explicit nonce (to replace a stuck tx)
cast send "$TARGET" "f()" --nonce 7 --private-key "$PRIVATE_KEY"
# deploy raw init code
cast send --create 0x6080604052... --private-key "$PRIVATE_KEY"
# deploy raw init code with value
cast send --create 0x6080... --value 1ether --private-key "$PRIVATE_KEY"
# do not wait for the receipt
cast send "$TARGET" "f()" --async --private-key "$PRIVATE_KEY"
# unlocked account on a dev node (no key needed)
cast send "$TARGET" "f()" --from "$VICTIM" --unlocked
```

## Transactions, receipts, traces

```bash
# full transaction
cast tx "$TXHASH"
# just the calldata
cast tx "$TXHASH" input
# receipt (status, gasUsed, logs)
cast receipt "$TXHASH"
# one field of the receipt
cast receipt "$TXHASH" status
# decode and pretty-print the execution trace
cast run "$TXHASH"
cast run "$TXHASH" --trace-printer
# step through in the debugger
cast run "$TXHASH" --debug
# estimate gas for a call
cast estimate "$TARGET" "distribute()"
cast estimate "$TARGET" "deposit()" --value 1ether
# simulate a call and see the revert reason
cast call "$TARGET" "willRevert()" --trace
```

## ABI, selectors, encoding

```bash
# 4-byte selector of a signature
cast sig "transfer(address,uint256)"
# event topic0
cast sig-event "Transfer(address,address,uint256)"
# lookup a selector in the public 4byte database
cast 4byte 0xa9059cbb
# decode full calldata via the 4byte database
cast 4byte-decode 0xa9059cbb000000000000000000000000dead...
# decode an event by its topics+data
cast 4byte-event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
# build calldata
cast calldata "transfer(address,uint256)" "$TO" 1000000000000000000
# decode calldata given the signature
cast calldata-decode "transfer(address,uint256)" 0xa9059cbb0000...
# decode a return value given the output types
cast abi-decode "balanceOf(address)(uint256)" 0x0000...0de0b6b3a7640000
# decode raw abi-encoded data (no function wrapper)
cast abi-decode "f()(address,uint256)" 0x... --input
# abi-encode arguments (no selector)
cast abi-encode "f(address,uint256)" "$ME" 42
# abi-encode packed (like abi.encodePacked)
cast abi-encode --packed "f(address,uint256)" "$ME" 42
# generate a solidity interface from a verified contract
cast interface 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
cast interface ./abi.json --name IVault
# pretty-print an ABI from an artifact
forge inspect src/Vault.sol:Vault abi
# list every method + selector
forge inspect src/Vault.sol:Vault methods
```

## Hashing, math, conversion

```bash
# keccak256 of a string
cast keccak "Transfer(address,address,uint256)"
# keccak256 of hex bytes
cast keccak 0xdeadbeef
# namehash (ENS)
cast namehash vitalik.eth
# to/from hex
cast --to-hex 255
cast --to-dec 0xff
# 32-byte left-padded hex
cast --to-uint256 42
cast --to-int256 -1
cast --to-bytes32 0x1234
# ascii <-> hex
cast --from-utf8 "hello"
cast --to-ascii 0x68656c6c6f
# units
cast --to-wei 1.5 ether
cast --from-wei 1500000000000000000
cast --to-unit 1000000000 gwei
# max uint256
cast --max-uint
cast --max-int
cast --min-int
# two's complement / bit ops
cast --to-int256 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
# checksum an address
cast to-check-sum-address 0xd8da6bf26964af9d7eed9e03e53415d37aa96045
# address from a public key
cast wallet address --private-key "$PRIVATE_KEY"
# concatenate hex
cast concat-hex 0x1234 0x5678
```

## CREATE / CREATE2

```bash
# CREATE address from deployer + nonce
cast compute-address "$DEPLOYER" --nonce 0
# CREATE address for the deployer's NEXT deployment (reads the live nonce)
cast compute-address "$DEPLOYER"
# init code of a local contract
forge inspect src/Attacker.sol:Attacker bytecode
# init code hash
cast keccak "$(forge inspect src/Attacker.sol:Attacker bytecode)"
# CREATE2 address
cast create2 --deployer "$FACTORY" --salt 0x00..01 --init-code-hash "$INIT_HASH"
# mine a salt for a vanity prefix
cast create2 --starts-with dead --deployer "$FACTORY" --init-code-hash "$INIT_HASH"
# mine for a suffix
cast create2 --ends-with 0000 --deployer "$FACTORY" --init-code-hash "$INIT_HASH"
# mine with a case-sensitive match
cast create2 --starts-with dEaD --case-sensitive --deployer "$FACTORY" --init-code-hash "$INIT_HASH"
```

## Bytecode

```bash
# disassemble hex bytecode
cast disassemble "$(cast code "$TARGET")"
# disassemble and grep the selectors
cast disassemble "$(cast code "$TARGET")" | grep -B1 "EQ" | grep PUSH4
# find PUSH32 constants (hashes, typehashes, event topics)
cast disassemble "$(cast code "$TARGET")" | grep PUSH32
# the deployment transaction's init code
cast tx "$CREATION_TX" input
```

## Logs and events

```bash
# all logs from a contract
cast logs --address "$TARGET" --from-block 0
# filter by event signature
cast logs "Transfer(address indexed,address indexed,uint256)" --address "$TARGET" --from-block 0
# filter by an indexed argument
cast logs "Transfer(address indexed,address indexed,uint256)" --address "$TARGET" \
  --from-block 0 "$ME"
# raw eth_getLogs
cast rpc eth_getLogs '{"address":"'"$TARGET"'","fromBlock":"0x0","toBlock":"latest"}'
```

## forge - build and test

```bash
# new project
forge init myproj --no-git
# build
forge build
# build with a specific solc
forge build --use 0.7.6
# build sizes (EIP-170 limit is 24576 bytes)
forge build --sizes
# run all tests, max verbosity (shows the full call trace)
forge test -vvvv
# one test
forge test --match-test test_drain -vvvv
# one contract
forge test --match-contract ReentrancyTest -vvv
# gas report
forge test --gas-report
# fuzz harder
forge test --fuzz-runs 100000
# coverage
forge coverage
# run tests against a fork
forge test --fork-url "$RPC_URL" -vvvv
forge test --fork-url "$MAINNET_RPC" --fork-block-number 19000000
# install a dependency
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install transmissions11/solmate --no-commit
# remappings
forge remappings > remappings.txt
# flatten (useful for pasting into a decompiler or verifier)
forge flatten src/Vault.sol
# format
forge fmt
```

## forge - deploy and script

```bash
# deploy a contract
forge create src/Attacker.sol:Attacker --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# with constructor args
forge create src/Attacker.sol:Attacker --constructor-args "$TARGET" 42 \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# funded at deployment (constructor-only attacks)
forge create src/Attacker.sol:Attacker --value 1ether \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# machine-readable output (grab deployedTo with jq)
forge create src/A.sol:A --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json | jq -r .deployedTo
# legacy tx type
forge create src/A.sol:A --legacy --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
# run a script (simulation only)
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" -vvvv
# actually broadcast
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast -vvvv
# one tx per block (needed for per-block-limited challenges)
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast --slow
# legacy + broadcast
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast --legacy
# pass the key via a keystore account instead of an env var
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --broadcast --account ctf
# resume a partially-broadcast script
forge script script/Solve.s.sol:Solve --rpc-url "$RPC_URL" --resume
```

## anvil - local chain and forking

```bash
# plain local chain, 10 funded accounts, deterministic keys
anvil
# fork the challenge chain
anvil --fork-url "$RPC_URL"
# fork at a specific block
anvil --fork-url "$MAINNET_RPC" --fork-block-number 19000000
# match a specific chain id
anvil --chain-id 31337
# huge block gas limit (or a small one to reproduce a DoS)
anvil --gas-limit 300000000
anvil --gas-limit 8000000
# zero base fee, so gas is free while you iterate
anvil --base-fee 0 --gas-price 0
# mine only when a transaction arrives (default) vs on an interval
anvil --block-time 1
# do not auto-mine; you control blocks
anvil --no-mining
# custom mnemonic / number of accounts / balance
anvil -m "test test test test test test test test test test test junk" -a 20 --balance 10000
# persist and reload state
anvil --dump-state state.json
anvil --load-state state.json
```

## anvil / hardhat cheat RPCs

```bash
# mine one block
cast rpc anvil_mine
# mine N blocks
cast rpc anvil_mine 0x64
# jump forward in time (seconds), then mine
cast rpc evm_increaseTime 86400 && cast rpc anvil_mine
# set the next block's timestamp exactly
cast rpc evm_setNextBlockTimestamp 1800000000
# set an account's balance
cast rpc anvil_setBalance "$ME" 0x21e19e0c9bab2400000
# set an account's nonce
cast rpc anvil_setNonce "$ME" 0x0
# overwrite a storage slot directly
cast rpc anvil_setStorageAt "$TARGET" 0x0 0x000000000000000000000000dead...
# replace a contract's code
cast rpc anvil_setCode "$TARGET" 0x6080604052...
# impersonate any account, then send as them
cast rpc anvil_impersonateAccount "$VICTIM"
cast send "$TARGET" "adminOnly()" --from "$VICTIM" --unlocked
cast rpc anvil_stopImpersonatingAccount "$VICTIM"
# impersonate everything at once
cast rpc anvil_autoImpersonateAccount true
# snapshot / revert the whole chain state
SNAP=$(cast rpc evm_snapshot)
cast rpc evm_revert "$SNAP"
# disable/enable auto-mining
cast rpc evm_setAutomine false
cast rpc evm_setIntervalMining 5
```

## chisel (Solidity REPL)

```bash
# start the REPL
chisel
# inside chisel:
#   uint256 a = 2**255;
#   a * 2                                  // check the wrap
#   keccak256(abi.encode(address(1), uint256(2)))
#   !source                                // show the session source
#   !clear                                 // reset
#   !fork $RPC_URL                         // attach to a chain, then call live contracts
#   !exec cast balance $ME
```

## Useful one-liners

```bash
# is the challenge solved yet?
cast call "$SETUP" "isSolved()(bool)"
# find the target the setup deployed (try the usual getter names)
for f in TARGET target challenge instance CHALLENGE; do
  cast call "$SETUP" "$f()(address)" 2>/dev/null && echo "  <- $f" ; done
# dump the first 32 storage slots
for i in $(seq 0 31); do printf "%2d: " "$i"; cast storage "$TARGET" "$i"; done
# every selector present in a deployed contract
cast disassemble "$(cast code "$TARGET")" | awk '/PUSH4/ {print $NF}' | sort -u
# balance of everything interesting
for a in "$ME" "$SETUP" "$TARGET"; do echo -n "$a "; cast balance "$a" --ether; done
# watch a contract's balance change
watch -n2 "cast balance $TARGET --ether --rpc-url $RPC_URL"
# who deployed this contract? (needs an explorer-backed node or a full archive scan)
cast rpc eth_getTransactionCount "$TARGET" latest
# ERC20 quick look
cast call "$TOKEN" "name()(string)"; cast call "$TOKEN" "symbol()(string)"; \
  cast call "$TOKEN" "decimals()(uint8)"; cast call "$TOKEN" "totalSupply()(uint256)"
# approve max
cast send "$TOKEN" "approve(address,uint256)" "$SPENDER" "$(cast --max-uint)" \
  --private-key "$PRIVATE_KEY"
```

## foundry.toml knobs that matter in CTFs

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"      # match the challenge, or bytecode/behaviour differs
evm_version = "cancun"       # "shanghai"/"paris"/"london" change selfdestruct & PUSH0
optimizer = true
optimizer_runs = 200
via_ir = false
fuzz = { runs = 10000 }
ffi = true                   # allows vm.ffi() to shell out from a test/script
gas_limit = "18446744073709551615"

[rpc_endpoints]
chal = "${RPC_URL}"
```
